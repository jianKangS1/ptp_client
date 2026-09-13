"""PtpL2Master: state machine + TX/RX/RESP thread orchestration (design doc §5).

Covers the full E2E grandmaster: periodic Announce / Sync (+ Follow_Up) plus
Delay_Req reception → Delay_Resp answering (RX/RESP threads, slave session
table with ageing / rate limiting).
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Callable, Mapping, Optional

from ptp_client.ptp.constants import MessageType
from ptp_client.ptp.header import PTPHeader, PortIdentity
from ptp_client.ptp.timestamp import PTPTimestamp

from ptp_client.ptp.l2master import constants as l2
from ptp_client.ptp.l2master.clock import SystemClock
from ptp_client.ptp.l2master.config import MasterConfig
from ptp_client.ptp.l2master.messages import (
    AnnounceBody,
    ClockQuality,
    build_announce,
    build_delay_resp,
    build_follow_up,
    build_sync,
    parse_delay_req,
)
from ptp_client.ptp.l2master.scheduler import PeriodicScheduler
from ptp_client.ptp.l2master.session import SessionTable
from ptp_client.ptp.l2master.transport import (
    L2Transport,
    ReceivedFrame,
    build_ethernet_frame,
    open_transport,
)

log = logging.getLogger("ptp.l2master")

# Frame event callback: (direction "tx"/"rx", message_type, ptp_payload, extra info).
FrameCallback = Callable[[str, int, bytes, dict], None]

# Exponential backoff bounds for TX failures (design doc §5.2).
_FAULT_BACKOFF_MIN = 1.0
_FAULT_BACKOFF_MAX = 30.0

# Delay_Req → Delay_Resp context handed from the RX thread to the RESP thread.
_RespItem = tuple[PTPHeader, int, bytes]  # (header, receive_timestamp_ns, src_mac)

# Fields that cannot be changed while the master is running (they need the raw
# transport or the slave session table rebuilt) — see apply_runtime_update().
_IMMUTABLE_FIELDS = frozenset(
    {"interface", "profile", "offline", "max_slaves", "delay_resp_rate_limit", "announce_receipt_timeout"}
)


class MasterState(str, Enum):
    INIT = "INIT"
    LISTENING = "LISTENING"
    ACTIVE = "ACTIVE"
    FAULT = "FAULT"
    STOPPED = "STOPPED"


@dataclass
class MasterStats:
    state: MasterState = MasterState.INIT
    started_monotonic: float = 0.0
    announce_sent: int = 0
    sync_sent: int = 0
    follow_up_sent: int = 0
    delay_req_recv: int = 0
    delay_resp_sent: int = 0
    delay_resp_dropped: int = 0
    rx_bad_version: int = 0
    rx_other_domain: int = 0
    rx_other_type: int = 0
    rx_parse_errors: int = 0
    session_overflow: int = 0
    resp_queue_full: int = 0
    tx_errors: int = 0
    tx_skipped: int = 0

    @property
    def uptime_sec(self) -> float:
        if not self.started_monotonic:
            return 0.0
        return time.monotonic() - self.started_monotonic


def clock_identity_from_mac(mac: bytes) -> bytes:
    """IEEE EUI-64 style: OUI(3) + FF FE + NIC(3) → 8 octets."""
    if len(mac) != 6:
        raise ValueError("MAC must be 6 octets")
    return mac[:3] + b"\xff\xfe" + mac[3:]


class PtpL2Master:
    def __init__(
        self,
        cfg: MasterConfig,
        *,
        clock: Optional[SystemClock] = None,
        on_frame: Optional[FrameCallback] = None,
    ) -> None:
        cfg.validate()
        self.cfg = cfg
        self.clock = clock or SystemClock()
        self._on_frame = on_frame
        self.stats = MasterStats()
        self._stop_event = threading.Event()
        self._tx_thread: Optional[threading.Thread] = None
        self._rx_thread: Optional[threading.Thread] = None
        self._resp_thread: Optional[threading.Thread] = None
        self._resp_queue: "queue.Queue[_RespItem]" = queue.Queue(maxsize=1024)
        self._sessions = SessionTable(
            max_slaves=cfg.max_slaves,
            rate_limit_pps=cfg.delay_resp_rate_limit,
            session_timeout_sec=cfg.session_timeout_sec(),
        )
        self._transport: Optional[L2Transport] = None
        self._seq_announce = 0
        self._seq_sync = 0
        self._lock = threading.Lock()
        # Bumped whenever a log-interval may have changed → the TX loop rebuilds
        # its schedulers (see apply_runtime_update / _tx_loop).
        self._interval_gen = 0

        self.source_port: Optional[PortIdentity] = (
            PortIdentity(cfg.clock_identity, cfg.port_number) if cfg.clock_identity else None
        )

    # ---------------- lifecycle ----------------

    def start(self) -> None:
        """Open the L2 transport and start the RX/RESP/TX loops. Raises on failure."""
        self._transport = open_transport(self.cfg.interface, offline=self.cfg.offline)
        if self.cfg.clock_identity is None:
            self.source_port = PortIdentity(
                clock_identity_from_mac(self._transport.src_mac), self.cfg.port_number
            )
        else:
            self.source_port = PortIdentity(self.cfg.clock_identity, self.cfg.port_number)
        log.info(
            "master starting: iface=%s domain=%d profile=%s clockIdentity=%s src_mac=%s dst_mac=%s%s",
            self.cfg.interface,
            self.cfg.domain_number,
            self.cfg.profile,
            self.source_port.clock_identity.hex(),
            self._transport.src_mac.hex(":"),
            self.cfg.dst_mac.hex(":"),
            " OFFLINE(virtual wire, frames are not sent)" if self.cfg.offline else "",
        )
        self.stats.started_monotonic = time.monotonic()
        self._set_state(MasterState.LISTENING)
        self._stop_event.clear()
        # RX → RESP → TX (design doc §5.7: TX starts only when RX/RESP are ready).
        self._rx_thread = threading.Thread(target=self._rx_loop, name="ptp-l2-master-rx", daemon=True)
        self._rx_thread.start()
        self._resp_thread = threading.Thread(target=self._resp_loop, name="ptp-l2-master-resp", daemon=True)
        self._resp_thread.start()
        self._tx_thread = threading.Thread(target=self._tx_loop, name="ptp-l2-master-tx", daemon=True)
        self._tx_thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        # Drain pending Delay_Req contexts (bounded by drain_timeout) before exit.
        self._drain_resp_queue(timeout=0.1)
        for name in ("_tx_thread", "_rx_thread", "_resp_thread"):
            thread: Optional[threading.Thread] = getattr(self, name)
            if thread is not None:
                thread.join(timeout=2.0)
                setattr(self, name, None)
        transport = self._transport
        if transport is not None:
            transport.close()
            self._transport = None
        self._set_state(MasterState.STOPPED)
        log.info("master stopped: %s", self.get_stats())

    def wait(self) -> None:
        """Block until stop() is called or the TX loop dies permanently."""
        thread = self._tx_thread
        if thread is not None:
            thread.join()

    def get_stats(self) -> MasterStats:
        with self._lock:
            return MasterStats(**self.stats.__dict__)

    def list_slaves(self) -> list:
        """Snapshot of the online slave sessions (design doc §5.5)."""
        return self._sessions.snapshot()

    # ---------------- runtime reconfiguration ----------------

    def apply_runtime_update(self, changes: Mapping[str, Any]) -> MasterConfig:
        """Swap the message fields of a running master without restarting it.

        Takes effect from the next Announce / Sync / Follow_Up / Delay_Resp.
        ``interface`` / ``profile`` / ``offline`` / session-table sizing are not
        runtime-mutable (they need the transport or session table rebuilt), so
        they are rejected here.
        """
        # Keys present in `changes` are applied as-is (vlan_id=None means
        # "remove the VLAN tag"); absent keys keep their current value.
        patch = dict(changes)
        if not patch:
            return self.cfg
        bad = set(patch) & _IMMUTABLE_FIELDS
        if bad:
            raise ValueError(f"字段不可在线修改，需要重启 Master: {', '.join(sorted(bad))}")
        with self._lock:
            new_cfg = replace(self.cfg, **patch)
        new_cfg.validate()
        with self._lock:
            self.cfg = new_cfg
            if new_cfg.clock_identity is not None:
                self.source_port = PortIdentity(new_cfg.clock_identity, new_cfg.port_number)
            elif self.source_port is not None:
                self.source_port = PortIdentity(self.source_port.clock_identity, new_cfg.port_number)
            self._interval_gen += 1
        log.info("master config updated at runtime: %s", sorted(patch))
        return new_cfg

    def run_forever(self) -> None:  # convenience for the CLI
        self.start()
        try:
            self.wait()
        finally:
            self.stop()

    # ---------------- TX loop ----------------

    def _set_state(self, state: MasterState) -> None:
        with self._lock:
            self.stats.state = state

    def _bump(self, attr: str, n: int = 1) -> None:
        with self._lock:
            setattr(self.stats, attr, getattr(self.stats, attr) + n)

    def _emit_frame(self, direction: str, payload: bytes, **extra) -> None:
        """Notify an optional observer (web UI collector) of a TX/RX PTP message."""
        cb = self._on_frame
        if cb is None or not payload:
            return
        try:
            cb(direction, payload[0] & 0xF, payload, {"wall_unix": time.time(), **extra})
        except Exception:  # observer must never break the master loops
            log.debug("on_frame callback failed", exc_info=True)

    def _tx_loop(self) -> None:  # noqa: C901 — single scheduling loop
        transport = self._transport
        assert transport is not None
        assert self.source_port is not None

        def now() -> float:
            return self.clock.now_realtime_ns() / 1_000_000_000

        cfg = self.cfg
        sched_announce = PeriodicScheduler(cfg.log_announce_interval, now())
        sched_sync = PeriodicScheduler(cfg.log_sync_interval, now())
        gen = self._interval_gen
        backoff = 0.0

        while not self._stop_event.is_set():
            if self._interval_gen != gen:
                # A runtime update changed the announce/sync intervals: rebuild
                # both schedulers so the new period applies from the next tick.
                gen = self._interval_gen
                cfg = self.cfg
                now_sec = now()
                sched_announce = PeriodicScheduler(cfg.log_announce_interval, now_sec)
                sched_sync = PeriodicScheduler(cfg.log_sync_interval, now_sec)
            now_sec = now()
            timeout = min(sched_announce.wait_timeout(now_sec), sched_sync.wait_timeout(now_sec))
            if self._stop_event.wait(timeout=max(0.001, min(timeout, 0.5))):
                break
            now_sec = now()
            try:
                if sched_announce.due(now_sec):
                    self._send_announce(transport, now_sec)
                    sched_announce.advance(now_sec)
                if sched_sync.due(now_sec):
                    self._send_sync_pair(transport, now_sec)
                    sched_sync.advance(now_sec)
                if backoff > 0:
                    log.info("TX recovered after fault (errors=%d)", self.stats.tx_errors)
                    backoff = 0.0
                    self._set_state(MasterState.ACTIVE)
            except OSError as e:
                self._bump("tx_errors")
                backoff = min(max(backoff * 2, _FAULT_BACKOFF_MIN), _FAULT_BACKOFF_MAX) if backoff else _FAULT_BACKOFF_MIN
                self._set_state(MasterState.FAULT)
                log.warning("send failed (%s), retry in %.1fs", e, backoff)
                if self._stop_event.wait(backoff):
                    break
                # Re-align deadlines after a fault gap (skip stale ticks).
                now_sec = now()
                sched_announce.advance(now_sec)
                sched_sync.advance(now_sec)
        self._set_state(MasterState.STOPPED)

    def _source_for(self, msg_key: str) -> PortIdentity:
        """sourcePortIdentity for one message type (honours per-message overrides)."""
        cfg = self.cfg
        assert self.source_port is not None
        ci = cfg.effective_clock_identity(msg_key)
        if ci is None:
            ci = self.source_port.clock_identity
        pn = cfg.effective(msg_key, "port_number")
        return PortIdentity(ci, pn)

    def _send_frame(self, transport: L2Transport, payload: bytes, *, msg_key: str = "announce", dst_mac: Optional[bytes] = None) -> None:
        cfg = self.cfg
        frame = build_ethernet_frame(
            dst_mac if dst_mac is not None else cfg.effective(msg_key, "dst_mac"),
            transport.src_mac,
            payload,
            vlan_id=cfg.effective(msg_key, "vlan_id"),
            vlan_pcp=cfg.effective(msg_key, "vlan_pcp"),
        )
        transport.send(frame)

    def _send_announce(self, transport: L2Transport, now_sec: float) -> None:
        cfg = self.cfg
        assert self.source_port is not None
        src = self._source_for("announce")
        seq = self._seq_announce
        self._seq_announce = (seq + 1) & 0xFFFF
        body = AnnounceBody(
            origin_timestamp=self.clock.realtime_ptp_timestamp(),
            current_utc_offset=cfg.current_utc_offset,
            grandmaster_priority1=cfg.priority1,
            grandmaster_clock_quality=ClockQuality(
                cfg.clock_class, cfg.clock_accuracy, cfg.offset_scaled_log_variance
            ),
            grandmaster_priority2=cfg.priority2,
            grandmaster_identity=src.clock_identity,
            steps_removed=0,
            time_source=cfg.time_source,
        )
        payload = build_announce(
            source=src,
            domain_number=cfg.effective("announce", "domain_number"),
            body=body,
            sequence_id=seq,
            log_announce_interval=cfg.log_announce_interval,
            transport_specific=cfg.effective("announce", "transport_specific"),
            flags=cfg.announce_flags,
        )
        self._send_frame(transport, payload, msg_key="announce")
        self._bump("announce_sent")
        self._set_state(MasterState.ACTIVE)
        self._emit_frame("tx", payload)
        log.debug("TX Announce seq=%d utcOffset=%d clockClass=%d", seq, cfg.current_utc_offset, cfg.clock_class)

    def _send_sync_pair(self, transport: L2Transport, now_sec: float) -> None:
        cfg = self.cfg
        assert self.source_port is not None
        seq = self._seq_sync
        self._seq_sync = (seq + 1) & 0xFFFF
        t1 = self.clock.realtime_ptp_timestamp()
        sync_src = self._source_for("sync")
        payload = build_sync(
            source=sync_src,
            domain_number=cfg.effective("sync", "domain_number"),
            origin_timestamp=t1,
            sequence_id=seq,
            log_sync_interval=cfg.log_sync_interval,
            two_step=cfg.two_step,
            transport_specific=cfg.effective("sync", "transport_specific"),
            flags=cfg.sync_flags,
        )
        self._send_frame(transport, payload, msg_key="sync")
        self._bump("sync_sent")
        self._set_state(MasterState.ACTIVE)
        self._emit_frame("tx", payload)
        log.debug("TX Sync seq=%d t1=%d.%09d", seq, t1.seconds, t1.nanoseconds)

        if not cfg.two_step:
            return
        # Software precise timestamp: taken right after the send primitive.
        precise = self.clock.realtime_ptp_timestamp()
        gap = cfg.follow_up_gap_ms / 1000.0
        if gap > 0 and self._stop_event.wait(gap):
            return
        fu_src = self._source_for("followup")
        fu = build_follow_up(
            source=fu_src,
            domain_number=cfg.effective("followup", "domain_number"),
            precise_origin_timestamp=precise,
            sequence_id=seq,
            log_sync_interval=cfg.log_sync_interval,
            transport_specific=cfg.effective("followup", "transport_specific"),
            flags=cfg.follow_up_flags,
        )
        self._send_frame(transport, fu, msg_key="followup")
        self._bump("follow_up_sent")
        self._emit_frame("tx", fu)
        log.debug("TX Follow_Up seq=%d precise=%d.%09d", seq, precise.seconds, precise.nanoseconds)

    # ---------------- RX loop (design doc §5.4) ----------------

    def _rx_loop(self) -> None:
        transport = self._transport
        assert transport is not None
        while not self._stop_event.is_set():
            try:
                frame = transport.recv(timeout=0.2)
            except OSError as e:
                self._bump("rx_parse_errors")
                log.warning("recv failed: %s", e)
                if self._stop_event.wait(0.2):
                    break
                continue
            if frame is None:
                continue
            self._handle_frame(frame)

    def _handle_frame(self, frame: ReceivedFrame) -> None:
        cfg = self.cfg  # read fresh: runtime updates must apply to RX filtering
        payload = frame.payload
        if len(payload) < l2.HEADER_LEN:
            self._bump("rx_parse_errors")
            return
        try:
            hdr = PTPHeader.unpack(payload, 0)
        except ValueError:
            self._bump("rx_parse_errors")
            return
        if hdr.version_ptp != 2:
            self._bump("rx_bad_version")
            return
        # In unlinked mode each message may carry its own domain; accept any.
        if hdr.domain_number not in {cfg.effective(k, "domain_number") for k in cfg.MESSAGE_KEYS}:
            self._bump("rx_other_domain")
            return
        # Ignore our own frames looped back by the NIC/switch (like ptp4l does).
        assert self.source_port is not None
        own_ids = {self.source_port.clock_identity} | {
            cfg.effective_clock_identity(k) for k in cfg.MESSAGE_KEYS
        } - {None}
        if hdr.source_identity.clock_identity in own_ids:
            return
        if hdr.message_type == int(MessageType.ANNOUNCE):
            # Foreign master present (design doc §5.8): first build logs a warning only.
            log.warning(
                "received foreign Announce from clockIdentity=%s (dual-master?)",
                hdr.source_identity.clock_identity.hex(),
            )
            return
        if hdr.message_type != int(MessageType.DELAY_REQ):
            self._bump("rx_other_type")
            return
        try:
            req = parse_delay_req(payload)
        except ValueError:
            self._bump("rx_parse_errors")
            return

        session, allowed = self._sessions.register_or_touch(
            req.header.source_identity, frame.src_mac, frame.rx_monotonic_ns / 1e9
        )
        self._bump("delay_req_recv")
        if session is None:
            self._bump("session_overflow")
            log.warning("session table full; dropping Delay_Req from %s", req.header.source_identity.clock_identity.hex())
            return
        if not allowed:
            self._bump("delay_resp_dropped")
            log.debug("rate limit: dropping Delay_Resp for seq=%d", req.header.sequence_id)
            return
        try:
            self._resp_queue.put_nowait((req.header, frame.rx_realtime_ns, frame.src_mac))
        except queue.Full:
            self._bump("resp_queue_full")
            self._bump("delay_resp_dropped")
            log.warning("resp queue full; dropping Delay_Resp seq=%d", req.header.sequence_id)
            return
        self._emit_frame("rx", payload, src_mac=frame.src_mac.hex(":"))
        log.debug(
            "RX Delay_Req seq=%d slave=%s:%d origin=%d.%09d",
            req.header.sequence_id,
            req.header.source_identity.clock_identity.hex(),
            req.header.source_identity.port_number,
            req.origin_timestamp.seconds,
            req.origin_timestamp.nanoseconds,
        )

    # ---------------- RESP loop (design doc §5.4 step 9-10) ----------------

    def _resp_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                item = self._resp_queue.get(timeout=0.2)
            except queue.Empty:
                continue
            self._send_delay_resp(*item)

    def _drain_resp_queue(self, timeout: float) -> None:
        """Best-effort flush of queued Delay_Req contexts before shutdown (§5.7)."""
        deadline = time.monotonic() + timeout
        transport = self._transport
        while transport is not None and time.monotonic() < deadline:
            try:
                item = self._resp_queue.get_nowait()
            except queue.Empty:
                break
            self._send_delay_resp(*item)

    def _send_delay_resp(self, hdr: PTPHeader, rx_realtime_ns: int, src_mac: bytes) -> None:
        transport = self._transport
        if transport is None or self.source_port is None:
            return
        cfg = self.cfg
        t2 = PTPTimestamp(seconds=rx_realtime_ns // 1_000_000_000, nanoseconds=rx_realtime_ns % 1_000_000_000)
        dr_src = self._source_for("delayresp")
        payload = build_delay_resp(
            source=dr_src,
            domain_number=cfg.effective("delayresp", "domain_number"),
            receive_timestamp=t2,
            requesting_port_identity=hdr.source_identity,
            sequence_id=hdr.sequence_id,
            unicast=cfg.delay_resp_unicast,
            transport_specific=cfg.effective("delayresp", "transport_specific"),
            flags=cfg.delay_resp_flags,
        )
        dst = src_mac if cfg.delay_resp_unicast else cfg.effective("delayresp", "dst_mac")
        try:
            self._send_frame(transport, payload, msg_key="delayresp", dst_mac=dst)
        except OSError as e:
            self._bump("tx_errors")
            self._bump("delay_resp_dropped")
            log.warning("Delay_Resp send failed seq=%d: %s", hdr.sequence_id, e)
            return
        self._bump("delay_resp_sent")
        self._sessions.mark_resp_sent(hdr.source_identity)
        self._emit_frame("tx", payload, dst_mac=dst.hex(":"))
        log.debug(
            "TX Delay_Resp seq=%d to=%s:%d t2=%d.%09d",
            hdr.sequence_id,
            hdr.source_identity.clock_identity.hex(),
            hdr.source_identity.port_number,
            t2.seconds,
            t2.nanoseconds,
        )

