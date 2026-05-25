"""PTPv2 unicast ACR-oriented client: event (319) + general (320) UDP with a receiver thread."""

from __future__ import annotations

import json
import select
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from typing import Any, Callable, Mapping, Sequence

from ptp_client.ptp.constants import (
    EVENT_PORT,
    FLAG_TWO_STEP,
    GENERAL_PORT,
    MessageType,
    PTP_IPV4_MULTICAST,
)
from ptp_client.ptp.ipv4_send import send_ipv4_udp_raw, try_open_ipv4_raw_sender
from ptp_client.ptp.delay_request import build_delay_request_spec
from ptp_client.ptp.header import PTPHeader, PortIdentity
from ptp_client.ptp.packet import parse_delay_resp_body, parse_follow_up_body, parse_sync_body
from ptp_client.ptp.request_builder import build_ptp_udp_payload
from ptp_client.ptp.serde import message_summary, ptp_timestamp_to_posix_seconds

_AGENT_DEBUG_LOG = Path(__file__).resolve().parents[3] / "debug-0f35fe.log"

# Software-only timestamps: send()/recv() boundary uses host wall clock; offset/delay estimates
# are degraded vs hardware timestamping — see project ACR notes.


def _local_ip_toward(peer_ip: str) -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((peer_ip, EVENT_PORT))
        ip, _ = probe.getsockname()
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()
    return ip if ip and ip != "0.0.0.0" else "127.0.0.1"


def _join_ptp_multicast(sock: socket.socket, interface_ip: str) -> None:
    """Join default PTP UDP/IPv4 multicast group on the given interface address."""
    mreq = struct.pack(
        "=4s4s",
        socket.inet_aton(PTP_IPV4_MULTICAST),
        socket.inet_aton(interface_ip),
    )
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)


@dataclass(frozen=True, slots=True)
class PTPDelayExchangeResult:
    delay_req_udp: bytes
    delay_resp_udp: bytes
    request_header: PTPHeader
    response_header: PTPHeader
    t3_send_unix: float
    t4_master_rx_posix_approx: float
    wall_recv_resp_unix: float
    client_ip: str
    client_event_port: int
    server_ip: str


@dataclass(frozen=True, slots=True)
class PTPSyncSampleResult:
    """One two-step Sync + Follow_Up pair (or one-step Sync)."""

    sync_udp: bytes
    follow_up_udp: bytes | None
    sync_header: PTPHeader
    follow_up_header: PTPHeader | None
    t1_master_posix_approx: float
    t2_sync_recv_unix: float
    one_step: bool


@dataclass(frozen=True, slots=True)
class PTPAcrEstimateResult:
    """Combined E2E-style offset / mean path delay from one Sync sample + one Delay exchange."""

    sync: PTPSyncSampleResult
    delay: PTPDelayExchangeResult
    offset_seconds: float
    mean_path_delay_seconds: float


class PTPAcrUnicastClient:
    """
    Unicast UDP to a master: event socket (319) and general socket (320).

    One background **receiver** thread drains both ports into a bounded deque; the
    G.8275.2 **manager** thread (see :class:`G82752UnicastSession`) sends Signalling /
    Delay_Req and waits on the buffer without blocking recv.
    """

    def __init__(
        self,
        master_host: str,
        *,
        domain_number: int = 0,
        family: int = socket.AF_INET,
        general_buf_max: int = 1024,
        on_packet: Callable[[str, str, bytes, float], None] | None = None,
    ) -> None:
        self._master_host = master_host
        self._domain = int(domain_number) & 0xFF
        self._family = family
        self._on_packet = on_packet
        self._event_sock: socket.socket | None = None
        self._general_sock: socket.socket | None = None
        self._seq = 0
        self._stop = threading.Event()
        self._receiver_thread: threading.Thread | None = None

        self._general_buf: deque[tuple[PTPHeader, bytes, float]] = deque(maxlen=general_buf_max)
        self._general_lock = threading.Lock()
        self._general_cv = threading.Condition(self._general_lock)
        self._multicast = False
        self._event_dest: tuple[str, int] = (PTP_IPV4_MULTICAST, EVENT_PORT)
        self._event_peer: tuple[str, int] | None = None
        self._general_peer: tuple[str, int] | None = None
        self._iface_ip = "0.0.0.0"
        self._raw_ip_sender: socket.socket | None = None
        self._ip_id = 0

    @property
    def domain_number(self) -> int:
        return self._domain

    def allocate_sequence_id(self) -> int:
        self._seq = (self._seq + 1) & 0xFFFF
        return self._seq

    def _emit_packet(self, direction: str, channel: str, payload: bytes, wall: float | None = None) -> None:
        if self._on_packet is None:
            return
        if wall is None:
            wall = time.time()
        try:
            self._on_packet(direction, channel, payload, wall)
        except Exception:
            pass

    def _agent_log_outgoing_unicast(self, hypothesis_id: str, channel: str, payload: bytes) -> None:
        # #region agent log
        peer: dict[str, object] | None = None
        try:
            sock = self._event_sock if channel == "event" else self._general_sock
            if sock is not None:
                if channel == "general" and self._general_peer is not None:
                    ip, port = self._general_peer[0], int(self._general_peer[1])
                    peer = {"ip": ip, "port": port}
                elif channel == "event" and self._event_peer is not None:
                    ip, port = self._event_peer[0], int(self._event_peer[1])
                    peer = {"ip": ip, "port": port}
                else:
                    ip, port = sock.getpeername()[:2]
                    peer = {"ip": ip, "port": int(port)}
        except OSError:
            if channel == "general" and self._general_peer is not None:
                peer = {"ip": self._general_peer[0], "port": int(self._general_peer[1])}
            elif channel == "event" and self._event_peer is not None:
                peer = {"ip": self._event_peer[0], "port": int(self._event_peer[1])}
        summ: dict
        try:
            summ = dict(message_summary(payload))
            summ.pop("raw_hex", None)
        except Exception as exc:  # noqa: BLE001 — debug path
            summ = {"parse_error": repr(exc), "raw_length": len(payload)}
        tlv_types: list[dict[str, int]] | str | None = None
        try:
            if len(payload) >= 34:
                hdr = PTPHeader.unpack(payload, 0)
                if hdr.message_type == int(MessageType.SIGNALING):
                    from ptp_client.ptp.signaling import iter_tlvs

                    tlv_types = [{"type": int(t), "lengthField": int(l)} for t, l, _v in iter_tlvs(payload, 44)]
        except Exception:
            tlv_types = "unavailable"
        record = {
            "sessionId": "0f35fe",
            "runId": "pre-fix",
            "hypothesisId": hypothesis_id,
            "location": "ptp/client.py:_agent_log_outgoing_unicast",
            "message": "unicast_udp_send",
            "data": {
                "channel": channel,
                "peer": peer,
                "master_host": self._master_host,
                "domain": self._domain,
                "fields": summ,
                "signaling_tlv_headers": tlv_types,
                "payload_len": len(payload),
                "payload_hex_preview": payload[:64].hex(),
            },
            "timestamp": int(time.time() * 1000),
        }
        try:
            with open(_AGENT_DEBUG_LOG, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError:
            pass
        if "parse_error" not in summ:
            print(
                "[ptp unicast send]",
                channel,
                "peer=",
                peer,
                "msg=",
                summ.get("message_type_name"),
                "seq=",
                summ.get("sequence_id"),
                "domain=",
                summ.get("domain_number"),
                "flags=0x%x" % int(summ.get("flags", 0)),
                "correction_ns=",
                summ.get("correction_field_ns"),
                "source=",
                summ.get("source_identity"),
                "body=",
                summ.get("body"),
                "tlvs=",
                tlv_types,
                flush=True,
            )
        else:
            print("[ptp unicast send]", channel, "peer=", peer, "parse_error=", summ.get("parse_error"), flush=True)
        # #endregion

    def send_general(self, udp_payload: bytes) -> None:
        """Send a datagram on the connected general port (UDP 320). Used for Signalling."""
        if self._general_sock is None:
            raise RuntimeError("call start() before send_general()")
        self._emit_packet("tx", "general", udp_payload)
        self._agent_log_outgoing_unicast("H2", "general", udp_payload)
        if self._multicast:
            self._general_sock.sendto(udp_payload, (PTP_IPV4_MULTICAST, GENERAL_PORT))
        elif self._general_peer is not None:
            self._general_sock.sendto(udp_payload, self._general_peer)
        else:
            self._general_sock.send(udp_payload)

    def _send_event(self, payload: bytes) -> None:
        assert self._event_sock is not None
        self._emit_packet("tx", "event", payload)
        if self._multicast:
            self._event_sock.sendto(payload, self._event_dest)
        elif self._event_peer is not None:
            if self._raw_ip_sender is not None:
                c_ip, c_port = self._event_sock.getsockname()
                if c_ip in ("0.0.0.0", ""):
                    c_ip = _local_ip_toward(self._event_peer[0])
                self._ip_id = (self._ip_id + 1) & 0xFFFF
                try:
                    send_ipv4_udp_raw(
                        self._raw_ip_sender,
                        src_ip=c_ip,
                        dst_ip=self._event_peer[0],
                        src_port=int(c_port),
                        dst_port=int(self._event_peer[1]),
                        payload=payload,
                        ip_id=self._ip_id,
                    )
                    return
                except OSError:
                    pass
            self._event_sock.sendto(payload, self._event_peer)
        else:
            self._event_sock.send(payload)

    def start(
        self,
        *,
        source_address: tuple[str, int] | None = None,
        timeout: float | None = None,
        transport: str = "unicast",
    ) -> None:
        if self._event_sock is not None:
            raise RuntimeError("client already started")

        self._multicast = transport == "multicast"
        ev = socket.socket(self._family, socket.SOCK_DGRAM)
        gen = socket.socket(self._family, socket.SOCK_DGRAM)
        if timeout is not None:
            ev.settimeout(timeout)
            gen.settimeout(timeout)

        iface_ip = "0.0.0.0"
        if source_address is not None:
            host, port = source_address[0], int(source_address[1])
            iface_ip = host
            if self._multicast:
                ev.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                gen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                ev.bind((host, EVENT_PORT))
                gen.bind((host, GENERAL_PORT))
            elif port == 0:
                ev.bind((host, 0))
                gen.bind((host, 0))
            elif port == EVENT_PORT:
                ev.bind((host, EVENT_PORT))
                gen.bind((host, GENERAL_PORT))
            else:
                raise ValueError(
                    "source_address port must be 0 (dual ephemeral) or 319 (bind 319/320 pair)"
                )
        elif self._multicast:
            ev.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            gen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ev.bind(("", EVENT_PORT))
            gen.bind(("", GENERAL_PORT))

        if self._multicast:
            if iface_ip in ("0.0.0.0", ""):
                iface_ip = _local_ip_toward(self._master_host)
            self._iface_ip = iface_ip
            _join_ptp_multicast(ev, iface_ip)
            _join_ptp_multicast(gen, iface_ip)
            self._event_dest = (PTP_IPV4_MULTICAST, EVENT_PORT)
        else:
            infos = socket.getaddrinfo(self._master_host, EVENT_PORT, self._family, socket.SOCK_DGRAM)
            self._event_peer = infos[0][4]
            infos_g = socket.getaddrinfo(self._master_host, GENERAL_PORT, self._family, socket.SOCK_DGRAM)
            self._general_peer = infos_g[0][4]
            # Unconnected UDP + sendto/recvfrom (Windows connected-UDP can drop Sync on 319).
            if sys.platform == "win32":
                self._raw_ip_sender = try_open_ipv4_raw_sender()

        self._event_sock = ev
        self._general_sock = gen
        self._stop.clear()
        self._receiver_thread = threading.Thread(
            target=self._receiver_loop, name="ptp-recv", daemon=True
        )
        self._receiver_thread.start()

    def close(self) -> None:
        self._stop.set()
        try:
            if self._general_sock is not None:
                self._general_sock.close()
        finally:
            if self._event_sock is not None:
                self._event_sock.close()
        if self._raw_ip_sender is not None:
            try:
                self._raw_ip_sender.close()
            except OSError:
                pass
            self._raw_ip_sender = None
        if self._receiver_thread is not None:
            self._receiver_thread.join(timeout=2.0)
        self._event_sock = None
        self._general_sock = None
        self._receiver_thread = None
        with self._general_cv:
            self._general_buf.clear()

    def __enter__(self) -> PTPAcrUnicastClient:
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _ingest_ptp_datagram(self, data: bytes, wall: float | None = None) -> bool:
        """Parse and append one PTP datagram to the general-port buffer. Returns True if accepted."""
        if wall is None:
            wall = time.time()
        try:
            if len(data) < 34:
                return False
            hdr = PTPHeader.unpack(data, 0)
            if len(data) < hdr.message_length:
                return False
            if len(data) > hdr.message_length:
                data = data[: hdr.message_length]
        except ValueError:
            return False
        with self._general_cv:
            self._general_buf.append((hdr, data, wall))
            self._general_cv.notify_all()
            self._emit_packet("rx", "recv", data, wall)
            if hdr.message_type == int(MessageType.SIGNALING):
                from ptp_client.ptp.signaling import describe_signaling_udp

                summ = describe_signaling_udp(data)
                if summ.get("grants"):
                    print("[ptp unicast recv] signaling grants=", summ.get("grants"), flush=True)
                elif summ.get("tlvs"):
                    print("[ptp unicast recv] signaling tlvs=", summ.get("tlvs"), flush=True)
            elif hdr.message_type == int(MessageType.SYNC):
                print(
                    "[ptp unicast recv] sync seq=",
                    hdr.sequence_id,
                    "domain=",
                    hdr.domain_number,
                    "flags=0x%x" % hdr.flags,
                    "source=",
                    hdr.source_identity.clock_identity.hex(),
                    flush=True,
                )
            elif hdr.message_type == int(MessageType.FOLLOW_UP):
                print(
                    "[ptp unicast recv] follow_up seq=",
                    hdr.sequence_id,
                    "domain=",
                    hdr.domain_number,
                    flush=True,
                )
            elif hdr.message_type == int(MessageType.DELAY_RESP):
                print(
                    "[ptp unicast recv] delay_resp seq=",
                    hdr.sequence_id,
                    "domain=",
                    hdr.domain_number,
                    "source=",
                    hdr.source_identity.clock_identity.hex(),
                    flush=True,
                )
        return True

    def _drain_event_to_buffer(self) -> None:
        """No-op when the receiver thread is active (Sync on 319 is ingested there)."""

    def _poll_event_signaling(self) -> None:
        """Yield so the receiver thread can ingest pending datagrams."""
        time.sleep(0)

    def _receiver_loop(self) -> None:
        """Single recv thread: poll event (319) and general (320) sockets."""
        assert self._event_sock is not None and self._general_sock is not None
        socks = [self._event_sock, self._general_sock]
        while not self._stop.is_set():
            try:
                readable, _, _ = select.select(socks, [], [], 0.2)
            except OSError as exc:
                print(f"[ptp dbg] receiver select error: {exc!r}", flush=True)
                break
            for sock in readable:
                try:
                    data, _peer = sock.recvfrom(4096)
                except OSError:
                    continue
                self._ingest_ptp_datagram(data)

    def _pop_matching_general(
        self,
        accept: Callable[[PTPHeader, bytes, float], bool],
        *,
        deadline: float,
    ) -> tuple[PTPHeader, bytes, float]:
        while time.monotonic() < deadline:
            with self._general_cv:
                for idx in range(len(self._general_buf)):
                    hdr, pl, wall = self._general_buf[idx]
                    if accept(hdr, pl, wall):
                        del self._general_buf[idx]
                        return hdr, pl, wall
            wait_for = min(0.05, deadline - time.monotonic())
            if wait_for > 0:
                with self._general_cv:
                    self._general_cv.wait(timeout=wait_for)
        with self._general_cv:
            buf_len = len(self._general_buf)
            types = [int(h.message_type) for h, _pl, _w in list(self._general_buf)[-8:]]
        print(
            f"[ptp dbg] pop_matching timeout buf_len={buf_len} recent_msg_types={types}",
            flush=True,
        )
        raise TimeoutError("timeout waiting for PTP message on general port")

    def _build_two_step_sync_sample(
        self,
        *,
        sh: PTPHeader,
        data: bytes,
        wall_sync: float,
        fh: PTPHeader,
        fpl: bytes,
    ) -> PTPSyncSampleResult:
        fbody = parse_follow_up_body(fpl, fh)
        t1 = ptp_timestamp_to_posix_seconds(fbody.precise_origin_timestamp)
        return PTPSyncSampleResult(
            sync_udp=data,
            follow_up_udp=fpl,
            sync_header=sh,
            follow_up_header=fh,
            t1_master_posix_approx=t1,
            t2_sync_recv_unix=wall_sync,
            one_step=False,
        )

    def _try_sync_sample_follow_up_led(
        self,
        *,
        deadline: float,
        allow_degraded: bool = False,
    ) -> PTPSyncSampleResult | None:
        """
        Two-step recovery when Follow_Up (320) is present but Sync (319) was missed.

        Prefer pairing with a matching Sync in the buffer; optionally fall back to Follow_Up-only
        timestamps so E2E Delay_Req can still be sent (offset estimate is degraded).
        """
        domain = self._domain

        with self._general_cv:
            candidates = [
                (h, pl, w)
                for h, pl, w in self._general_buf
                if h.domain_number == domain and h.message_type == int(MessageType.FOLLOW_UP)
            ]
        if not candidates:
            return None

        fh, fpl, wall_fu = max(candidates, key=lambda x: x[0].sequence_id)
        seq = fh.sequence_id
        gm = fh.source_identity.clock_identity

        def accept_sync(h: PTPHeader, pl: bytes, _w: float) -> bool:
            return (
                h.domain_number == domain
                and h.message_type == int(MessageType.SYNC)
                and h.sequence_id == seq
                and h.source_identity.clock_identity == gm
            )

        sync_deadline = min(deadline, time.monotonic() + 2.0)
        try:
            sh, data, wall_sync = self._pop_matching_general(accept_sync, deadline=sync_deadline)
            with self._general_cv:
                for idx, (h, pl, _w) in enumerate(self._general_buf):
                    if (
                        h.domain_number == domain
                        and h.message_type == int(MessageType.FOLLOW_UP)
                        and h.sequence_id == seq
                    ):
                        del self._general_buf[idx]
                        fh, fpl = h, pl
                        break
            return self._build_two_step_sync_sample(
                sh=sh, data=data, wall_sync=wall_sync, fh=fh, fpl=fpl
            )
        except TimeoutError:
            if not allow_degraded:
                return None

        with self._general_cv:
            for idx, (h, pl, w) in enumerate(self._general_buf):
                if (
                    h.domain_number == domain
                    and h.message_type == int(MessageType.FOLLOW_UP)
                    and h.sequence_id == seq
                ):
                    del self._general_buf[idx]
                    fh, fpl, wall_fu = h, pl, w
                    break

        fbody = parse_follow_up_body(fpl, fh)
        t1 = ptp_timestamp_to_posix_seconds(fbody.precise_origin_timestamp)
        sh = replace(fh, message_type=int(MessageType.SYNC))
        print(
            "[wait_sync_sample] warning: Follow_Up seq=",
            seq,
            "without matching Sync on 319; using degraded software timestamps",
            flush=True,
        )
        return PTPSyncSampleResult(
            sync_udp=fpl,
            follow_up_udp=fpl,
            sync_header=sh,
            follow_up_header=fh,
            t1_master_posix_approx=t1,
            t2_sync_recv_unix=wall_fu,
            one_step=False,
        )

    def exchange_delay(
        self,
        spec: Mapping[str, Any] | None = None,
        *,
        timeout: float = 5.0,
    ) -> PTPDelayExchangeResult:
        if self._event_sock is None or self._general_sock is None:
            raise RuntimeError("call start() before exchange_delay()")

        self._seq = (self._seq + 1) & 0xFFFF
        overrides = dict(spec or {})
        if overrides.get("message_type") == "delay_req":
            base = dict(overrides)
        else:
            base = build_delay_request_spec(
                overrides,
                domain_number=self._domain,
                clock_identity=overrides.get("clock_identity", "0001020304050607"),
                port_number=int(overrides.get("port_number", 1)),
                default_flags=int(overrides.get("flags", 0)),
            )
        base["sequence_id"] = self._seq

        payload = build_ptp_udp_payload(base)
        hdr0 = PTPHeader.unpack(payload, 0)
        our_id = hdr0.source_identity
        seq = hdr0.sequence_id

        deadline = time.monotonic() + timeout
        t3 = time.time()
        print(
            f"[ptp dbg] Delay_Req send seq={seq} timeout={timeout}s deadline_in={timeout:.1f}s",
            flush=True,
        )
        self._agent_log_outgoing_unicast("H1", "event", payload)
        self._send_event(payload)

        def accept_delay_resp(h: PTPHeader, pl: bytes, _w: float) -> bool:
            if h.domain_number != self._domain or h.message_type != int(MessageType.DELAY_RESP):
                return False
            if h.sequence_id != seq:
                return False
            try:
                body = parse_delay_resp_body(pl, h)
            except ValueError:
                return False
            return (
                body.requesting_port_identity.clock_identity == our_id.clock_identity
                and body.requesting_port_identity.port_number == our_id.port_number
            )

        rh, rpl, wall_r = self._pop_matching_general(accept_delay_resp, deadline=deadline)
        body = parse_delay_resp_body(rpl, rh)
        t4 = ptp_timestamp_to_posix_seconds(body.receive_timestamp)

        c_ip, c_port = self._event_sock.getsockname()
        if self._multicast:
            s_ip = self._master_host
        elif self._event_peer is not None:
            s_ip = self._event_peer[0]
        else:
            s_ip, _ = self._event_sock.getpeername()
        if c_ip in ("0.0.0.0", ""):
            c_ip = _local_ip_toward(s_ip if not self._multicast else self._master_host)

        return PTPDelayExchangeResult(
            delay_req_udp=payload,
            delay_resp_udp=rpl,
            request_header=hdr0,
            response_header=rh,
            t3_send_unix=t3,
            t4_master_rx_posix_approx=t4,
            wall_recv_resp_unix=wall_r,
            client_ip=c_ip,
            client_event_port=int(c_port),
            server_ip=s_ip,
        )

    def wait_sync_sample(
        self,
        *,
        timeout: float = 5.0,
    ) -> PTPSyncSampleResult:
        """
        Block for the next Sync, then resolve t1 (two-step: matching Follow_Up on general port).

        Sync may arrive on event port (319) or already sit in ``_general_buf`` after negotiation
        (``_drain_event_to_buffer`` during Signalling GRANT wait moves 319 traffic there).
        """
        if self._event_sock is None:
            raise RuntimeError("call start() before wait_sync_sample()")

        deadline = time.monotonic() + timeout

        def accept_sync(h: PTPHeader, pl: bytes, _w: float) -> bool:
            if h.domain_number != self._domain or h.message_type != int(MessageType.SYNC):
                return False
            if len(pl) < h.message_length:
                return False
            return True

        while time.monotonic() < deadline:
            try:
                sh, data, wall_sync = self._pop_matching_general(
                    accept_sync,
                    deadline=time.monotonic() + 0.05,
                )
            except TimeoutError:
                paired = self._try_sync_sample_follow_up_led(
                    deadline=deadline,
                    allow_degraded=False,
                )
                if paired is not None:
                    return paired
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    with self._general_cv:
                        self._general_cv.wait(timeout=min(0.05, remaining))
                continue

            sync_body = parse_sync_body(data, sh)
            gm_clock = sh.source_identity.clock_identity

            if sh.flags & FLAG_TWO_STEP:
                fu_deadline = time.monotonic() + max(0.0, deadline - time.monotonic())

                def accept_fu(h: PTPHeader, pl: bytes, _w: float) -> bool:
                    if h.domain_number != self._domain or h.message_type != int(MessageType.FOLLOW_UP):
                        return False
                    if h.sequence_id != sh.sequence_id:
                        return False
                    return h.source_identity.clock_identity == gm_clock

                self._drain_event_to_buffer()
                fh, fpl, _ = self._pop_matching_general(accept_fu, deadline=fu_deadline)
                return self._build_two_step_sync_sample(
                    sh=sh, data=data, wall_sync=wall_sync, fh=fh, fpl=fpl
                )

            t1 = ptp_timestamp_to_posix_seconds(sync_body.origin_timestamp)
            return PTPSyncSampleResult(
                sync_udp=data,
                follow_up_udp=None,
                sync_header=sh,
                follow_up_header=None,
                t1_master_posix_approx=t1,
                t2_sync_recv_unix=wall_sync,
                one_step=True,
            )

        with self._general_cv:
            pending_types = [
                int(h.message_type)
                for h, _pl, _w in self._general_buf
                if h.domain_number == self._domain
            ]
        print(
            "[wait_sync_sample] timeout; buffered domain-matched message types:",
            pending_types[:20],
            flush=True,
        )
        degraded = self._try_sync_sample_follow_up_led(deadline=time.monotonic(), allow_degraded=True)
        if degraded is not None:
            return degraded
        raise TimeoutError("timeout waiting for PTP Sync")

    def estimate_offset_and_delay(
        self,
        *,
        delay_spec: Mapping[str, Any] | None = None,
        sync_timeout: float = 5.0,
        delay_timeout: float = 5.0,
    ) -> PTPAcrEstimateResult:
        """
        One Sync sample (two-step or one-step) plus one Delay_Req/Delay_Resp exchange.

        Uses the usual E2E-style combination (ignores correctionField subtleties):

        offset = ((t2 - t1) - (t4 - t3)) / 2
        mean_delay = ((t2 - t1) + (t4 - t3)) / 2

        All times are approximations when software timestamping is used.
        """
        sync = self.wait_sync_sample(timeout=sync_timeout)
        delay = self.exchange_delay(delay_spec, timeout=delay_timeout)
        t1 = sync.t1_master_posix_approx
        t2 = sync.t2_sync_recv_unix
        t3 = delay.t3_send_unix
        t4 = delay.t4_master_rx_posix_approx
        offset = ((t2 - t1) - (t4 - t3)) / 2.0
        mean_delay = ((t2 - t1) + (t4 - t3)) / 2.0
        return PTPAcrEstimateResult(sync=sync, delay=delay, offset_seconds=offset, mean_path_delay_seconds=mean_delay)


def run_parallel_delay_exchanges(
    masters: Sequence[str],
    *,
    workers: int = 8,
    timeout: float = 5.0,
    domain_number: int = 0,
    delay_spec: Mapping[str, Any] | None = None,
    source_address: tuple[str, int] | None = None,
) -> list[tuple[str, PTPDelayExchangeResult | BaseException]]:
    """
    Run independent Delay_Req exchanges against multiple masters (each uses its own client + thread).

    Returns one entry per host in the same order as ``masters``; failures are ``Exception`` values.
    """

    def job(host: str) -> PTPDelayExchangeResult:
        c = PTPAcrUnicastClient(host, domain_number=domain_number)
        try:
            c.start(source_address=source_address)
            return c.exchange_delay(delay_spec, timeout=timeout)
        finally:
            c.close()

    out: list[tuple[str, PTPDelayExchangeResult | BaseException]] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(job, h) for h in masters]
        for h, fut in zip(masters, futures, strict=True):
            try:
                out.append((h, fut.result(timeout=timeout + 30.0)))
            except Exception as e:
                out.append((h, e))
    return out
