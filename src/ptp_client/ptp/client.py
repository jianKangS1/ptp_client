"""PTPv2 unicast ACR-oriented client: event (319) + general (320) UDP with a receiver thread."""

from __future__ import annotations

import socket
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from ptp_client.ptp.constants import EVENT_PORT, FLAG_TWO_STEP, GENERAL_PORT, MessageType
from ptp_client.ptp.header import PTPHeader, PortIdentity
from ptp_client.ptp.packet import parse_delay_resp_body, parse_follow_up_body, parse_sync_body
from ptp_client.ptp.request_builder import build_ptp_udp_payload
from ptp_client.ptp.serde import ptp_timestamp_to_posix_seconds

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
    Unicast UDP to a master: connected event socket (319) and general socket (320).

    A background thread drains the general port into a bounded deque so Follow_Up / Delay_Resp
    can be matched out-of-order with Sync / Delay_Req.
    """

    def __init__(
        self,
        master_host: str,
        *,
        domain_number: int = 0,
        family: int = socket.AF_INET,
        general_buf_max: int = 1024,
    ) -> None:
        self._master_host = master_host
        self._domain = int(domain_number) & 0xFF
        self._family = family
        self._event_sock: socket.socket | None = None
        self._general_sock: socket.socket | None = None
        self._seq = 0
        self._stop = threading.Event()
        self._reader: threading.Thread | None = None

        self._general_buf: deque[tuple[PTPHeader, bytes, float]] = deque(maxlen=general_buf_max)
        self._general_lock = threading.Lock()
        self._general_cv = threading.Condition(self._general_lock)

    @property
    def domain_number(self) -> int:
        return self._domain

    def allocate_sequence_id(self) -> int:
        self._seq = (self._seq + 1) & 0xFFFF
        return self._seq

    def send_general(self, udp_payload: bytes) -> None:
        """Send a datagram on the connected general port (UDP 320). Used for Signalling."""
        if self._general_sock is None:
            raise RuntimeError("call start() before send_general()")
        self._general_sock.send(udp_payload)

    def start(
        self,
        *,
        source_address: tuple[str, int] | None = None,
        timeout: float | None = None,
    ) -> None:
        if self._event_sock is not None:
            raise RuntimeError("client already started")

        ev = socket.socket(self._family, socket.SOCK_DGRAM)
        gen = socket.socket(self._family, socket.SOCK_DGRAM)
        if timeout is not None:
            ev.settimeout(timeout)
            gen.settimeout(timeout)

        if source_address is not None:
            host, port = source_address[0], int(source_address[1])
            if port == 0:
                ev.bind((host, 0))
                gen.bind((host, 0))
            elif port == EVENT_PORT:
                ev.bind((host, EVENT_PORT))
                gen.bind((host, GENERAL_PORT))
            else:
                raise ValueError(
                    "source_address port must be 0 (dual ephemeral) or 319 (bind 319/320 pair)"
                )

        infos = socket.getaddrinfo(self._master_host, EVENT_PORT, self._family, socket.SOCK_DGRAM)
        ev_peer = infos[0][4]
        infos_g = socket.getaddrinfo(self._master_host, GENERAL_PORT, self._family, socket.SOCK_DGRAM)
        gen_peer = infos_g[0][4]

        ev.connect(ev_peer)
        gen.connect(gen_peer)

        self._event_sock = ev
        self._general_sock = gen
        self._stop.clear()
        self._reader = threading.Thread(target=self._general_reader_loop, name="ptp-general-recv", daemon=True)
        self._reader.start()

    def close(self) -> None:
        self._stop.set()
        try:
            if self._general_sock is not None:
                self._general_sock.close()
        finally:
            if self._event_sock is not None:
                self._event_sock.close()
        if self._reader is not None:
            self._reader.join(timeout=2.0)
        self._event_sock = None
        self._general_sock = None
        self._reader = None
        with self._general_cv:
            self._general_buf.clear()

    def __enter__(self) -> PTPAcrUnicastClient:
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _general_reader_loop(self) -> None:
        assert self._general_sock is not None
        while not self._stop.is_set():
            try:
                self._general_sock.settimeout(0.2)
                data, _peer = self._general_sock.recvfrom(4096)
            except TimeoutError:
                continue
            except OSError:
                break
            wall = time.time()
            try:
                if len(data) < 34:
                    continue
                hdr = PTPHeader.unpack(data, 0)
                if hdr.message_length != len(data):
                    continue
            except ValueError:
                continue
            with self._general_cv:
                self._general_buf.append((hdr, data, wall))
                self._general_cv.notify_all()

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
        raise TimeoutError("timeout waiting for PTP message on general port")

    def exchange_delay(
        self,
        spec: Mapping[str, Any] | None = None,
        *,
        timeout: float = 5.0,
    ) -> PTPDelayExchangeResult:
        if self._event_sock is None or self._general_sock is None:
            raise RuntimeError("call start() before exchange_delay()")

        self._seq = (self._seq + 1) & 0xFFFF
        base: dict[str, Any] = dict(spec or {})
        base.setdefault("message_type", "delay_req")
        base.setdefault("domain_number", self._domain)
        base["sequence_id"] = self._seq

        payload = build_ptp_udp_payload(base)
        hdr0 = PTPHeader.unpack(payload, 0)
        our_id = hdr0.source_identity
        seq = hdr0.sequence_id

        deadline = time.monotonic() + timeout
        t3 = time.time()
        self._event_sock.send(payload)

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
        s_ip, _ = self._event_sock.getpeername()
        if c_ip in ("0.0.0.0", ""):
            c_ip = _local_ip_toward(s_ip)

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
        Block for the next Sync on the event port, then resolve t1:

        - two-step: wait for Follow_Up with matching sequenceId (and same GM clock id) on general port
        - one-step: use originTimestamp in Sync
        """
        if self._event_sock is None:
            raise RuntimeError("call start() before wait_sync_sample()")

        assert self._event_sock is not None
        deadline = time.monotonic() + timeout
        self._event_sock.settimeout(0.2)

        while time.monotonic() < deadline:
            try:
                data, _ = self._event_sock.recvfrom(4096)
            except TimeoutError:
                continue
            wall_sync = time.time()
            if len(data) < 34:
                continue
            try:
                sh = PTPHeader.unpack(data, 0)
                if sh.message_length != len(data) or sh.domain_number != self._domain:
                    continue
                if sh.message_type != int(MessageType.SYNC):
                    continue
            except ValueError:
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

                fh, fpl, _ = self._pop_matching_general(accept_fu, deadline=fu_deadline)
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
