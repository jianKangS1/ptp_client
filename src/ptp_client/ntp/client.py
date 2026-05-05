"""UDP NTP/SNTP client: send customizable requests, parse responses, estimate offset and delay."""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from ptp_client.ntp.packet import NTPPacket, NTPTime


def _local_ip_toward(peer_ip: str) -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((peer_ip, 123))
        ip, _ = probe.getsockname()
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()
    return ip if ip and ip != "0.0.0.0" else "127.0.0.1"


@dataclass(frozen=True, slots=True)
class NTPExchangeResult:
    """One client–server exchange (RFC 5905 delay/offset formulas)."""

    request: NTPPacket
    response: NTPPacket
    t1_unix: float
    t2_unix: float
    t3_unix: float
    t4_unix: float
    offset_seconds: float
    round_trip_delay_seconds: float
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    request_udp: bytes
    response_udp: bytes
    wall_send_unix: float
    wall_recv_unix: float

    @property
    def stratum(self) -> int:
        return self.response.stratum

    @property
    def kiss_code(self) -> str | None:
        """If stratum is 0, reference id is a kiss code (4 ASCII chars)."""
        if self.response.stratum != 0:
            return None
        return self.response.reference_id_as_text()


class NTPClient:
    """Stateless SNTP-style client over IPv4 UDP (extend for IPv6 later)."""

    def __init__(self, *, family: int = socket.AF_INET) -> None:
        self._family = family

    def exchange(
        self,
        host: str,
        port: int = 123,
        *,
        request: NTPPacket | None = None,
        timeout: float = 5.0,
        source_address: tuple[str, int] | None = None,
    ) -> NTPExchangeResult:
        """
        Send one NTP request and wait for a 48-byte reply.

        :param request: Full packet (use `NTPPacket` or `NTPPacket.client_request(...)`).
        :param source_address: Optional (bind_host, bind_port) before send.
        """
        req = request if request is not None else NTPPacket.client_request()
        payload = req.pack()

        infos = socket.getaddrinfo(host, port, self._family, socket.SOCK_DGRAM)
        peer = infos[0][4]

        with socket.socket(self._family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            if source_address is not None:
                sock.bind(source_address)
            sock.connect(peer)
            wall_send = time.time()
            sock.send(payload)
            data = sock.recv(2048)
            wall_recv = time.time()

            c_ip, c_port = sock.getsockname()
            s_ip, s_port = sock.getpeername()

        rsp = NTPPacket.from_bytes(data)
        t4 = wall_recv
        t1 = req.origin_timestamp.to_unix()
        t2 = rsp.receive_timestamp.to_unix()
        t3 = rsp.transmit_timestamp.to_unix()

        offset = ((t2 - t1) + (t3 - t4)) / 2.0
        delay = (t4 - t1) - (t3 - t2)

        if c_ip in ("0.0.0.0", ""):
            c_ip = _local_ip_toward(s_ip)

        return NTPExchangeResult(
            request=req,
            response=rsp,
            t1_unix=t1,
            t2_unix=t2,
            t3_unix=t3,
            t4_unix=t4,
            offset_seconds=offset,
            round_trip_delay_seconds=delay,
            client_ip=c_ip,
            client_port=int(c_port),
            server_ip=s_ip,
            server_port=int(s_port),
            request_udp=payload,
            response_udp=bytes(data),
            wall_send_unix=wall_send,
            wall_recv_unix=wall_recv,
        )


def quick_offset(host: str, port: int = 123, *, timeout: float = 5.0) -> NTPExchangeResult:
    """One-shot query with default client packet (mode client, v4, origin = send time)."""
    return NTPClient().exchange(host, port, timeout=timeout)
