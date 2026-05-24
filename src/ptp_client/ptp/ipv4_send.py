"""IPv4/UDP transmit with software-computed checksums (Windows Wireshark / lab)."""

from __future__ import annotations

import socket
import sys

from ptp_client.ntp.pcap import build_ipv4_udp_datagram


def try_open_ipv4_raw_sender() -> socket.socket | None:
    """
    Open a raw IPv4 sender (IP_HDRINCL) so IP/UDP checksums are on-wire as built.

    Requires Administrator on Windows. Returns None if unavailable.
    """
    if sys.platform != "win32":
        return None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        return s
    except OSError:
        return None


def send_ipv4_udp_raw(
    raw_sock: socket.socket,
    *,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes,
    ip_id: int,
) -> None:
    """Send one IPv4/UDP datagram with valid header checksums."""
    pkt = build_ipv4_udp_datagram(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        payload=payload,
        ip_id=ip_id,
    )
    raw_sock.sendto(pkt, (dst_ip, 0))
