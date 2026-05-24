"""Minimal libpcap (microsecond) writer: two IPv4/UDP datagrams (LINKTYPE_RAW 101)."""

from __future__ import annotations

import socket
import struct


# tcpdump / Wireshark: LINKTYPE_RAW — IPv4 or IPv6 header begins the packet
LINKTYPE_RAW_IP = 101


def _ipv4_checksum(header_20: bytes) -> int:
    assert len(header_20) == 20
    s = sum(struct.unpack("!10H", header_20))
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _udp_checksum(src_ip: str, dst_ip: str, udp_segment: bytes) -> int:
    """RFC 768 UDP checksum over pseudo-header + UDP header + payload."""
    pseudo = (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + struct.pack("!HH", 17, len(udp_segment))
        + udp_segment
    )
    if len(pseudo) % 2:
        pseudo += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(pseudo) // 2), pseudo))
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    csum = (~s) & 0xFFFF
    return 0xFFFF if csum == 0 else csum


def build_ipv4_udp_datagram(
    *,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes,
    ip_id: int,
) -> bytes:
    """IPv4 header + UDP header + payload with valid IP and UDP checksums."""
    total_len = 20 + 8 + len(payload)
    saddr = struct.unpack("!I", socket.inet_aton(src_ip))[0]
    daddr = struct.unpack("!I", socket.inet_aton(dst_ip))[0]
    hdr = struct.pack(
        "!BBHHHBBHII",
        0x45,
        0x00,
        total_len,
        ip_id & 0xFFFF,
        0x4000,
        64,
        17,
        0,
        saddr,
        daddr,
    )
    csum = _ipv4_checksum(hdr)
    hdr = struct.pack(
        "!BBHHHBBHII",
        0x45,
        0x00,
        total_len,
        ip_id & 0xFFFF,
        0x4000,
        64,
        17,
        csum,
        saddr,
        daddr,
    )
    udp_len = 8 + len(payload)
    udp_hdr = struct.pack("!HHHH", src_port & 0xFFFF, dst_port & 0xFFFF, udp_len, 0)
    udp_csum = _udp_checksum(src_ip, dst_ip, udp_hdr + payload)
    udp = struct.pack("!HHHH", src_port & 0xFFFF, dst_port & 0xFFFF, udp_len, udp_csum)
    return hdr + udp + payload


def pcap_global_header(link_type: int = LINKTYPE_RAW_IP) -> bytes:
    return struct.pack(
        "<IHHIIII",
        0xA1B2C3D4,
        2,
        4,
        0,
        0,
        65535,
        link_type,
    )


def pcap_record(ts_unix: float, pkt: bytes) -> bytes:
    sec = int(ts_unix)
    usec = int((ts_unix - sec) * 1_000_000)
    incl = len(pkt)
    return struct.pack("<IIII", sec, usec, incl, incl) + pkt


def build_ntp_exchange_pcap(
    *,
    client_ip: str,
    server_ip: str,
    client_port: int,
    server_port: int,
    request_udp: bytes,
    response_udp: bytes,
    wall_send_unix: float,
    wall_recv_unix: float,
) -> bytes:
    """Two records: client→server, server→client."""
    id1 = int(wall_send_unix * 1_000_000) & 0xFFFF
    id2 = id1 ^ 0xACE1
    p1 = build_ipv4_udp_datagram(
        src_ip=client_ip,
        dst_ip=server_ip,
        src_port=client_port,
        dst_port=server_port,
        payload=request_udp,
        ip_id=id1,
    )
    p2 = build_ipv4_udp_datagram(
        src_ip=server_ip,
        dst_ip=client_ip,
        src_port=server_port,
        dst_port=client_port,
        payload=response_udp,
        ip_id=id2,
    )
    parts: list[bytes] = [pcap_global_header()]
    parts.append(pcap_record(wall_send_unix, p1))
    parts.append(pcap_record(wall_recv_unix, p2))
    return b"".join(parts)


def format_hex_preview(data: bytes, width: int = 16, max_lines: int = 64) -> list[str]:
    lines: list[str] = []
    for i in range(0, min(len(data), width * max_lines), width):
        chunk = data[i : i + width]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hx:<{width*3}}  {asc}")
    if len(data) > width * max_lines:
        lines.append(f"... ({len(data)} bytes total, truncated preview)")
    return lines
