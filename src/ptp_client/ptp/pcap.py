"""Build pcap traces for PTP UDP datagrams (IPv4 LINKTYPE_RAW)."""

from __future__ import annotations

from ptp_client.ntp.pcap import build_ipv4_udp_datagram, pcap_global_header, pcap_record


def build_ptp_udp_pcap(records: list[tuple[float, str, int, str, int, bytes]]) -> bytes:
    """
    One pcap file from a list of UDP payloads and five-tuple metadata.

    Each record: ``(wall_unix, src_ip, src_port, dst_ip, dst_port, udp_payload)``.
    """
    parts: list[bytes] = [pcap_global_header()]
    for i, (ts, sip, sport, dip, dport, payload) in enumerate(records):
        pkt = build_ipv4_udp_datagram(
            src_ip=sip,
            dst_ip=dip,
            src_port=sport,
            dst_port=dport,
            payload=payload,
            ip_id=(int(ts * 1_000_000) ^ (i * 0x1357)) & 0xFFFF,
        )
        parts.append(pcap_record(ts, pkt))
    return b"".join(parts)
