import struct

from ptp_client.ntp.pcap import _ipv4_checksum, _udp_checksum, build_ipv4_udp_datagram


def test_ipv4_udp_ntp_length() -> None:
    ntp = b"\x00" * 48
    pkt = build_ipv4_udp_datagram(
        src_ip="192.0.2.1",
        dst_ip="192.0.2.2",
        src_port=54321,
        dst_port=123,
        payload=ntp,
        ip_id=0x1234,
    )
    assert len(pkt) == 20 + 8 + 48


def test_ipv4_udp_checksums_delay_req_size() -> None:
    """44-octet PTP Delay_Req UDP payload (G.8275 lab) must have valid L3/L4 checksums."""
    from ptp_client.ptp.constants import FLAG_UNICAST
    from ptp_client.ptp.request_builder import build_ptp_udp_payload

    ptp = build_ptp_udp_payload(
        {
            "message_type": "delay_req",
            "domain_number": 44,
            "sequence_id": 3,
            "clock_identity": "0001020304050607",
            "port_number": 1,
            "flags": FLAG_UNICAST,
        }
    )
    assert len(ptp) == 44
    pkt = build_ipv4_udp_datagram(
        src_ip="172.19.160.1",
        dst_ip="172.19.173.58",
        src_port=319,
        dst_port=319,
        payload=ptp,
        ip_id=0xABCD,
    )
    assert len(pkt) == 20 + 8 + 44
    ip_hdr = bytearray(pkt[:20])
    ip_stored = struct.unpack("!H", ip_hdr[10:12])[0]
    ip_hdr[10:12] = b"\x00\x00"
    assert ip_stored == _ipv4_checksum(bytes(ip_hdr))
    udp_csum = struct.unpack("!H", pkt[26:28])[0]
    assert udp_csum != 0
    sport, dport, udp_len, _ = struct.unpack("!HHHH", pkt[20:28])
    udp_zero_csum = struct.pack("!HHHH", sport, dport, udp_len, 0) + pkt[28:]
    assert udp_csum == _udp_checksum("172.19.160.1", "172.19.173.58", udp_zero_csum)


def test_pcap_two_records() -> None:
    from ptp_client.ntp.pcap import build_ntp_exchange_pcap

    pcap = build_ntp_exchange_pcap(
        client_ip="192.0.2.1",
        server_ip="192.0.2.2",
        client_port=50000,
        server_port=123,
        request_udp=b"\x01" * 48,
        response_udp=b"\x02" * 48,
        wall_send_unix=1_700_000_000.0,
        wall_recv_unix=1_700_000_000.25,
    )
    assert pcap[:4] == b"\xd4\xc3\xb2\xa1"
    assert len(pcap) == 24 + (16 + 76) * 2
