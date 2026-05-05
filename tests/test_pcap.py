from ptp_client.ntp.pcap import build_ipv4_udp_datagram, build_ntp_exchange_pcap


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


def test_pcap_two_records() -> None:
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
