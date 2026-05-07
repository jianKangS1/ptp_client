import pytest

from ptp_client.ptp.constants import MessageType
from ptp_client.ptp.header import PTPHeader, PortIdentity
from ptp_client.ptp.packet import parse_delay_req_body, parse_delay_resp_body
from ptp_client.ptp.request_builder import build_ptp_udp_payload
from ptp_client.ptp.timestamp import PTPTimestamp


def test_ptp_header_roundtrip() -> None:
    src = PortIdentity(bytes.fromhex("aabbccddeeff0011"), 7)
    h = PTPHeader(
        message_type=int(MessageType.DELAY_REQ),
        version_ptp=2,
        message_length=54,
        domain_number=3,
        minor_sdo_id=0,
        flags=0x0200,
        correction_field_ns=-1000,
        source_identity=src,
        sequence_id=0x1234,
        control_field=0x01,
        log_message_interval=-3,
        transport_specific=0,
    )
    raw = h.pack()
    assert len(raw) == 34
    g = PTPHeader.unpack(raw, 0)
    assert g.message_type == h.message_type
    assert g.version_ptp == 2
    assert g.message_length == 54
    assert g.domain_number == 3
    assert g.flags == 0x0200
    assert g.correction_field_ns == -1000
    assert g.source_identity.clock_identity == src.clock_identity
    assert g.source_identity.port_number == 7
    assert g.sequence_id == 0x1234
    assert g.control_field == 0x01
    assert g.log_message_interval == -3


def test_delay_req_payload_size_and_parse() -> None:
    spec = {
        "message_type": "delay_req",
        "domain_number": 0,
        "sequence_id": 9,
        "clock_identity": "0102030405060708",
        "port_number": 2,
        "origin_timestamp": {"seconds": 1_700_000_000, "nanoseconds": 123_456_789},
    }
    udp = build_ptp_udp_payload(spec)
    assert len(udp) == 54
    hdr = PTPHeader.unpack(udp, 0)
    assert hdr.message_length == len(udp)
    body = parse_delay_req_body(udp, hdr)
    assert body.origin_timestamp == PTPTimestamp(1_700_000_000, 123_456_789)


def test_delay_resp_parse() -> None:
    spec = {
        "message_type": "delay_resp",
        "sequence_id": 3,
        "clock_identity": "1020304050607080",
        "port_number": 1,
        "receive_timestamp": {"seconds": 100, "nanoseconds": 0},
        "requesting_port_identity": {"clock_identity": "0102030405060708", "port_number": 2},
    }
    udp = build_ptp_udp_payload(spec)
    hdr = PTPHeader.unpack(udp, 0)
    body = parse_delay_resp_body(udp, hdr)
    assert body.receive_timestamp.seconds == 100
    assert body.requesting_port_identity.port_number == 2


def test_invalid_clock_identity() -> None:
    with pytest.raises(ValueError):
        build_ptp_udp_payload({"message_type": "sync", "clock_identity": "deadbeef"})
