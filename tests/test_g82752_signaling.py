from ptp_client.ptp.constants import FLAG_UNICAST, MessageType
from ptp_client.ptp.header import PortIdentity
from ptp_client.ptp.signaling import (
    build_grant_unicast_tlv,
    build_request_unicast_tlv,
    build_signaling_udp_payload,
    extract_grants_from_signaling_udp,
    parse_grant_value,
    ptp_message_type_from_wire,
    wire_message_type_byte,
)


def test_wire_message_type_roundtrip() -> None:
    assert wire_message_type_byte(int(MessageType.ANNOUNCE)) == 0xB0
    assert ptp_message_type_from_wire(0xB0) == int(MessageType.ANNOUNCE)
    assert wire_message_type_byte(int(MessageType.SYNC)) == 0x00
    assert wire_message_type_byte(int(MessageType.DELAY_RESP)) == 0x90


def test_request_tlv_size() -> None:
    tlv = build_request_unicast_tlv(
        pt_message_type=int(MessageType.SYNC),
        log_inter_message_period=-3,
        duration_sec=300,
    )
    assert len(tlv) == 4 + 6


def test_grant_parse_roundtrip() -> None:
    tlv = build_grant_unicast_tlv(
        pt_message_type=int(MessageType.DELAY_RESP),
        log_inter_message_period=-7,
        duration_sec=120,
        flags=0x01,
    )
    val = tlv[4:]
    g = parse_grant_value(val)
    assert g.pt_message_type == int(MessageType.DELAY_RESP)
    assert g.log_inter_message_period == -7
    assert g.duration_sec == 120


def test_signaling_frame_extract_grants() -> None:
    src = PortIdentity(bytes.fromhex("0102030405060708"), 1)
    tlvs = build_request_unicast_tlv(
        pt_message_type=int(MessageType.ANNOUNCE),
        log_inter_message_period=0,
        duration_sec=60,
    )
    # dummy response: append synthetic grant
    gtlv = build_grant_unicast_tlv(
        pt_message_type=int(MessageType.ANNOUNCE),
        log_inter_message_period=0,
        duration_sec=300,
    )
    _req = build_signaling_udp_payload(
        domain_number=44,
        source_identity=src,
        target_identity=src,
        tlvs=tlvs,
        sequence_id=1,
        flags=FLAG_UNICAST,
    )
    assert len(_req) >= 44
    # Synthetic reply: header + target + grant only
    rep = build_signaling_udp_payload(
        domain_number=44,
        source_identity=src,
        target_identity=src,
        tlvs=gtlv,
        sequence_id=2,
        flags=FLAG_UNICAST,
    )
    grants = extract_grants_from_signaling_udp(rep)
    assert len(grants) == 1
    assert grants[0].duration_sec == 300
