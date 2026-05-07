"""
PTP Signaling TLVs for unicast negotiation (IEEE 1588 clause 16.1).

Wire layout matches common open-source stacks (e.g. linuxptp `tlv.h`): the
``message_type`` octet in REQUEST/GRANT TLVs carries ``(ptpMessageType << 4)``.

Profile behaviour for ITU-T G.8275.2 is orchestrated in :mod:`ptp_client.ptp.g82752_unicast`.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ptp_client.ptp.constants import FLAG_UNICAST, MessageType
from ptp_client.ptp.header import PTPHeader, PortIdentity

# IEEE 1588 TLV typeField values (linuxptp `tlv.h`)
TLV_REQUEST_UNICAST_TRANSMISSION = 0x0004
TLV_GRANT_UNICAST_TRANSMISSION = 0x0005
TLV_CANCEL_UNICAST_TRANSMISSION = 0x0006
TLV_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION = 0x0007

REQUEST_TLV_LENGTH_FIELD = 6
GRANT_TLV_LENGTH_FIELD = 8

TARGET_PORT_IDENTITY_WILDCARD = PortIdentity(bytes([0xFF] * 8), 0xFFFF)


def wire_message_type_byte(pt_message_type: int) -> int:
    """Encode PTP message type (e.g. 0x0B Announce) for REQUEST/GRANT/CANCEL style TLVs."""
    return (int(pt_message_type) & 0x0F) << 4


def ptp_message_type_from_wire(wire_byte: int) -> int:
    return (int(wire_byte) >> 4) & 0x0F


def build_request_unicast_tlv(*, pt_message_type: int, log_inter_message_period: int, duration_sec: int) -> bytes:
    """REQUEST_UNICAST_TRANSMISSION TLV (value length 6 per IEEE / linuxptp)."""
    body = struct.pack(
        "!BbI",
        wire_message_type_byte(pt_message_type),
        int(log_inter_message_period),
        int(duration_sec) & 0xFFFFFFFF,
    )
    if len(body) != 6:
        raise AssertionError
    return struct.pack("!HH", TLV_REQUEST_UNICAST_TRANSMISSION, REQUEST_TLV_LENGTH_FIELD) + body


def build_grant_unicast_tlv(
    *,
    pt_message_type: int,
    log_inter_message_period: int,
    duration_sec: int,
    reserved: int = 0,
    flags: int = 0,
) -> bytes:
    """GRANT_UNICAST_TRANSMISSION TLV (value length 8). duration_sec==0 means deny (linuxptp)."""
    val = struct.pack(
        "!BbIBB",
        wire_message_type_byte(pt_message_type),
        int(log_inter_message_period),
        int(duration_sec) & 0xFFFFFFFF,
        reserved & 0xFF,
        flags & 0xFF,
    )
    if len(val) != 8:
        raise AssertionError
    return struct.pack("!HH", TLV_GRANT_UNICAST_TRANSMISSION, GRANT_TLV_LENGTH_FIELD) + val


def build_cancel_unicast_tlv(*, pt_message_type: int) -> bytes:
    """CANCEL_UNICAST_TRANSMISSION TLV (value length 2)."""
    flags = wire_message_type_byte(pt_message_type)
    val = struct.pack("!BB", flags, 0)
    return struct.pack("!HH", TLV_CANCEL_UNICAST_TRANSMISSION, 2) + val


def build_ack_cancel_unicast_tlv(*, pt_message_type: int) -> bytes:
    val = struct.pack("!BB", wire_message_type_byte(pt_message_type), 0)
    return struct.pack("!HH", TLV_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION, 2) + val


def iter_tlvs(signaling_payload: bytes, body_start: int = 44) -> tuple[int, int, bytes]:
    """Yield (type, lengthField, value_bytes) from Signaling/Management style suffix."""
    off = body_start
    while off + 4 <= len(signaling_payload):
        typ, ln = struct.unpack_from("!HH", signaling_payload, off)
        off += 4
        if off + ln > len(signaling_payload):
            break
        yield typ, ln, signaling_payload[off : off + ln]
        off += ln


@dataclass(frozen=True, slots=True)
class ParsedGrant:
    pt_message_type: int
    log_inter_message_period: int
    duration_sec: int
    flags: int


def parse_grant_value(value: bytes) -> ParsedGrant:
    if len(value) < 8:
        raise ValueError("GRANT TLV value too short")
    mt_wire, log_i8, dur, _res, flg = struct.unpack_from("!BbIBB", value, 0)
    return ParsedGrant(
        pt_message_type=ptp_message_type_from_wire(mt_wire),
        log_inter_message_period=log_i8,
        duration_sec=dur & 0xFFFFFFFF,
        flags=flg,
    )


def parse_request_value(value: bytes) -> ParsedGrant:
    """Same numeric fields as grant without reserved/flags (first 6 octets)."""
    if len(value) < 6:
        raise ValueError("REQUEST TLV value too short")
    mt_wire, log_i8, dur = struct.unpack_from("!BbI", value, 0)
    return ParsedGrant(
        pt_message_type=ptp_message_type_from_wire(mt_wire),
        log_inter_message_period=log_i8,
        duration_sec=dur & 0xFFFFFFFF,
        flags=0,
    )


def extract_grants_from_signaling_udp(udp_payload: bytes) -> list[ParsedGrant]:
    hdr = PTPHeader.unpack(udp_payload, 0)
    if hdr.message_type != int(MessageType.SIGNALING):
        return []
    out: list[ParsedGrant] = []
    for typ, _ln, val in iter_tlvs(udp_payload, body_start=44):
        if typ == TLV_GRANT_UNICAST_TRANSMISSION:
            out.append(parse_grant_value(val))
    return out


def build_signaling_udp_payload(
    *,
    domain_number: int,
    source_identity: PortIdentity,
    target_identity: PortIdentity,
    tlvs: bytes,
    sequence_id: int,
    version_ptp: int = 2,
    log_message_interval: int = 0x7F,
    flags: int = FLAG_UNICAST,
) -> bytes:
    """Full Signaling message: header + targetPortIdentity + concatenated TLV octets."""
    body = target_identity.pack() + tlvs
    msg_len = 34 + len(body)
    hdr = PTPHeader(
        message_type=int(MessageType.SIGNALING),
        version_ptp=version_ptp,
        message_length=msg_len,
        domain_number=domain_number & 0xFF,
        minor_sdo_id=0,
        flags=flags,
        correction_field_ns=0,
        source_identity=source_identity,
        sequence_id=sequence_id & 0xFFFF,
        control_field=0,
        log_message_interval=log_message_interval,
        transport_specific=0,
    )
    return hdr.pack() + body
