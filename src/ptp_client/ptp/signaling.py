"""
PTP Signaling TLVs for unicast negotiation (IEEE 1588 clause 16.1).

Wire layout matches common open-source stacks (e.g. linuxptp `tlv.h`): the
``message_type`` octet in REQUEST/GRANT TLVs carries ``(ptpMessageType << 4)``.

Profile behaviour for ITU-T G.8275.2 is orchestrated in :mod:`ptp_client.ptp.g82752_unicast`.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Mapping

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
    for typ, ln, val in iter_tlvs(udp_payload, body_start=44):
        if typ == TLV_GRANT_UNICAST_TRANSMISSION:
            try:
                out.append(parse_grant_value(val))
            except ValueError:
                if ln >= 6 and len(val) >= 6:
                    out.append(parse_request_value(val))
    if out:
        return out
    # Fallback: scan for GRANT TLV headers (linuxptp / lab captures with padding)
    off = 44
    while off + 4 <= len(udp_payload):
        typ, ln = struct.unpack_from("!HH", udp_payload, off)
        if typ == TLV_GRANT_UNICAST_TRANSMISSION and off + 4 + ln <= len(udp_payload):
            val = udp_payload[off + 4 : off + 4 + ln]
            try:
                out.append(parse_grant_value(val))
            except ValueError:
                if len(val) >= 6:
                    out.append(parse_request_value(val))
        off += 1
    return out


def describe_signaling_udp(udp_payload: bytes) -> dict:
    """Debug summary of a Signaling datagram (TLV types, grants)."""
    try:
        hdr = PTPHeader.unpack(udp_payload, 0)
    except ValueError as exc:
        return {"error": repr(exc), "raw_length": len(udp_payload)}
    tlvs = [{"type": int(t), "lengthField": int(l)} for t, l, _v in iter_tlvs(udp_payload, 44)]
    grants = extract_grants_from_signaling_udp(udp_payload)
    return {
        "message_type": int(hdr.message_type),
        "domain_number": hdr.domain_number,
        "sequence_id": hdr.sequence_id,
        "message_length": hdr.message_length,
        "raw_length": len(udp_payload),
        "tlvs": tlvs,
        "grants": [
            {
                "pt_message_type": g.pt_message_type,
                "duration_sec": g.duration_sec,
                "log_inter_message_period": g.log_inter_message_period,
            }
            for g in grants
        ],
    }


def build_signaling_message(spec: Mapping) -> bytes:
    """Build a full Signaling message from a flat spec dict (Wireshark field order).

    All header fields are individually controllable so the web lab can mirror a
    real capture byte-for-byte. ``correction_field_ns`` is float nanoseconds and
    is encoded as the on-wire int64 scaled-ns value (ns * 2**16).
    """
    b0 = ((int(spec.get("major_sdo_id", 0)) & 0xF) << 4) | (int(spec.get("message_type", int(MessageType.SIGNALING))) & 0xF)
    b1 = ((int(spec.get("minor_version_ptp", 0)) & 0xF) << 4) | (int(spec.get("version_ptp", 2)) & 0xF)
    domain_number = int(spec.get("domain_number", 0)) & 0xFF
    minor_sdo_id = int(spec.get("minor_sdo_id", 0)) & 0xF
    flags = int(spec.get("flags", FLAG_UNICAST)) & 0xFFFF
    correction_raw = int(round(float(spec.get("correction_field_ns", 0)) * 65536))
    message_type_specific = int(spec.get("message_type_specific", 0)) & 0xFFFFFFFF
    clock_identity = _parse_clock_identity_hex(str(spec.get("clock_identity", "0001020304050607")))
    source_port_id = int(spec.get("source_port_id", 1)) & 0xFFFF
    sequence_id = int(spec.get("sequence_id", 0)) & 0xFFFF
    control_field = int(spec.get("control_field", 0x05)) & 0xFF
    log_message_interval = max(-128, min(127, int(spec.get("log_message_interval", 127))))
    target_clock_identity = _parse_clock_identity_hex(str(spec.get("target_clock_identity", "ffffffffffffffff")))
    target_port_id = int(spec.get("target_port_id", 0xFFFF)) & 0xFFFF

    tlv_type = int(spec.get("tlv_type", TLV_REQUEST_UNICAST_TRANSMISSION))
    mt_wire = wire_message_type_byte(int(spec.get("tlv_message_type", 0)))
    log_period = max(-128, min(127, int(spec.get("log_inter_message_period", 0))))
    duration = int(spec.get("duration_sec", 0)) & 0xFFFFFFFF
    if tlv_type == TLV_REQUEST_UNICAST_TRANSMISSION:
        val = struct.pack("!BbI", mt_wire, log_period, duration)
    elif tlv_type == TLV_GRANT_UNICAST_TRANSMISSION:
        val = struct.pack(
            "!BbIBB",
            mt_wire,
            log_period,
            duration,
            int(spec.get("tlv_reserved", 0)) & 0xFF,
            int(spec.get("tlv_flags", 0)) & 0xFF,
        )
    elif tlv_type in (TLV_CANCEL_UNICAST_TRANSMISSION, TLV_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION):
        val = struct.pack("!BB", mt_wire, 0)
    else:
        raise ValueError(f"unsupported tlv_type 0x{tlv_type:04x} for signaling builder")
    tlv = struct.pack("!HH", tlv_type, len(val)) + val

    body = target_clock_identity + struct.pack("!H", target_port_id) + tlv
    message_length = 34 + len(body)
    hdr = struct.pack("!BBHBBHq", b0, b1, message_length, domain_number, minor_sdo_id, flags, correction_raw)
    hdr += struct.pack("!I", message_type_specific)
    hdr += clock_identity
    hdr += struct.pack("!HHBb", source_port_id, sequence_id, control_field, log_message_interval)
    return hdr + body


def _parse_clock_identity_hex(s: str) -> bytes:
    s = s.strip().replace(":", "").replace("-", "").replace("0x", "").replace("0X", "")
    if len(s) != 16 or any(c not in "0123456789abcdefABCDEF" for c in s):
        raise ValueError("clock_identity must be 16 hex digits")
    return bytes.fromhex(s)


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
        control_field=0x05,
        log_message_interval=log_message_interval,
        transport_specific=0,
    )
    return hdr.pack() + body
