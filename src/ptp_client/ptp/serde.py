"""Serialize PTP messages for JSON / UI."""

from __future__ import annotations

from ptp_client.ptp.constants import MessageType
from ptp_client.ptp.header import PTPHeader, PortIdentity
from ptp_client.ptp.packet import (
    DelayReqBody,
    DelayRespBody,
    FollowUpBody,
    SyncBody,
    parse_body_for_message_type,
)
from ptp_client.ptp.timestamp import PTPTimestamp


def _port_id_dict(p: PortIdentity) -> dict:
    return {"clock_identity": p.clock_identity.hex(), "port_number": p.port_number}


def _ts_dict(t: PTPTimestamp) -> dict:
    return {"seconds": t.seconds, "nanoseconds": t.nanoseconds}


def ptp_timestamp_to_posix_seconds(ts: PTPTimestamp) -> float:
    """IEEE 1588 seconds/nanoseconds relative to the PTP epoch (1970-01-01 00:00:00 UTC)."""
    return ts.seconds + ts.nanoseconds * 1e-9


def _message_type_name(v: int) -> str:
    try:
        return MessageType(v).name
    except ValueError:
        return f"MT_{v}"


def message_summary(udp_payload: bytes) -> dict:
    """Parse one UDP payload and return a JSON-friendly summary (best-effort body decode)."""
    hdr = PTPHeader.unpack(udp_payload, 0)
    body = parse_body_for_message_type(udp_payload, hdr)
    out: dict = {
        "message_type": int(hdr.message_type),
        "message_type_name": _message_type_name(hdr.message_type),
        "version_ptp": hdr.version_ptp,
        "message_length": hdr.message_length,
        "domain_number": hdr.domain_number,
        "flags": hdr.flags,
        "correction_field_ns": hdr.correction_field_ns,
        "source_identity": _port_id_dict(hdr.source_identity),
        "sequence_id": hdr.sequence_id,
        "control_field": hdr.control_field,
        "log_message_interval": hdr.log_message_interval,
        "transport_specific": hdr.transport_specific,
        "raw_hex": udp_payload.hex(),
        "raw_length": len(udp_payload),
    }
    if body is None:
        out["body"] = None
        return out
    if isinstance(body, SyncBody):
        out["body"] = {"origin_timestamp": _ts_dict(body.origin_timestamp)}
    elif isinstance(body, FollowUpBody):
        out["body"] = {"precise_origin_timestamp": _ts_dict(body.precise_origin_timestamp)}
    elif isinstance(body, DelayReqBody):
        out["body"] = {"origin_timestamp": _ts_dict(body.origin_timestamp)}
    elif isinstance(body, DelayRespBody):
        out["body"] = {
            "receive_timestamp": _ts_dict(body.receive_timestamp),
            "requesting_port_identity": _port_id_dict(body.requesting_port_identity),
        }
    else:
        out["body"] = repr(body)
    return out
