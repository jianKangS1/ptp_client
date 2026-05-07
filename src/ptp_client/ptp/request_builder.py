"""Build PTPv2 UDP payloads from plain dicts (CLI / HTTP / tests)."""

from __future__ import annotations

from typing import Any, Mapping

from ptp_client.ptp.constants import MessageType
from ptp_client.ptp.header import PTPHeader, PortIdentity
from ptp_client.ptp.timestamp import PTPTimestamp


def _parse_clock_identity(s: str) -> bytes:
    s = s.strip().replace(":", "").replace("-", "")
    if len(s) != 16 or any(c not in "0123456789abcdefABCDEF" for c in s):
        raise ValueError("clock_identity must be 16 hex digits (8 octets)")
    return bytes.fromhex(s)


def _port_identity(spec: Mapping[str, Any]) -> PortIdentity:
    cid = spec.get("clock_identity")
    if cid is None:
        cid = "0001020304050607"
    if isinstance(cid, (bytes, bytearray)):
        b = bytes(cid)
    else:
        b = _parse_clock_identity(str(cid))
    pn = int(spec.get("port_number", 1))
    return PortIdentity(b, pn)


def _ts_from_spec(key: str, spec: Mapping[str, Any]) -> PTPTimestamp:
    v = spec.get(key)
    if v is None:
        return PTPTimestamp.zero()
    if isinstance(v, Mapping):
        return PTPTimestamp(int(v["seconds"]), int(v.get("nanoseconds", 0)))
    raise TypeError(f"{key} must be object with seconds/nanoseconds")


def build_ptp_udp_payload(spec: Mapping[str, Any]) -> bytes:
    """
    Build a full PTP message (header + body) for UDP unicast/multicast.

    Required:
      message_type: str or int — one of sync, delay_req, follow_up, delay_resp (or MessageType int).

    Common optional:
      version_ptp (default 2), domain_number (0), flags (0), correction_field_ns (0),
      transport_specific (0), sequence_id, log_message_interval (-127 default),
      source: { clock_identity, port_number } or top-level clock_identity / port_number

    Bodies:
      sync: reserved10 implicit zeros; origin_timestamp {seconds, nanoseconds}
      delay_req: same as sync body layout
      follow_up: precise_origin_timestamp
      delay_resp: receive_timestamp, requesting_port_identity {clock_identity, port_number}
    """
    mt_raw = spec["message_type"]
    if isinstance(mt_raw, str):
        mtl = mt_raw.strip().lower()
        msg_type = {
            "sync": MessageType.SYNC,
            "delay_req": MessageType.DELAY_REQ,
            "follow_up": MessageType.FOLLOW_UP,
            "delay_resp": MessageType.DELAY_RESP,
        }.get(mtl)
        if msg_type is None:
            raise ValueError(f"unknown message_type {mt_raw!r}")
    else:
        msg_type = MessageType(int(mt_raw))

    version_ptp = int(spec.get("version_ptp", 2))
    domain_number = int(spec.get("domain_number", 0))
    flags = int(spec.get("flags", 0)) & 0xFFFF
    correction_field_ns = int(spec.get("correction_field_ns", 0))
    transport_specific = int(spec.get("transport_specific", 0)) & 0xF
    sequence_id = int(spec.get("sequence_id", 0)) & 0xFFFF
    log_message_interval = int(spec.get("log_message_interval", -127))
    minor_sdo_id = int(spec.get("minor_sdo_id", 0)) & 0xF

    src_spec = spec.get("source")
    if isinstance(src_spec, Mapping):
        identity = _port_identity(src_spec)
    else:
        identity = _port_identity(spec)

    control_default = {
        MessageType.SYNC: 0x00,
        MessageType.DELAY_REQ: 0x01,
        MessageType.FOLLOW_UP: 0x02,
        MessageType.DELAY_RESP: 0x03,
    }.get(msg_type, 0)
    control_field = int(spec.get("control_field", control_default)) & 0xFF

    body = b""
    if msg_type == MessageType.SYNC or msg_type == MessageType.DELAY_REQ:
        origin = _ts_from_spec("origin_timestamp", spec)
        body = bytes(10) + origin.pack10()
    elif msg_type == MessageType.FOLLOW_UP:
        ts = _ts_from_spec("precise_origin_timestamp", spec)
        body = ts.pack10()
    elif msg_type == MessageType.DELAY_RESP:
        recv_ts = _ts_from_spec("receive_timestamp", spec)
        req = spec.get("requesting_port_identity")
        if not isinstance(req, Mapping):
            raise ValueError("delay_resp requires requesting_port_identity {clock_identity, port_number}")
        req_id = _port_identity(req)
        body = recv_ts.pack10() + req_id.pack()
    else:
        raise ValueError(f"building message_type {msg_type} not implemented in request_builder")

    message_length = 34 + len(body)
    hdr = PTPHeader(
        message_type=int(msg_type),
        version_ptp=version_ptp,
        message_length=message_length,
        domain_number=domain_number,
        minor_sdo_id=minor_sdo_id,
        flags=flags,
        correction_field_ns=correction_field_ns,
        source_identity=identity,
        sequence_id=sequence_id,
        control_field=control_field,
        log_message_interval=log_message_interval,
        transport_specific=transport_specific,
    )
    return hdr.pack() + body
