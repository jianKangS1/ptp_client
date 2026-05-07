"""PTP message bodies for Sync / Follow_Up / Delay_Req / Delay_Resp (IEEE 1588-2008)."""

from __future__ import annotations

from dataclasses import dataclass

from ptp_client.ptp.constants import MessageType
from ptp_client.ptp.header import PTPHeader, PortIdentity
from ptp_client.ptp.timestamp import PTPTimestamp


@dataclass(frozen=True, slots=True)
class SyncBody:
    origin_timestamp: PTPTimestamp


@dataclass(frozen=True, slots=True)
class FollowUpBody:
    precise_origin_timestamp: PTPTimestamp


@dataclass(frozen=True, slots=True)
class DelayReqBody:
    origin_timestamp: PTPTimestamp


@dataclass(frozen=True, slots=True)
class DelayRespBody:
    receive_timestamp: PTPTimestamp
    requesting_port_identity: PortIdentity


def parse_sync_body(data: bytes, header: PTPHeader) -> SyncBody:
    if len(data) < header.message_length:
        raise ValueError("truncated PTP message")
    body_off = 34
    if header.message_length < body_off + 20:
        raise ValueError("Sync body too short")
    # reserved 10 octets ignored
    origin = PTPTimestamp.unpack10(data, body_off + 10)
    return SyncBody(origin_timestamp=origin)


def parse_follow_up_body(data: bytes, header: PTPHeader) -> FollowUpBody:
    body_off = 34
    if header.message_length < body_off + 10:
        raise ValueError("Follow_Up body too short")
    ts = PTPTimestamp.unpack10(data, body_off)
    return FollowUpBody(precise_origin_timestamp=ts)


def parse_delay_req_body(data: bytes, header: PTPHeader) -> DelayReqBody:
    body_off = 34
    if header.message_length < body_off + 20:
        raise ValueError("Delay_Req body too short")
    origin = PTPTimestamp.unpack10(data, body_off + 10)
    return DelayReqBody(origin_timestamp=origin)


def parse_delay_resp_body(data: bytes, header: PTPHeader) -> DelayRespBody:
    body_off = 34
    if header.message_length < body_off + 20:
        raise ValueError("Delay_Resp body too short")
    recv_ts = PTPTimestamp.unpack10(data, body_off)
    req_id = PortIdentity.unpack(data, body_off + 10)
    return DelayRespBody(receive_timestamp=recv_ts, requesting_port_identity=req_id)


def parse_body_for_message_type(data: bytes, header: PTPHeader):
    try:
        mt = MessageType(header.message_type)
    except ValueError:
        return None
    if mt == MessageType.SYNC:
        return parse_sync_body(data, header)
    if mt == MessageType.FOLLOW_UP:
        return parse_follow_up_body(data, header)
    if mt == MessageType.DELAY_REQ:
        return parse_delay_req_body(data, header)
    if mt == MessageType.DELAY_RESP:
        return parse_delay_resp_body(data, header)
    return None
