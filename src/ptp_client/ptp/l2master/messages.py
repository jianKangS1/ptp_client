"""Build/parse master-side PTP messages (Announce / Sync / Follow_Up / Delay_Resp) for L2 transport."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ptp_client.ptp.constants import FLAG_TWO_STEP, FLAG_UNICAST, MessageType
from ptp_client.ptp.header import PTPHeader, PortIdentity
from ptp_client.ptp.timestamp import PTPTimestamp

from ptp_client.ptp.l2master import constants as l2


@dataclass(frozen=True, slots=True)
class ClockQuality:
    """grandmasterClockQuality (4 octets: clockClass + clockAccuracy + offsetScaledLogVariance)."""

    clock_class: int
    clock_accuracy: int
    offset_scaled_log_variance: int

    def __post_init__(self) -> None:
        if not 0 <= self.clock_class <= 255:
            raise ValueError("clockClass must be uint8")
        if not 0 <= self.clock_accuracy <= 255:
            raise ValueError("clockAccuracy must be uint8")
        if not 0 <= self.offset_scaled_log_variance <= 0xFFFF:
            raise ValueError("offsetScaledLogVariance must be uint16")

    def pack(self) -> bytes:
        return struct.pack("!BBH", self.clock_class, self.clock_accuracy, self.offset_scaled_log_variance)

    @classmethod
    def unpack(cls, data: bytes, offset: int = 0) -> "ClockQuality":
        return cls(*struct.unpack_from("!BBH", data, offset))


@dataclass(frozen=True, slots=True)
class AnnounceBody:
    origin_timestamp: PTPTimestamp
    current_utc_offset: int
    grandmaster_priority1: int
    grandmaster_clock_quality: ClockQuality
    grandmaster_priority2: int
    grandmaster_identity: bytes
    steps_removed: int
    time_source: int

    def __post_init__(self) -> None:
        if len(self.grandmaster_identity) != 8:
            raise ValueError("grandmaster_identity must be 8 bytes")
        if not 0 <= self.steps_removed <= 0xFFFF:
            raise ValueError("steps_removed must be uint16")

    def pack(self) -> bytes:
        return (
            self.origin_timestamp.pack10()
            + struct.pack("!HBB", self.current_utc_offset & 0xFFFF, 0, self.grandmaster_priority1)
            + self.grandmaster_clock_quality.pack()
            + struct.pack("!B", self.grandmaster_priority2)
            + self.grandmaster_identity
            + struct.pack("!HB", self.steps_removed, self.time_source)
        )

    @classmethod
    def unpack(cls, data: bytes, offset: int = 0) -> "AnnounceBody":
        if len(data) < offset + l2.ANNOUNCE_BODY_LEN:
            raise ValueError("Announce body too short")
        ts = PTPTimestamp.unpack10(data, offset)
        utc_offset, _reserved, prio1 = struct.unpack_from("!HBB", data, offset + 10)
        quality = ClockQuality.unpack(data, offset + 14)
        prio2 = data[offset + 18]
        gm_id = data[offset + 19 : offset + 27]
        steps, time_source = struct.unpack_from("!HB", data, offset + 27)
        return cls(
            origin_timestamp=ts,
            current_utc_offset=utc_offset,
            grandmaster_priority1=prio1,
            grandmaster_clock_quality=quality,
            grandmaster_priority2=prio2,
            grandmaster_identity=gm_id,
            steps_removed=steps,
            time_source=time_source,
        )


def _header(
    *,
    message_type: MessageType,
    domain_number: int,
    flags: int,
    source: PortIdentity,
    sequence_id: int,
    control_field: int,
    log_message_interval: int,
    transport_specific: int,
    body_len: int,
) -> PTPHeader:
    return PTPHeader(
        message_type=int(message_type),
        version_ptp=2,
        message_length=l2.HEADER_LEN + body_len,
        domain_number=domain_number,
        minor_sdo_id=0,
        flags=flags & 0xFFFF,
        correction_field_ns=0,
        source_identity=source,
        sequence_id=sequence_id & 0xFFFF,
        control_field=control_field,
        log_message_interval=log_message_interval,
        transport_specific=transport_specific,
    )


def build_announce(
    *,
    source: PortIdentity,
    domain_number: int,
    body: AnnounceBody,
    sequence_id: int,
    log_announce_interval: int,
    flags: int = l2.ANNOUNCE_DEFAULT_FLAGS,
    transport_specific: int = 0,
) -> bytes:
    hdr = _header(
        message_type=MessageType.ANNOUNCE,
        domain_number=domain_number,
        flags=flags,
        source=source,
        sequence_id=sequence_id,
        control_field=l2.CONTROL_ANNOUNCE,
        log_message_interval=log_announce_interval,
        transport_specific=transport_specific,
        body_len=l2.ANNOUNCE_BODY_LEN,
    )
    return hdr.pack() + body.pack()


def build_sync(
    *,
    source: PortIdentity,
    domain_number: int,
    origin_timestamp: PTPTimestamp,
    sequence_id: int,
    log_sync_interval: int,
    two_step: bool,
    transport_specific: int = 0,
) -> bytes:
    flags = FLAG_TWO_STEP if two_step else 0
    hdr = _header(
        message_type=MessageType.SYNC,
        domain_number=domain_number,
        flags=flags,
        source=source,
        sequence_id=sequence_id,
        control_field=l2.CONTROL_SYNC,
        log_message_interval=log_sync_interval,
        transport_specific=transport_specific,
        body_len=l2.SYNC_BODY_LEN,
    )
    return hdr.pack() + origin_timestamp.pack10()


def build_follow_up(
    *,
    source: PortIdentity,
    domain_number: int,
    precise_origin_timestamp: PTPTimestamp,
    sequence_id: int,
    log_sync_interval: int,
    transport_specific: int = 0,
) -> bytes:
    hdr = _header(
        message_type=MessageType.FOLLOW_UP,
        domain_number=domain_number,
        flags=FLAG_TWO_STEP,
        source=source,
        sequence_id=sequence_id,
        control_field=l2.CONTROL_FOLLOW_UP,
        log_message_interval=log_sync_interval,
        transport_specific=transport_specific,
        body_len=l2.FOLLOW_UP_BODY_LEN,
    )
    return hdr.pack() + precise_origin_timestamp.pack10()


@dataclass(frozen=True, slots=True)
class DelayReq:
    """Parsed Delay_Req: common header + originTimestamp (diagnostics only)."""

    header: PTPHeader
    origin_timestamp: PTPTimestamp


def parse_delay_req(data: bytes) -> DelayReq:
    """Parse a full PTP Delay_Req payload (34 B header + 10 B body)."""
    if len(data) < l2.HEADER_LEN:
        raise ValueError("PTP message shorter than common header")
    hdr = PTPHeader.unpack(data, 0)
    if hdr.message_type != int(MessageType.DELAY_REQ):
        raise ValueError(f"not a Delay_Req (messageType={hdr.message_type:#x})")
    if len(data) < l2.DELAY_REQ_MSG_LEN:
        raise ValueError("Delay_Req truncated")
    origin = PTPTimestamp.unpack10(data, l2.HEADER_LEN)
    return DelayReq(header=hdr, origin_timestamp=origin)


def build_delay_resp(
    *,
    source: PortIdentity,
    domain_number: int,
    receive_timestamp: PTPTimestamp,
    requesting_port_identity: PortIdentity,
    sequence_id: int,
    unicast: bool,
    transport_specific: int = 0,
) -> bytes:
    """Build a Delay_Resp (design doc §4.5): t2 + echoed requestingPortIdentity."""
    flags = FLAG_UNICAST if unicast else 0
    hdr = _header(
        message_type=MessageType.DELAY_RESP,
        domain_number=domain_number,
        flags=flags,
        source=source,
        sequence_id=sequence_id,
        control_field=l2.CONTROL_DELAY_RESP,
        log_message_interval=l2.LOG_MSG_INTERVAL_NA,
        transport_specific=transport_specific,
        body_len=l2.DELAY_RESP_BODY_LEN,
    )
    body = receive_timestamp.pack10() + requesting_port_identity.pack()
    return hdr.pack() + body

