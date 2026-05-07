"""PTP common message header (34 octets, IEEE 1588-2008)."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Self

from ptp_client.ptp.constants import MessageType


@dataclass(slots=True)
class PortIdentity:
    clock_identity: bytes
    port_number: int

    def __post_init__(self) -> None:
        if len(self.clock_identity) != 8:
            raise ValueError("clock_identity must be 8 bytes")
        if not (0 <= self.port_number < 65536):
            raise ValueError("port_number must be uint16")

    def pack(self) -> bytes:
        return self.clock_identity + struct.pack("!H", self.port_number)

    @classmethod
    def unpack(cls, data: bytes, offset: int = 0) -> Self:
        if len(data) < offset + 10:
            raise ValueError("need 10 bytes for PortIdentity")
        return cls(data[offset : offset + 8], struct.unpack_from("!H", data, offset + 8)[0])


@dataclass(slots=True)
class PTPHeader:
    """
    PTPv2 common header.

    correctionField is the on-wire int64 (scaled nanoseconds per IEEE 1588: integer ns of delay
    correction when interpreted as signed ns in many stacks; linuxptp uses scaled format — callers
    may set raw wire value for custom probes).
    """

    message_type: int
    version_ptp: int
    message_length: int
    domain_number: int
    minor_sdo_id: int
    flags: int
    correction_field_ns: int
    source_identity: PortIdentity
    sequence_id: int
    control_field: int
    log_message_interval: int
    transport_specific: int = 0

    @property
    def message_type_enum(self) -> MessageType:
        return MessageType(self.message_type)

    @classmethod
    def unpack(cls, data: bytes, offset: int = 0) -> Self:
        if len(data) < offset + 34:
            raise ValueError("PTP header requires 34 bytes")
        b0, b1 = struct.unpack_from("!BB", data, offset)
        transport_specific = (b0 >> 4) & 0xF
        message_type = b0 & 0xF
        minor_sdo_id = (b1 >> 4) & 0xF
        version_ptp = b1 & 0xF
        message_length, domain_number, _reserved1, flags = struct.unpack_from("!HBBH", data, offset + 2)
        (correction_field_ns,) = struct.unpack_from("!q", data, offset + 8)
        src = PortIdentity.unpack(data, offset + 20)
        sequence_id, control_field, log_message_interval = struct.unpack_from("!Hbb", data, offset + 30)
        return cls(
            message_type=message_type,
            version_ptp=version_ptp,
            message_length=message_length,
            domain_number=domain_number,
            minor_sdo_id=minor_sdo_id,
            flags=flags & 0xFFFF,
            correction_field_ns=correction_field_ns,
            source_identity=src,
            sequence_id=sequence_id & 0xFFFF,
            control_field=control_field & 0xFF,
            log_message_interval=log_message_interval,
            transport_specific=transport_specific,
        )

    def pack(self) -> bytes:
        b0 = ((self.transport_specific & 0xF) << 4) | (self.message_type & 0xF)
        b1 = ((self.minor_sdo_id & 0xF) << 4) | (self.version_ptp & 0xF)
        hdr = struct.pack(
            "!BBHBBHq",
            b0,
            b1,
            self.message_length & 0xFFFF,
            self.domain_number & 0xFF,
            0,
            self.flags & 0xFFFF,
            int(self.correction_field_ns),
        )
        hdr += b"\x00\x00\x00\x00"
        hdr += self.source_identity.pack()
        hdr += struct.pack(
            "!Hbb",
            self.sequence_id & 0xFFFF,
            self.control_field if self.control_field < 128 else self.control_field - 256,
            self.log_message_interval
            if self.log_message_interval < 128
            else self.log_message_interval - 256,
        )
        return hdr
