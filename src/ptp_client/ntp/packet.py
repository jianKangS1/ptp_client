"""NTPv4 packet layout (RFC 5905): encode, decode, and field-level customization."""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Self

# Seconds between NTP epoch (1900-01-01 00:00:00 UTC) and Unix epoch.
_NTP_UNIX_OFFSET = 2208988800


class NTPLeapIndicator(IntEnum):
    """Leap indicator (LI), 2-bit field in first octet."""

    NO_WARNING = 0
    LAST_MINUTE_61 = 1
    LAST_MINUTE_59 = 2
    ALARM = 3


class NTPMode(IntEnum):
    """NTP association mode (3-bit)."""

    RESERVED = 0
    SYMMETRIC_ACTIVE = 1
    SYMMETRIC_PASSIVE = 2
    CLIENT = 3
    SERVER = 4
    BROADCAST = 5
    CONTROL = 6
    PRIVATE = 7


class NTPVersion(IntEnum):
    """Protocol version (3-bit)."""

    V3 = 3
    V4 = 4


@dataclass(frozen=True, slots=True)
class NTPTime:
    """NTP 64-bit timestamp: 32-bit seconds + 32-bit fraction since 1900-01-01 00:00 UTC."""

    seconds: int
    fraction: int

    @classmethod
    def from_unix(cls, ts: float | None = None) -> Self:
        """Build from Unix time (seconds); default: current time."""
        if ts is None:
            ts = time.time()
        ntp = ts + _NTP_UNIX_OFFSET
        sec = int(ntp)
        frac = int((ntp - sec) * (2**32)) & 0xFFFFFFFF
        return cls(sec, frac)

    def to_unix(self) -> float:
        return self.seconds - _NTP_UNIX_OFFSET + self.fraction / (2**32)

    def pack(self) -> bytes:
        return struct.pack("!II", self.seconds & 0xFFFFFFFF, self.fraction)

    @classmethod
    def unpack(cls, data: bytes, offset: int = 0) -> Self:
        sec, frac = struct.unpack_from("!II", data, offset)
        return cls(sec, frac)


def _pack_li_vn_mode(li: int, vn: int, mode: int) -> int:
    return ((li & 0x3) << 6) | ((vn & 0x7) << 3) | (mode & 0x7)


def _unpack_li_vn_mode(b: int) -> tuple[int, int, int]:
    return (b >> 6) & 0x3, (b >> 3) & 0x7, b & 0x7


def float_to_ntp_short(value: float, *, signed: bool) -> int:
    """Convert seconds to NTP short format (16.16 fixed point in 32 bits)."""
    if signed:
        raw = int(round(value * (2**16)))
        if raw < -(2**31) or raw >= 2**31:
            raise ValueError("root_delay out of range for signed NTP short")
        return raw & 0xFFFFFFFF
    raw_u = int(round(value * (2**16)))
    if raw_u < 0 or raw_u > 0xFFFFFFFF:
        raise ValueError("root_dispersion out of range for unsigned NTP short")
    return raw_u


def ntp_short_to_float(word: int, *, signed: bool) -> float:
    if signed:
        v = word if word < 2**31 else word - 2**32
        return v / (2**16)
    return (word & 0xFFFFFFFF) / (2**16)


@dataclass(slots=True)
class NTPPacket:
    """
    Full 48-byte NTPv4 packet. All fields can be set before `pack()` for custom probes.

    On a typical client request, receive_timestamp and transmit_timestamp are zero;
    origin_timestamp is often set to send time. The server fills t2/t3.
    """

    leap_indicator: int = int(NTPLeapIndicator.NO_WARNING)
    version: int = int(NTPVersion.V4)
    mode: int = int(NTPMode.CLIENT)
    stratum: int = 0
    poll: int = 0
    precision: int = 0
    root_delay: int = 0
    root_dispersion: int = 0
    reference_id: bytes = b"\x00\x00\x00\x00"
    reference_timestamp: NTPTime = field(default_factory=lambda: NTPTime(0, 0))
    origin_timestamp: NTPTime = field(default_factory=lambda: NTPTime(0, 0))
    receive_timestamp: NTPTime = field(default_factory=lambda: NTPTime(0, 0))
    transmit_timestamp: NTPTime = field(default_factory=lambda: NTPTime(0, 0))

    @classmethod
    def client_request(
        cls,
        *,
        version: int = int(NTPVersion.V4),
        mode: int = int(NTPMode.CLIENT),
        origin: NTPTime | None = None,
        leap_indicator: int | None = None,
        stratum: int | None = None,
        poll: int | None = None,
        precision: int | None = None,
        root_delay: int | None = None,
        root_dispersion: int | None = None,
        reference_id: bytes | None = None,
        reference_timestamp: NTPTime | None = None,
        receive_timestamp: NTPTime | None = None,
        transmit_timestamp: NTPTime | None = None,
    ) -> Self:
        """Minimal client query; origin defaults to 'now' if omitted."""
        o = origin if origin is not None else NTPTime.from_unix()
        pkt = cls(version=version, mode=mode, origin_timestamp=o)
        if leap_indicator is not None:
            pkt.leap_indicator = leap_indicator
        if stratum is not None:
            pkt.stratum = stratum
        if poll is not None:
            pkt.poll = poll
        if precision is not None:
            pkt.precision = precision
        if root_delay is not None:
            pkt.root_delay = root_delay
        if root_dispersion is not None:
            pkt.root_dispersion = root_dispersion
        if reference_id is not None:
            pkt.reference_id = reference_id
        if reference_timestamp is not None:
            pkt.reference_timestamp = reference_timestamp
        if receive_timestamp is not None:
            pkt.receive_timestamp = receive_timestamp
        if transmit_timestamp is not None:
            pkt.transmit_timestamp = transmit_timestamp
        return pkt

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        if len(data) < 48:
            raise ValueError("NTP packet must be at least 48 bytes")
        li_vn_mode, stratum, poll, precision = struct.unpack_from("!BBBb", data, 0)
        li, vn, mode = _unpack_li_vn_mode(li_vn_mode)
        root_delay, root_dispersion, ref_id = struct.unpack_from("!II4s", data, 4)
        ref_ts = NTPTime.unpack(data, 16)
        ori_ts = NTPTime.unpack(data, 24)
        recv_ts = NTPTime.unpack(data, 32)
        xmit_ts = NTPTime.unpack(data, 40)
        return cls(
            leap_indicator=li,
            version=vn,
            mode=mode,
            stratum=stratum,
            poll=poll,
            precision=precision,
            root_delay=root_delay,
            root_dispersion=root_dispersion,
            reference_id=ref_id,
            reference_timestamp=ref_ts,
            origin_timestamp=ori_ts,
            receive_timestamp=recv_ts,
            transmit_timestamp=xmit_ts,
        )

    def pack(self) -> bytes:
        if len(self.reference_id) != 4:
            raise ValueError("reference_id must be 4 bytes")
        li_vn_mode = _pack_li_vn_mode(self.leap_indicator, self.version, self.mode)
        header = struct.pack(
            "!BBBbII4s",
            li_vn_mode,
            self.stratum & 0xFF,
            self.poll & 0xFF,
            self.precision,
            self.root_delay & 0xFFFFFFFF,
            self.root_dispersion & 0xFFFFFFFF,
            self.reference_id,
        )
        return (
            header
            + self.reference_timestamp.pack()
            + self.origin_timestamp.pack()
            + self.receive_timestamp.pack()
            + self.transmit_timestamp.pack()
        )

    def reference_id_as_text(self) -> str:
        """If ref id is printable ASCII, return as string; else hex."""
        if all(32 <= b < 127 for b in self.reference_id):
            return self.reference_id.decode("ascii", errors="replace")
        return self.reference_id.hex()
