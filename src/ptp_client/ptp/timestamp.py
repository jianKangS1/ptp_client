"""PTP Timestamp type (48-bit seconds + 32-bit nanoseconds)."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Self


@dataclass(frozen=True, slots=True)
class PTPTimestamp:
    """IEEE 1588 Timestamp: 48-bit seconds field + 32-bit nanoseconds field."""

    seconds: int
    nanoseconds: int

    def __post_init__(self) -> None:
        if self.seconds < 0 or self.seconds >= 2**48:
            raise ValueError("seconds must be in [0, 2**48)")
        if self.nanoseconds >= 10**9 or self.nanoseconds < 0:
            raise ValueError("nanoseconds must be in [0, 1e9)")

    @classmethod
    def zero(cls) -> Self:
        return cls(0, 0)

    def pack10(self) -> bytes:
        """10 octets on the wire: uint48 BE + uint32 BE."""
        sec = self.seconds & ((1 << 48) - 1)
        b6 = sec.to_bytes(6, "big", signed=False)
        b4 = struct.pack("!I", self.nanoseconds & 0xFFFFFFFF)
        return b6 + b4

    @classmethod
    def unpack10(cls, data: bytes, offset: int = 0) -> Self:
        if len(data) < offset + 10:
            raise ValueError("need 10 bytes for PTP Timestamp")
        sec = int.from_bytes(data[offset : offset + 6], "big", signed=False)
        (ns,) = struct.unpack_from("!I", data, offset + 6)
        return cls(sec, ns)
