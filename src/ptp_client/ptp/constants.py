"""PTPv2 UDP defaults (IEEE 1588 Annex E style)."""

from __future__ import annotations

from enum import IntEnum


EVENT_PORT = 319
GENERAL_PORT = 320
DEFAULT_DOMAIN = 0
# ITU-T G.8275.2 default PTP domain (clause 6.2.1); range {44–63}.
G82752_DEFAULT_DOMAIN = 44


class MessageType(IntEnum):
    """PTP messageType field (lower nibble of first octet with transportSpecific=0)."""

    SYNC = 0x0
    DELAY_REQ = 0x1
    PDELAY_REQ = 0x2
    PDELAY_RESP = 0x3
    FOLLOW_UP = 0x8
    DELAY_RESP = 0x9
    PDELAY_RESP_FOLLOW_UP = 0xA
    ANNOUNCE = 0xB
    SIGNALING = 0xC
    MANAGEMENT = 0xD


# IEEE 1588-2008: two-step flag (bit 9 of messageFlags)
FLAG_TWO_STEP = 1 << 9
# flagField octet 1 (MSB of 16-bit flags in big-endian header): UNICAST flag (IEEE 1588 / linuxptp)
FLAG_UNICAST = 1 << (2 + 8)
