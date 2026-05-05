import struct

import pytest

from ptp_client.ntp.packet import (
    NTPMode,
    NTPPacket,
    NTPTime,
    NTPVersion,
    float_to_ntp_short,
    ntp_short_to_float,
)


def test_ntp_time_unix_roundtrip() -> None:
    t = 1_700_000_000.125
    n = NTPTime.from_unix(t)
    assert abs(n.to_unix() - t) < 1e-6


def test_packet_pack_unpack_roundtrip() -> None:
    p = NTPPacket(
        leap_indicator=0,
        version=int(NTPVersion.V4),
        mode=int(NTPMode.CLIENT),
        stratum=0,
        poll=6,
        precision=-18,
        root_delay=float_to_ntp_short(0.001, signed=True),
        root_dispersion=float_to_ntp_short(0.002, signed=False),
        reference_id=b"GPS\x00",
        reference_timestamp=NTPTime(3_894_251_234, 0x8000_0000),
        origin_timestamp=NTPTime.from_unix(1_700_000_000.0),
        receive_timestamp=NTPTime(0, 0),
        transmit_timestamp=NTPTime(0, 0),
    )
    b = p.pack()
    assert len(b) == 48
    q = NTPPacket.from_bytes(b)
    assert q.leap_indicator == p.leap_indicator
    assert q.version == p.version
    assert q.mode == p.mode
    assert q.stratum == p.stratum
    assert q.poll == p.poll
    assert q.precision == p.precision
    assert q.root_delay == p.root_delay
    assert q.root_dispersion == p.root_dispersion
    assert q.reference_id == p.reference_id
    assert q.reference_timestamp.seconds == p.reference_timestamp.seconds
    assert q.origin_timestamp.seconds == p.origin_timestamp.seconds


def test_ntp_short_float() -> None:
    x = 0.015625
    w = float_to_ntp_short(x, signed=True)
    assert abs(ntp_short_to_float(w, signed=True) - x) < 1e-9


def test_invalid_packet_length() -> None:
    with pytest.raises(ValueError):
        NTPPacket.from_bytes(b"\x00" * 40)
