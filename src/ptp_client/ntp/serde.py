"""Serialize NTP packets for JSON / UI."""

from __future__ import annotations

from ptp_client.ntp.packet import NTPPacket, ntp_short_to_float


def packet_summary(p: NTPPacket) -> dict:
    raw = p.pack()
    return {
        "leap_indicator": p.leap_indicator,
        "version": p.version,
        "mode": p.mode,
        "stratum": p.stratum,
        "poll": p.poll,
        "precision": p.precision,
        "root_delay_seconds": ntp_short_to_float(p.root_delay, signed=True),
        "root_dispersion_seconds": ntp_short_to_float(p.root_dispersion, signed=False),
        "reference_id_hex": p.reference_id.hex(),
        "reference_id_display": p.reference_id_as_text(),
        "reference_timestamp": {
            "seconds": p.reference_timestamp.seconds,
            "fraction": p.reference_timestamp.fraction,
        },
        "origin_timestamp": {
            "seconds": p.origin_timestamp.seconds,
            "fraction": p.origin_timestamp.fraction,
            "unix_approx": p.origin_timestamp.to_unix(),
        },
        "receive_timestamp": {
            "seconds": p.receive_timestamp.seconds,
            "fraction": p.receive_timestamp.fraction,
            "unix_approx": p.receive_timestamp.to_unix(),
        },
        "transmit_timestamp": {
            "seconds": p.transmit_timestamp.seconds,
            "fraction": p.transmit_timestamp.fraction,
            "unix_approx": p.transmit_timestamp.to_unix(),
        },
        "raw_hex": raw.hex(),
        "raw_length": len(raw),
    }
