"""Build `NTPPacket` from a plain dict (CLI / HTTP API)."""

from __future__ import annotations

from typing import Any, Mapping

from ptp_client.ntp.packet import NTPPacket, NTPTime, float_to_ntp_short


def _parse_ref_id(s: str) -> bytes:
    s = s.strip()
    if len(s) == 8 and all(c in "0123456789abcdefABCDEF" for c in s):
        return bytes.fromhex(s)
    if len(s) == 4:
        return s.encode("ascii", errors="strict")
    raise ValueError("reference_id must be 4 ASCII chars or 8 hex digits")


def build_ntp_packet(spec: Mapping[str, Any]) -> NTPPacket:
    """
    Keys (all optional except none required — defaults match typical client query):

    leap_indicator, version, mode, stratum, poll, precision (int)
    root_delay_sec, root_dispersion_sec (float | null → 0)
    reference_id_hex (8 hex) or reference_id_ascii (4 chars), or reference_id (same rules as hex/ascii)
    reference_timestamp: {seconds, fraction} NTP epoch
    receive_timestamp, transmit_timestamp: same
    origin: one of:
      - omit + origin_auto_now true (default): NTPTime.from_unix() at call site
      - origin_unix: float
      - origin_ntp: {seconds, fraction}
    """
    leap = int(spec.get("leap_indicator", 0))
    version = int(spec.get("version", 4))
    mode = int(spec.get("mode", 3))
    stratum = int(spec.get("stratum", 0))
    poll = int(spec.get("poll", 0))
    precision = int(spec.get("precision", 0))

    rd = spec.get("root_delay_sec")
    rdp = spec.get("root_dispersion_sec")
    root_delay = float_to_ntp_short(float(rd), signed=True) if rd is not None else 0
    root_dispersion = float_to_ntp_short(float(rdp), signed=False) if rdp is not None else 0

    ref_id_b = b"\x00\x00\x00\x00"
    if spec.get("reference_id") not in (None, ""):
        ref_id_b = _parse_ref_id(str(spec["reference_id"]))
    elif spec.get("reference_id_hex") not in (None, ""):
        ref_id_b = _parse_ref_id(str(spec["reference_id_hex"]))
    elif spec.get("reference_id_ascii") not in (None, ""):
        ref_id_b = _parse_ref_id(str(spec["reference_id_ascii"]))

    def _ntp_time(key: str) -> NTPTime:
        v = spec.get(key)
        if v is None:
            return NTPTime(0, 0)
        if isinstance(v, Mapping):
            return NTPTime(int(v["seconds"]), int(v.get("fraction", 0)) & 0xFFFFFFFF)
        raise TypeError(f"{key} must be object with seconds/fraction")

    ref_ts = _ntp_time("reference_timestamp")
    recv_ts = _ntp_time("receive_timestamp")
    xmit_ts = _ntp_time("transmit_timestamp")

    origin_auto = spec.get("origin_auto_now", True)
    if spec.get("origin_unix") is not None:
        origin = NTPTime.from_unix(float(spec["origin_unix"]))
    elif spec.get("origin_ntp") is not None:
        on = spec["origin_ntp"]
        origin = NTPTime(int(on["seconds"]), int(on.get("fraction", 0)) & 0xFFFFFFFF)
    elif origin_auto:
        origin = NTPTime.from_unix()
    else:
        origin = NTPTime(0, 0)

    return NTPPacket(
        leap_indicator=leap,
        version=version,
        mode=mode,
        stratum=stratum,
        poll=poll,
        precision=precision,
        root_delay=root_delay,
        root_dispersion=root_dispersion,
        reference_id=ref_id_b,
        reference_timestamp=ref_ts,
        origin_timestamp=origin,
        receive_timestamp=recv_ts,
        transmit_timestamp=xmit_ts,
    )
