"""Delay_Req wire-format spec and client-side send options (config / CLI)."""

from __future__ import annotations

from argparse import Namespace
from typing import Any, Mapping

from ptp_client.ptp.constants import FLAG_UNICAST

# Client-only keys in delayRequest JSON; never written into PTP Delay_Req header/body.
_CLIENT_ONLY_KEYS = frozenset(
    {
        "requestIntervalSec",
        "request_interval_sec",
        "logPeriod",
        "logMessageInterval",
        "log_message_interval",
    }
)


def _clock_hex(clock_identity: str | bytes) -> str:
    if isinstance(clock_identity, (bytes, bytearray)):
        return bytes(clock_identity).hex()
    return str(clock_identity).strip().replace(":", "").replace("-", "")


def _pick_int(mapping: Mapping[str, Any], *keys: str, default: int | None = None) -> int | None:
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return int(mapping[key])
    return default


def _pick_origin(mapping: Mapping[str, Any]) -> dict[str, int] | None:
    origin = mapping.get("originTimestamp")
    if origin is None:
        origin = mapping.get("origin_timestamp")
    if not isinstance(origin, Mapping):
        return None
    return {
        "seconds": int(origin["seconds"]),
        "nanoseconds": int(origin.get("nanoseconds", 0)),
    }


def parse_delay_request_interval_sec(mapping: Mapping[str, Any] | None) -> float | None:
    """
    Client-side Delay_Req send interval (seconds). Not encoded in the PTP packet.

    Returns ``None`` when unset or ``<= 0`` (single exchange).
    """
    if not mapping:
        return None
    raw = mapping.get("requestIntervalSec")
    if raw is None:
        raw = mapping.get("request_interval_sec")
    if raw is None:
        return None
    interval = float(raw)
    return interval if interval > 0.0 else None


def delay_request_interval_from_namespace(ns: Namespace) -> float | None:
    val = getattr(ns, "delay_req_interval", None)
    if val is None:
        return None
    interval = float(val)
    return interval if interval > 0.0 else None


def build_delay_request_spec(
    overrides: Mapping[str, Any] | None = None,
    *,
    domain_number: int,
    clock_identity: str | bytes,
    port_number: int,
    default_flags: int = FLAG_UNICAST,
) -> dict[str, Any]:
    """
    Build a ``build_ptp_udp_payload`` dict for IEEE 1588 Delay_Req.

    ``overrides`` may use JSON config keys (camelCase) or internal snake_case.
    Client-only keys (e.g. ``requestIntervalSec``) are ignored for wire format.
    ``sequence_id`` is omitted here; :meth:`PTPAcrUnicastClient.exchange_delay` assigns it.
    """
    o: dict[str, Any] = {
        k: v for k, v in dict(overrides or {}).items() if k not in _CLIENT_ONLY_KEYS
    }

    cid = o.get("clockIdentity")
    if cid is None:
        cid = o.get("clock_identity")
    if cid is None:
        cid = clock_identity

    pn = _pick_int(o, "portNumber", "port_number", default=port_number)
    flags = _pick_int(o, "flags", default=default_flags)
    correction = _pick_int(o, "correctionFieldNs", "correction_field_ns", default=0)

    spec: dict[str, Any] = {
        "message_type": "delay_req",
        "domain_number": int(domain_number) & 0xFF,
        "clock_identity": _clock_hex(cid),
        "port_number": int(pn if pn is not None else port_number),
        "flags": int(flags if flags is not None else default_flags) & 0xFFFF,
        "correction_field_ns": int(correction if correction is not None else 0),
        "log_message_interval": -127,
    }

    origin = _pick_origin(o)
    if origin is not None:
        spec["origin_timestamp"] = origin

    return spec


def delay_request_spec_from_namespace(
    ns: Namespace,
    *,
    domain_number: int,
    clock_identity: str | bytes,
    port_number: int,
    default_flags: int = FLAG_UNICAST,
) -> dict[str, Any]:
    """Merge ``--delay-req-*`` CLI overrides with session defaults."""
    overrides: dict[str, Any] = {}

    dr_clock = getattr(ns, "delay_req_clock_identity", None)
    if dr_clock is not None:
        overrides["clock_identity"] = dr_clock.hex() if isinstance(dr_clock, bytes) else dr_clock

    if getattr(ns, "delay_req_port_number", None) is not None:
        overrides["port_number"] = ns.delay_req_port_number
    if getattr(ns, "delay_req_flags", None) is not None:
        overrides["flags"] = ns.delay_req_flags
    if getattr(ns, "delay_req_correction_ns", None) is not None:
        overrides["correction_field_ns"] = ns.delay_req_correction_ns

    origin: dict[str, int] = {}
    if getattr(ns, "delay_req_origin_sec", None) is not None:
        origin["seconds"] = int(ns.delay_req_origin_sec)
    if getattr(ns, "delay_req_origin_ns", None) is not None:
        origin["nanoseconds"] = int(ns.delay_req_origin_ns)
    if origin:
        overrides["origin_timestamp"] = origin

    # delay/estimate modes: legacy --flags / --correction-ns apply when no --delay-req-* set
    if "flags" not in overrides and getattr(ns, "flags", None) is not None:
        overrides["flags"] = ns.flags
    if "correction_field_ns" not in overrides and getattr(ns, "correction_ns", None) is not None:
        overrides["correction_field_ns"] = ns.correction_ns
    if "clock_identity" not in overrides and getattr(ns, "clock_identity", None) is not None:
        cid = ns.clock_identity
        overrides["clock_identity"] = cid.hex() if isinstance(cid, bytes) else cid
    if "port_number" not in overrides and getattr(ns, "port_number", None) is not None:
        overrides["port_number"] = ns.port_number

    return build_delay_request_spec(
        overrides,
        domain_number=domain_number,
        clock_identity=clock_identity,
        port_number=port_number,
        default_flags=default_flags,
    )
