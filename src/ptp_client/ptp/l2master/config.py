"""MasterConfig dataclass, JSON(C) loading and validation (design doc §6/§7)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Literal, Optional

from ptp_client.ptp.l2master import constants as l2

Profile = Literal["g82751", "1588v2"]

# Per-profile defaults (design doc §4.8).
_PROFILE_DEFAULTS: dict[str, dict] = {
    "g82751": {
        "domain_number": 43,
        "log_announce_interval": -3,
        "log_sync_interval": -4,
        "dst_mac": l2.G82751_PTP_MAC,
    },
    "1588v2": {
        "domain_number": 0,
        "log_announce_interval": 0,
        "log_sync_interval": 0,
        "dst_mac": l2.IEEE1588_PTP_MAC,
    },
}

# Validation ranges (design doc §7).
_RANGES: dict[str, dict[str, tuple[int, int]]] = {
    "g82751": {
        "domain_number": (24, 43),
        "log_announce_interval": (-3, 0),
        "log_sync_interval": (-7, -3),
    },
    "1588v2": {
        "domain_number": (0, 127),
        "log_announce_interval": (-3, 1),
        "log_sync_interval": (-7, 1),
    },
}


@dataclass
class MasterConfig:
    interface: str = ""
    profile: Profile = "g82751"
    domain_number: int = 43
    clock_identity: Optional[bytes] = None  # None → derived from NIC MAC
    port_number: int = 1
    priority1: int = 128
    priority2: int = 128
    clock_class: int = 6
    clock_accuracy: int = 0x31
    offset_scaled_log_variance: int = 0xFFFF
    time_source: int = l2.TIME_SOURCE_INTERNAL_OSCILLATOR
    current_utc_offset: int = 0
    log_announce_interval: int = -3
    log_sync_interval: int = -4
    two_step: bool = True
    follow_up_gap_ms: float = 1.0
    transport_specific: int = 0
    vlan_id: Optional[int] = None
    vlan_pcp: int = 6
    dst_mac: bytes = l2.G82751_PTP_MAC
    announce_receipt_timeout: int = 3
    delay_resp_unicast: bool = False
    max_slaves: int = 64
    delay_resp_rate_limit: int = 256

    def validate(self) -> None:
        if not self.interface:
            raise ValueError("interface is required")
        if self.profile not in _RANGES:
            raise ValueError(f"unknown profile {self.profile!r} (use g82751|1588v2)")
        ranges = _RANGES[self.profile]
        for name, (lo, hi) in ranges.items():
            v = getattr(self, name)
            if not lo <= v <= hi:
                raise ValueError(f"{name}={v} out of range [{lo}, {hi}] for profile {self.profile}")
        if self.clock_identity is not None:
            if len(self.clock_identity) != 8:
                raise ValueError("clock_identity must be 8 octets")
            if self.clock_identity == b"\xff" * 8:
                raise ValueError("clock_identity must not be all-FF")
        if len(self.dst_mac) != 6:
            raise ValueError("dst_mac must be 6 octets")
        if self.vlan_id is not None and not 0 <= self.vlan_id <= 0xFFF:
            raise ValueError("vlan_id must be 0..4095")
        if not 0 <= self.vlan_pcp <= 7:
            raise ValueError("vlan_pcp must be 0..7")
        if not 0 <= self.transport_specific <= 0xF:
            raise ValueError("transport_specific must be 0..15")
        if not 0 <= self.port_number <= 0xFFFF:
            raise ValueError("port_number must be uint16")
        if self.follow_up_gap_ms < 0:
            raise ValueError("follow_up_gap_ms must be >= 0")
        if self.max_slaves < 1:
            raise ValueError("max_slaves must be >= 1")
        if self.delay_resp_rate_limit < 0:
            raise ValueError("delay_resp_rate_limit must be >= 0 (0 = unlimited)")

    def session_timeout_sec(self) -> float:
        """Slave session ageing window (design doc §5.5)."""
        return self.announce_receipt_timeout * (2.0**self.log_announce_interval) * 2

    def apply_profile_defaults(self, overrides: set[str]) -> None:
        """Fill fields the user did not explicitly set with the profile defaults."""
        d = _PROFILE_DEFAULTS[self.profile]
        for name, value in d.items():
            if name not in overrides:
                setattr(self, name, value)


def _strip_jsonc_comments(text: str) -> str:
    # Remove // line comments and /* */ block comments, preserving strings.
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def _strip_trailing_commas(text: str) -> str:
    return _TRAILING_COMMA.sub(r"\1", text)


def _parse_mac(s: str) -> bytes:
    b = bytes.fromhex(re.sub(r"[:\- ]", "", s))
    if len(b) != 6:
        raise ValueError(f"MAC must be 6 octets, got {s!r}")
    return b


def _parse_clock_identity(s: str) -> bytes:
    b = bytes.fromhex(re.sub(r"[:\- ]", "", s))
    if len(b) != 8:
        raise ValueError("clock_identity must be 16 hex digits (8 octets)")
    return b


# JSON keys (camelCase) → dataclass field names.
_KEY_MAP = {
    "interface": "interface",
    "profile": "profile",
    "domainNumber": "domain_number",
    "clockIdentity": "clock_identity",
    "portNumber": "port_number",
    "priority1": "priority1",
    "priority2": "priority2",
    "clockClass": "clock_class",
    "clockAccuracy": "clock_accuracy",
    "offsetScaledLogVariance": "offset_scaled_log_variance",
    "timeSource": "time_source",
    "currentUtcOffset": "current_utc_offset",
    "logAnnounceInterval": "log_announce_interval",
    "logSyncInterval": "log_sync_interval",
    "twoStep": "two_step",
    "followUpGapMs": "follow_up_gap_ms",
    "transportSpecific": "transport_specific",
    "vlanId": "vlan_id",
    "vlanPcp": "vlan_pcp",
    "dstMac": "dst_mac",
    "announceReceiptTimeout": "announce_receipt_timeout",
    "delayRespUnicast": "delay_resp_unicast",
    "maxSlaves": "max_slaves",
    "delayRespRateLimit": "delay_resp_rate_limit",
}


def config_from_dict(data: dict) -> MasterConfig:
    known = {f.name for f in fields(MasterConfig)}
    kwargs: dict = {}
    overrides: set[str] = set()
    for key, value in data.items():
        if key.startswith("$"):  # "$schema"
            continue
        name = _KEY_MAP.get(key)
        if name is None:
            raise ValueError(f"unknown config key {key!r}")
        if name == "clock_identity" and isinstance(value, str):
            value = _parse_clock_identity(value)
        if name == "dst_mac" and isinstance(value, str):
            value = _parse_mac(value)
        kwargs[name] = value
        overrides.add(name)
    cfg = MasterConfig(**kwargs)
    cfg.apply_profile_defaults(overrides)
    cfg.validate()
    return cfg


def load_config_dict(path: str | Path) -> dict:
    text = Path(path).read_text(encoding="utf-8")
    data = json.loads(_strip_trailing_commas(_strip_jsonc_comments(text)))
    if not isinstance(data, dict):
        raise ValueError("config root must be a JSON object")
    return data


def load_config(path: str | Path) -> MasterConfig:
    return config_from_dict(load_config_dict(path))
