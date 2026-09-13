"""L2 Grandmaster lab runner for the web UI.

Mirrors ptp_lab.py's start/poll/stop pattern: one running master per server
(raw NIC is an exclusive resource), live frame records (Wireshark-style),
stats counters and the online slave session table.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Mapping

from ptp_client.ptp.l2master.config import MasterConfig, config_from_dict, patch_from_dict
from ptp_client.ptp.l2master.master import MasterState, PtpL2Master
from ptp_client.ptp.serde import message_summary

# Bound the in-memory frame log (poll clients only need a recent window).
_MAX_FRAME_RECORDS = 5000


@dataclass
class L2FrameRecord:
    index: int
    direction: str
    wall_unix: float
    payload_hex: str
    summary: dict[str, Any]
    peer_mac: str = ""  # TX: dst MAC; RX: src MAC


class L2FrameCollector:
    def __init__(self) -> None:
        self.records: list[L2FrameRecord] = []
        self._lock = threading.Lock()

    def on_frame(self, direction: str, message_type: int, payload: bytes, extra: dict) -> None:
        try:
            summary = message_summary(payload)
        except Exception:  # never break the master over a UI decode error
            summary = {"message_type": message_type, "message_type_name": f"MT_{message_type}", "body": None}
        peer = str(extra.get("dst_mac") or extra.get("src_mac") or "")
        with self._lock:
            idx = len(self.records)
            self.records.append(
                L2FrameRecord(
                    index=idx,
                    direction=direction,
                    wall_unix=float(extra.get("wall_unix") or time.time()),
                    payload_hex=payload.hex(),
                    summary=summary,
                    peer_mac=peer,
                )
            )
            if len(self.records) > _MAX_FRAME_RECORDS:
                # drop oldest in chunks
                del self.records[: _MAX_FRAME_RECORDS // 10]

    def records_since(self, since: int) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {
                    "index": r.index,
                    "direction": r.direction,
                    "wall_unix": r.wall_unix,
                    "payload_hex": r.payload_hex,
                    "summary": r.summary,
                    "peer_mac": r.peer_mac,
                }
                for r in self.records[since:]
            ]

    def total(self) -> int:
        with self._lock:
            return len(self.records)


@dataclass
class _L2MasterRun:
    run_id: str
    master: PtpL2Master
    cfg: MasterConfig
    collector: L2FrameCollector
    created_at: float = field(default_factory=time.time)


_RUN: _L2MasterRun | None = None
_LOCK = threading.Lock()


def _config_snapshot(cfg: MasterConfig) -> dict[str, Any]:
    return {
        "interface": cfg.interface,
        "offline": cfg.offline,
        "profile": cfg.profile,
        "domain_number": cfg.domain_number,
        "clock_identity": cfg.clock_identity.hex() if cfg.clock_identity else None,
        "port_number": cfg.port_number,
        "priority1": cfg.priority1,
        "priority2": cfg.priority2,
        "clock_class": cfg.clock_class,
        "clock_accuracy": cfg.clock_accuracy,
        "offset_scaled_log_variance": cfg.offset_scaled_log_variance,
        "time_source": cfg.time_source,
        "current_utc_offset": cfg.current_utc_offset,
        "log_announce_interval": cfg.log_announce_interval,
        "log_sync_interval": cfg.log_sync_interval,
        "two_step": cfg.two_step,
        "follow_up_gap_ms": cfg.follow_up_gap_ms,
        "transport_specific": cfg.transport_specific,
        "announce_flags": cfg.announce_flags,
        "sync_flags": cfg.sync_flags,
        "follow_up_flags": cfg.follow_up_flags,
        "delay_resp_flags": cfg.delay_resp_flags,
        "vlan_id": cfg.vlan_id,
        "vlan_pcp": cfg.vlan_pcp,
        "dst_mac": cfg.dst_mac.hex(":"),
        "delay_resp_unicast": cfg.delay_resp_unicast,
        "max_slaves": cfg.max_slaves,
        "delay_resp_rate_limit": cfg.delay_resp_rate_limit,
        "header_link": cfg.header_link,
        "message_overrides": {
            k: {
                **({"domain_number": v["domain_number"]} if "domain_number" in v else {}),
                **({"clock_identity": v["clock_identity"].hex()} if "clock_identity" in v else {}),
                **({"port_number": v["port_number"]} if "port_number" in v else {}),
                **({"transport_specific": v["transport_specific"]} if "transport_specific" in v else {}),
                **({"dst_mac": v["dst_mac"].hex(":")} if "dst_mac" in v else {}),
                **({"vlan_id": v["vlan_id"]} if "vlan_id" in v else {}),
                **({"vlan_pcp": v["vlan_pcp"]} if "vlan_pcp" in v else {}),
            }
            for k, v in cfg.message_overrides.items()
        },
    }


def start_l2_master_lab(body: Mapping[str, Any]) -> dict[str, Any]:
    """Build a MasterConfig from camelCase keys and start the L2 master."""
    global _RUN
    data = dict(body)
    if isinstance(data.get("interface"), str):
        data["interface"] = data["interface"].strip()
    try:
        cfg = config_from_dict(data)
    except (ValueError, TypeError) as e:
        raise ValueError(str(e)) from e

    with _LOCK:
        if _RUN is not None:
            # Replace semantics: tear down the previous run first (single raw NIC).
            try:
                _RUN.master.stop()
            except Exception:  # noqa: BLE001
                pass
            _RUN = None

        collector = L2FrameCollector()
        master = PtpL2Master(cfg, on_frame=collector.on_frame)
        master.start()  # opens the raw transport; raises OSError on failure
        run = _L2MasterRun(run_id=uuid.uuid4().hex[:12], master=master, cfg=cfg, collector=collector)
        _RUN = run

    return {
        "run_id": run.run_id,
        "state": master.stats.state.value,
        "transport": "virtual" if cfg.offline else "live",
        "config": _config_snapshot(cfg),
        "src_mac": master._transport.src_mac.hex(":") if master._transport else "",  # noqa: SLF001
    }


def stop_l2_master_lab() -> dict[str, Any]:
    global _RUN
    with _LOCK:
        run = _RUN
        _RUN = None
    if run is None:
        return {"stopping": False}
    run.master.stop()
    return {"run_id": run.run_id, "stopping": True}


def update_l2_master_lab(body: Mapping[str, Any]) -> dict[str, Any]:
    """Apply message-field changes to the running master (no restart)."""
    run = _RUN
    if run is None:
        raise RuntimeError("master is not running")
    data = dict(body)
    try:
        patch = patch_from_dict(data)
    except (ValueError, TypeError) as e:
        raise ValueError(str(e)) from e
    try:
        cfg = run.master.apply_runtime_update(patch)
    except ValueError as e:
        raise ValueError(str(e)) from e
    return {"run_id": run.run_id, "updated": sorted(patch), "config": _config_snapshot(cfg)}


def poll_l2_master_lab(since: int = 0) -> dict[str, Any]:
    global _RUN
    run = _RUN
    if run is None:
        return {"status": "stopped", "state": MasterState.STOPPED.value, "messages": [], "next_index": 0}

    st = run.master.get_stats()
    slaves = [
        {
            "clock_identity": s.port_identity.clock_identity.hex(),
            "port_number": s.port_identity.port_number,
            "src_mac": s.src_mac.hex(":"),
            "delay_req_count": s.delay_req_count,
            "delay_resp_sent": s.delay_resp_sent,
            "delay_resp_dropped": s.delay_resp_dropped,
            "last_seen_ago_ms": max(0, int((time.monotonic() - s.last_seen) * 1000)),
        }
        for s in run.master.list_slaves()
    ]
    return {
        "run_id": run.run_id,
        "status": "running",
        "state": st.state.value,
        "uptime_sec": round(st.uptime_sec, 1),
        "stats": {
            "announce_sent": st.announce_sent,
            "sync_sent": st.sync_sent,
            "follow_up_sent": st.follow_up_sent,
            "delay_req_recv": st.delay_req_recv,
            "delay_resp_sent": st.delay_resp_sent,
            "delay_resp_dropped": st.delay_resp_dropped,
            "rx_bad_version": st.rx_bad_version,
            "rx_other_domain": st.rx_other_domain,
            "rx_other_type": st.rx_other_type,
            "rx_parse_errors": st.rx_parse_errors,
            "session_overflow": st.session_overflow,
            "resp_queue_full": st.resp_queue_full,
            "tx_errors": st.tx_errors,
            "tx_skipped": st.tx_skipped,
        },
        "slaves": slaves,
        "slave_count": len(slaves),
        "config": _config_snapshot(run.cfg),
        "messages": run.collector.records_since(max(0, int(since))),
        "next_index": run.collector.total(),
    }


def list_interfaces() -> list[dict[str, str]]:
    """Enumerate L2 interfaces usable by the master (best-effort, platform-specific)."""
    import sys

    out: list[dict[str, str]] = []
    if sys.platform.startswith("linux"):
        import os

        net = "/sys/class/net"
        if os.path.isdir(net):
            for name in sorted(os.listdir(net)):
                out.append({"name": name, "description": name})
        return out
    # Windows: scapy/Npcap interface table.
    try:
        from scapy.all import conf

        for _dev, iface in conf.ifaces.items():
            name = getattr(iface, "name", str(iface))
            desc = getattr(iface, "description", name)
            try:
                mac = (getattr(iface, "mac", "") or "").lower()
            except Exception:  # noqa: BLE001
                mac = ""
            out.append({"name": name, "description": desc, "mac": mac})
    except Exception:  # noqa: BLE001 — scapy/Npcap missing
        return []
    return out
