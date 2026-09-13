"""CLI: run the PTP L2 grandmaster (Announce + Sync/Follow_Up) from a config file.

Examples:
    ptp-l2-master --config config/ptp-l2-master.json
    ptp-l2-master --iface eth0 --profile g82751 --domain 43
    ptp-l2-master --iface "Ethernet" --profile 1588v2 --duration 60   (Windows/Npcap)
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from types import FrameType

from ptp_client.ptp.l2master.config import MasterConfig, config_from_dict, load_config_dict
from ptp_client.ptp.l2master.master import MasterStats, PtpL2Master
from ptp_client.ptp.l2master.transport import L2TransportError


def _parse_clock_identity(s: str) -> bytes:
    b = bytes.fromhex(s.replace(":", "").replace("-", ""))
    if len(b) != 8:
        raise argparse.ArgumentTypeError("clock-identity must be 16 hex digits")
    return b


def _parse_mac(s: str) -> bytes:
    b = bytes.fromhex(s.replace(":", "").replace("-", ""))
    if len(b) != 6:
        raise argparse.ArgumentTypeError("MAC must be 12 hex digits")
    return b


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ptp-l2-master",
        description="PTP G.8275.1 / IEEE 1588v2 layer-2 E2E grandmaster (Announce+Sync/Follow_Up, Delay_Req→Delay_Resp).",
    )
    p.add_argument("--config", type=str, default=None, help="JSON(C) config file (see config/ptp-l2-master.json)")
    p.add_argument("--iface", type=str, default=None, help="interface name (overrides config)")
    p.add_argument(
        "--offline",
        action="store_true",
        help="virtual wire: keep the interface name as a label but do not open the NIC; "
        "layer-2 frames are generated (and shown in logs) but never sent",
    )
    p.add_argument("--profile", choices=("g82751", "1588v2"), default=None, help="profile (overrides config)")
    p.add_argument("--domain", type=int, default=None, help="domainNumber (overrides config)")
    p.add_argument("--clock-identity", type=_parse_clock_identity, default=None, help="8-octet clockIdentity (hex)")
    p.add_argument("--port-number", type=int, default=None, help="source portNumber")
    p.add_argument("--announce-log", type=int, default=None, help="logAnnounceInterval (2^n s)")
    p.add_argument("--sync-log", type=int, default=None, help="logSyncInterval (2^n s)")
    p.add_argument("--one-step", action="store_true", help="one-step Sync (no Follow_Up)")
    p.add_argument("--vlan-id", type=int, default=None, help="add 802.1Q tag with this VID")
    p.add_argument("--vlan-pcp", type=int, default=None, help="VLAN PCP (default 6)")
    p.add_argument("--dst-mac", type=_parse_mac, default=None, help="override destination multicast MAC (hex)")
    p.add_argument("--delay-resp-unicast", action="store_true", help="unicast Delay_Resp back to the slave")
    p.add_argument("--max-slaves", type=int, default=None, help="slave session table limit")
    p.add_argument("--rate-limit", type=int, default=None, help="Delay_Resp rate limit pps (0=unlimited)")
    p.add_argument("--duration", type=float, default=0.0, help="run for N seconds then exit (0=until Ctrl-C)")
    p.add_argument("--stats-period", type=float, default=10.0, help="print stats every N s (0=off)")
    p.add_argument("-v", "--verbose", action="store_true", help="DEBUG logging (per-packet)")
    return p


def _config_from_args(ns: argparse.Namespace) -> MasterConfig:
    data: dict = load_config_dict(ns.config) if ns.config else {}
    # CLI overrides (only when explicitly provided).
    mapping = {
        "interface": ns.iface,
        "profile": ns.profile,
        "domainNumber": ns.domain,
        "clockIdentity": ns.clock_identity,
        "portNumber": ns.port_number,
        "logAnnounceInterval": ns.announce_log,
        "logSyncInterval": ns.sync_log,
        "vlanId": ns.vlan_id,
        "vlanPcp": ns.vlan_pcp,
        "dstMac": ns.dst_mac,
        "maxSlaves": ns.max_slaves,
        "delayRespRateLimit": ns.rate_limit,
    }
    for key, value in mapping.items():
        if value is not None:
            data[key] = value
    if ns.one_step:
        data["twoStep"] = False
    if ns.delay_resp_unicast:
        data["delayRespUnicast"] = True
    if ns.offline:
        data["offline"] = True
    return config_from_dict(data)


def main(argv: list[str] | None = None) -> int:
    ns = build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if ns.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-5s %(name)s: %(message)s",
    )
    try:
        cfg = _config_from_args(ns)
    except (ValueError, OSError) as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2

    master = PtpL2Master(cfg)
    stop_requested = False

    def _on_signal(signum: int, frame: FrameType | None) -> None:  # noqa: ARG001
        nonlocal stop_requested
        if stop_requested:
            return
        stop_requested = True
        print("\n[master] stopping...", flush=True)
        master.stop()

    signal.signal(signal.SIGINT, _on_signal)
    try:
        signal.signal(signal.SIGTERM, _on_signal)
    except (ValueError, AttributeError, OSError):  # SIGTERM unsupported on some platforms
        pass

    try:
        master.start()
    except (L2TransportError, OSError, ValueError) as e:
        print(f"start failed: {e}", file=sys.stderr)
        return 1

    def _fmt(st: MasterStats) -> str:
        return (
            f"state={st.state.value} uptime={st.uptime_sec:6.1f}s "
            f"announce={st.announce_sent} sync={st.sync_sent} follow_up={st.follow_up_sent} "
            f"delay_req={st.delay_req_recv} delay_resp={st.delay_resp_sent} dropped={st.delay_resp_dropped} "
            f"slaves={len(master.list_slaves())} "
            f"tx_errors={st.tx_errors} skipped={st.tx_skipped}"
        )

    try:
        if ns.duration > 0:
            deadline = time.monotonic() + ns.duration
            interval = ns.stats_period if ns.stats_period > 0 else ns.duration
            while not stop_requested:
                step = min(interval, max(0.0, deadline - time.monotonic()))
                if step <= 0:
                    break
                time.sleep(step)
                if ns.stats_period > 0 and not stop_requested and time.monotonic() < deadline:
                    print(f"[master] {_fmt(master.get_stats())}", flush=True)
        elif ns.stats_period > 0:
            while not stop_requested:
                time.sleep(ns.stats_period)
                if not stop_requested:
                    print(f"[master] {_fmt(master.get_stats())}", flush=True)
        else:
            master.wait()
    finally:
        if not stop_requested:
            master.stop()
    print(f"[master] final: {_fmt(master.get_stats())}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
