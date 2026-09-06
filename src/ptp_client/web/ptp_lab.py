"""PTP ACR lab runner for the web UI: packet capture, stats, G.8275.2 session.

The run is executed on a background thread; the UI starts it, polls for new
packets (Wireshark-style live view) and may request a stop, which ends the
measure loop and sends CANCEL (Signalling) to the server before closing.
"""

from __future__ import annotations

import base64
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Mapping

from ptp_client.ptp.client import PTPAcrUnicastClient
from ptp_client.ptp.constants import EVENT_PORT, FLAG_UNICAST
from ptp_client.ptp.delay_request import build_delay_request_spec, parse_delay_request_interval_sec
from ptp_client.ptp.g82752_unicast import G82752AcrRunConfig, G82752UnicastSession
from ptp_client.ptp.header import PortIdentity
from ptp_client.ptp.pcap import build_ptp_udp_pcap
from ptp_client.ptp.request_builder import build_ptp_udp_payload
from ptp_client.ptp.serde import message_summary
from ptp_client.ptp.signaling import describe_signaling_udp
from ptp_client.ntp.pcap import format_hex_preview

# Web runs until the user presses Stop (measure_duration_sec 0/None = unlimited).


def _parse_clock_identity(s: str) -> bytes:
    s = s.strip().replace(":", "").replace("-", "")
    if len(s) != 16:
        raise ValueError("clock_identity must be 16 hex digits")
    return bytes.fromhex(s)


def enrich_message_summary(udp_payload: bytes) -> dict[str, Any]:
    summ = message_summary(udp_payload)
    if summ.get("message_type_name") == "SIGNALING":
        summ["signaling"] = describe_signaling_udp(udp_payload)
    return summ


@dataclass
class PacketRecord:
    index: int
    direction: str
    channel: str
    wall_unix: float
    udp_hex: str
    summary: dict[str, Any]
    src: str = ""
    dst: str = ""


@dataclass
class PtpPacketCollector:
    records: list[PacketRecord] = field(default_factory=list)
    pcap_rows: list[tuple[float, str, int, str, int, bytes]] = field(default_factory=list)
    _client_ip: str = "0.0.0.0"
    _client_event_port: int = 319
    _client_general_port: int = 320
    _server_ip: str = "0.0.0.0"

    def bind_endpoints(
        self,
        *,
        client_ip: str,
        client_event_port: int,
        client_general_port: int,
        server_ip: str,
    ) -> None:
        self._client_ip = client_ip
        self._client_event_port = client_event_port
        self._client_general_port = client_general_port
        self._server_ip = server_ip

    def on_packet(self, direction: str, channel: str, payload: bytes, wall: float) -> None:
        summ = enrich_message_summary(payload)
        idx = len(self.records)
        if direction == "tx":
            if channel == "event":
                sip, sport, dip, dport = self._client_ip, self._client_event_port, self._server_ip, 319
            else:
                sip, sport, dip, dport = self._client_ip, self._client_general_port, self._server_ip, 320
        else:
            if channel == "event":
                sip, sport, dip, dport = self._server_ip, 319, self._client_ip, self._client_event_port
            else:
                sip, sport, dip, dport = self._server_ip, 320, self._client_ip, self._client_general_port
        self.records.append(
            PacketRecord(
                index=idx,
                direction=direction,
                channel=channel,
                wall_unix=wall,
                udp_hex=payload.hex(),
                summary=summ,
                src=f"{sip}:{sport}",
                dst=f"{dip}:{dport}",
            )
        )
        self.pcap_rows.append((wall, sip, sport, dip, dport, payload))

    def stats_by_message_type(self) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = defaultdict(lambda: {"tx": 0, "rx": 0, "total": 0})
        for rec in self.records:
            name = str(rec.summary.get("message_type_name", "UNKNOWN"))
            out[name][rec.direction] += 1
            out[name]["total"] += 1
        return {k: dict(v) for k, v in sorted(out.items())}

    def records_since(self, index: int) -> list[dict[str, Any]]:
        """Thread-safe snapshot of packet records appended after ``index`` (Wireshark-style poll)."""
        snapshot = self.records[index:]
        return [
            {
                "index": r.index,
                "direction": r.direction,
                "channel": r.channel,
                "wall_unix": r.wall_unix,
                "udp_hex": r.udp_hex,
                "summary": r.summary,
                "src": r.src,
                "dst": r.dst,
            }
            for r in snapshot
        ]

    def total_records(self) -> int:
        return len(self.records)


def build_ptp_packet_response(spec: Mapping[str, Any]) -> dict[str, Any]:
    payload = build_ptp_udp_payload(dict(spec))
    return {
        "udp_hex": payload.hex(),
        "raw_length": len(payload),
        "packet": enrich_message_summary(payload),
    }


@dataclass
class _LabRun:
    run_id: str
    client: PTPAcrUnicastClient
    session: G82752UnicastSession
    collector: PtpPacketCollector
    negotiated: dict[str, Any]
    master: str
    domain: int
    stop_event: threading.Event = field(default_factory=threading.Event)
    finished: threading.Event = field(default_factory=threading.Event)
    error: str | None = None
    cancel_sent: bool = False
    gm_info: dict[str, Any] = field(default_factory=dict)
    pcap_base64: str | None = None
    pcap_size: int = 0
    pcap_preview_lines: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)


_RUNS: dict[str, _LabRun] = {}
_RUNS_LOCK = threading.Lock()
_FINISHED_RUN_TTL_SEC = 600.0


def _get_run(run_id: str) -> _LabRun:
    with _RUNS_LOCK:
        run = _RUNS.get(run_id)
    if run is None:
        raise KeyError(run_id)
    return run


def _gc_finished_runs() -> None:
    now = time.time()
    with _RUNS_LOCK:
        stale = [
            rid
            for rid, r in _RUNS.items()
            if r.finished.is_set() and now - r.created_at > _FINISHED_RUN_TTL_SEC
        ]
        for rid in stale:
            _RUNS.pop(rid, None)


def _lab_worker(run: _LabRun, measure_duration_sec: int | None) -> None:
    session = run.session
    try:
        session.start_acr(
            G82752AcrRunConfig(
                measure_acr=True,
                delay_spec=run.negotiated["delay_spec"],
                sync_timeout=run.negotiated["sync_timeout"],
                delay_timeout=run.negotiated["delay_timeout"],
                delay_request_interval_sec=run.negotiated["delay_request_interval_sec"],
                measure_duration_sec=measure_duration_sec,
            )
        )
        stop_requested = False
        while not session.is_finished():
            if run.stop_event.is_set() and not stop_requested:
                session.request_stop()
                stop_requested = True
            time.sleep(0.1)
        try:
            session.wait_acr(timeout=5.0)
        except TimeoutError:
            run.error = "ACR manager did not finish in time"
        except BaseException as exc:  # manager-thread error re-raised
            msg = f"{type(exc).__name__}: {exc}"
            # 用户主动停止导致的提前退出（协商/测量中断）不算错误
            if stop_requested and "stop requested" in str(exc):
                pass
            else:
                run.error = msg
        st = session.state
        if st is not None:
            run.gm_info = {
                "gm_clock_identity": st.grandmaster_port_identity.clock_identity.hex(),
                "gm_port_number": st.grandmaster_port_identity.port_number,
                "grants_sec": {str(k): v for k, v in st.grants.items()},
            }
    except BaseException as exc:  # noqa: BLE001 — thread boundary
        run.error = f"{type(exc).__name__}: {exc}"
    finally:
        # Teardown: CANCEL negotiated streams so the server stops unicast tx.
        # Best-effort even if negotiation stalled (server may already hold a partial grant).
        try:
            session.cancel_unicast(wait_ack=False)
            run.cancel_sent = True
        except Exception:  # noqa: BLE001 — best-effort teardown
            pass
        try:
            session.stop_acr()
        finally:
            run.client.close()
        try:
            pcap_bytes = build_ptp_udp_pcap(list(run.collector.pcap_rows))
            run.pcap_base64 = base64.b64encode(pcap_bytes).decode("ascii")
            run.pcap_size = len(pcap_bytes)
            run.pcap_preview_lines = format_hex_preview(pcap_bytes, width=16, max_lines=64)
        except Exception:  # noqa: BLE001
            pass
        run.finished.set()


def start_g8275_acr_lab(body: Mapping[str, Any]) -> dict[str, Any]:
    """Start a background G.8275.2 ACR run; returns run_id immediately (non-blocking)."""
    _gc_finished_runs()

    master = str(body["master"]).strip()
    if not master:
        raise ValueError("master is required")
    domain = int(body.get("domain", 44))
    clock_identity = _parse_clock_identity(str(body.get("clock_identity", "0001020304050607")))
    port_number = int(body.get("port_number", 1))
    our = PortIdentity(clock_identity, port_number)

    announce_log = int(body.get("announce_log", 0))
    sync_log = int(body.get("sync_log", 0))
    duration_sec = int(body.get("duration_sec", body.get("duration", 300)))
    sync_timeout = float(body.get("sync_timeout", 8.0))
    delay_timeout = float(body.get("delay_timeout", 8.0))
    negotiate_delay_resp = bool(body.get("negotiate_delay_resp", False))
    delay_resp_log = int(body.get("delay_resp_log", 0))

    delay_req_cfg = body.get("delay_request") or {}
    delay_spec = build_delay_request_spec(
        delay_req_cfg,
        domain_number=domain,
        clock_identity=clock_identity,
        port_number=port_number,
        default_flags=FLAG_UNICAST,
    )
    delay_interval = body.get("delay_request_interval_sec")
    if delay_interval is None:
        delay_interval = parse_delay_request_interval_sec(delay_req_cfg)
    if delay_interval is not None:
        delay_interval = float(delay_interval)
        if delay_interval <= 0:
            delay_interval = None

    measure_duration_sec = body.get("measure_duration_sec")
    if measure_duration_sec is not None:
        measure_duration_sec = int(measure_duration_sec)
        if measure_duration_sec <= 0:
            measure_duration_sec = None  # run until Stop is pressed

    # Fixed protocol ports: event 319 / general 320 (no user-configurable bind port).
    bind = str(body.get("bind") or "").strip()
    src_adr = (bind, EVENT_PORT)  # bind "" = all interfaces, still 319/320

    collector = PtpPacketCollector()
    client = PTPAcrUnicastClient(master, domain_number=domain, on_packet=collector.on_packet)
    session = G82752UnicastSession(
        client=client,
        our_identity=our,
        domain_number=domain,
        announce_log_period=announce_log,
        sync_log_period=sync_log,
        delay_resp_log_period=delay_resp_log,
        duration_sec=duration_sec,
        negotiate_delay_resp=negotiate_delay_resp,
    )

    client.start(source_address=src_adr)
    try:
        ev_ip, ev_port = client._event_sock.getsockname()  # noqa: SLF001 — lab endpoint capture
        _gen_ip, gen_port = client._general_sock.getsockname()  # noqa: SLF001
        server_ip = client._event_peer[0] if client._event_peer else master  # noqa: SLF001
        if ev_ip in ("0.0.0.0", ""):
            from ptp_client.ptp.client import _local_ip_toward

            ev_ip = _local_ip_toward(server_ip)
        collector.bind_endpoints(
            client_ip=ev_ip,
            client_event_port=int(ev_port),
            client_general_port=int(gen_port),
            server_ip=server_ip,
        )
    except Exception:
        client.close()
        raise

    run = _LabRun(
        run_id=uuid.uuid4().hex[:12],
        client=client,
        session=session,
        collector=collector,
        negotiated={
            "announce_log": announce_log,
            "sync_log": sync_log,
            "delay_resp_log": delay_resp_log if negotiate_delay_resp else None,
            "duration_sec": duration_sec,
            "delay_request_interval_sec": delay_interval,
            "measure_duration_sec": measure_duration_sec,
            "delay_spec": delay_spec,
            "sync_timeout": sync_timeout,
            "delay_timeout": delay_timeout,
        },
        master=master,
        domain=domain,
    )
    with _RUNS_LOCK:
        _RUNS[run.run_id] = run

    threading.Thread(target=_lab_worker, args=(run, measure_duration_sec), name="ptp-lab-run", daemon=True).start()

    return {
        "run_id": run.run_id,
        "master": master,
        "domain": domain,
        "local": {"ip": ev_ip, "event_port": int(ev_port), "general_port": int(gen_port)},
    }


def poll_g8275_acr_lab(run_id: str, since_index: int = 0) -> dict[str, Any]:
    """Return packets received since ``since_index`` plus live stats (for the Wireshark-style view)."""
    run = _get_run(run_id)
    since_index = max(0, int(since_index))
    finished = run.finished.is_set()
    out: dict[str, Any] = {
        "run_id": run.run_id,
        "status": "finished" if finished else "running",
        "error": run.error,
        "cancel_sent": run.cancel_sent,
        "messages": run.collector.records_since(since_index),
        "next_index": run.collector.total_records(),
        "stats": run.collector.stats_by_message_type(),
        "master": run.master,
        "domain": run.domain,
        "negotiated": {k: v for k, v in run.negotiated.items() if not k.startswith("delay_spec") and k not in ("sync_timeout", "delay_timeout")},
    }
    out.update(run.gm_info)
    if finished:
        out["pcap_base64"] = run.pcap_base64
        out["pcap_size"] = run.pcap_size
        out["pcap_preview_lines"] = run.pcap_preview_lines
    return out


def stop_g8275_acr_lab(run_id: str) -> dict[str, Any]:
    """Request a graceful stop: measure loop ends, then CANCEL is sent to the server."""
    run = _get_run(run_id)
    run.stop_event.set()
    return {"run_id": run.run_id, "stopping": not run.finished.is_set()}
