"""PTP ACR lab runner for the web UI: packet capture, stats, G.8275.2 session."""

from __future__ import annotations

import base64
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Mapping

from ptp_client.ptp.client import PTPAcrEstimateResult, PTPAcrUnicastClient
from ptp_client.ptp.constants import FLAG_UNICAST
from ptp_client.ptp.delay_request import build_delay_request_spec, parse_delay_request_interval_sec
from ptp_client.ptp.g82752_unicast import G82752AcrRunConfig, G82752UnicastSession, UnicastNegotiationError
from ptp_client.ptp.header import PortIdentity
from ptp_client.ptp.pcap import build_ptp_udp_pcap
from ptp_client.ptp.request_builder import build_ptp_udp_payload
from ptp_client.ptp.serde import message_summary
from ptp_client.ptp.signaling import describe_signaling_udp
from ptp_client.ntp.pcap import format_hex_preview

# Web UI must not block HTTP forever; CLI uses measure_duration_sec=None for unlimited.
WEB_LAB_DEFAULT_MEASURE_SEC = 90


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
        self.records.append(
            PacketRecord(
                index=idx,
                direction=direction,
                channel=channel,
                wall_unix=wall,
                udp_hex=payload.hex(),
                summary=summ,
            )
        )
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
        self.pcap_rows.append((wall, sip, sport, dip, dport, payload))

    def stats_by_message_type(self) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = defaultdict(lambda: {"tx": 0, "rx": 0, "total": 0})
        for rec in self.records:
            name = str(rec.summary.get("message_type_name", "UNKNOWN"))
            out[name][rec.direction] += 1
            out[name]["total"] += 1
        return {k: dict(v) for k, v in sorted(out.items())}


def build_ptp_packet_response(spec: Mapping[str, Any]) -> dict[str, Any]:
    payload = build_ptp_udp_payload(dict(spec))
    return {
        "udp_hex": payload.hex(),
        "raw_length": len(payload),
        "packet": enrich_message_summary(payload),
    }


def _estimate_to_dict(est: PTPAcrEstimateResult) -> dict[str, Any]:
    sync = est.sync
    delay = est.delay
    return {
        "offset_seconds": est.offset_seconds,
        "mean_path_delay_seconds": est.mean_path_delay_seconds,
        "sync_one_step": sync.one_step,
        "t1_master_posix_approx": sync.t1_master_posix_approx,
        "t2_sync_recv_unix": sync.t2_sync_recv_unix,
        "t3_delay_req_send_unix": delay.t3_send_unix,
        "t4_delay_resp_rx_posix_approx": delay.t4_master_rx_posix_approx,
        "delay_req_seq": delay.request_header.sequence_id,
        "delay_resp_seq": delay.response_header.sequence_id,
    }


def run_g8275_acr_lab(body: Mapping[str, Any]) -> dict[str, Any]:
    master = str(body["master"]).strip()
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
            measure_duration_sec = None
    else:
        measure_duration_sec = None
    if measure_duration_sec is None:
        measure_duration_sec = WEB_LAB_DEFAULT_MEASURE_SEC

    bind = body.get("bind")
    bind_port = int(body.get("bind_port", 0))
    src_adr = (str(bind), bind_port) if bind else None

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

    estimates: list[dict[str, Any]] = []
    st = None
    try:
        client.start(source_address=src_adr)
        ev_ip, ev_port = client._event_sock.getsockname()  # noqa: SLF001 — lab endpoint capture
        gen_ip, gen_port = client._general_sock.getsockname()  # noqa: SLF001
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

        def _on_estimate(est: PTPAcrEstimateResult) -> None:
            estimates.append(_estimate_to_dict(est))

        session.start_acr(
            G82752AcrRunConfig(
                measure_acr=True,
                delay_spec=delay_spec,
                sync_timeout=sync_timeout,
                delay_timeout=delay_timeout,
                delay_request_interval_sec=delay_interval,
                measure_duration_sec=measure_duration_sec,
                on_estimate=_on_estimate,
            )
        )
        wait_timeout: float | None = None
        if measure_duration_sec is not None:
            wait_timeout = float(measure_duration_sec) + sync_timeout + 30.0
        session.wait_acr(timeout=wait_timeout)
        st = session.state
    finally:
        session.stop_acr()
        client.close()

    if st is None:
        raise UnicastNegotiationError("negotiate() did not complete")

    pcap_bytes = build_ptp_udp_pcap(collector.pcap_rows)
    records_out = [
        {
            "index": r.index,
            "direction": r.direction,
            "channel": r.channel,
            "wall_unix": r.wall_unix,
            "udp_hex": r.udp_hex,
            "summary": r.summary,
        }
        for r in collector.records
    ]

    return {
        "master": master,
        "domain": domain,
        "gm_clock_identity": st.grandmaster_port_identity.clock_identity.hex(),
        "gm_port_number": st.grandmaster_port_identity.port_number,
        "grants_sec": st.grants,
        "negotiated": {
            "announce_log": announce_log,
            "sync_log": sync_log,
            "delay_resp_log": delay_resp_log if negotiate_delay_resp else None,
            "duration_sec": duration_sec,
            "delay_request_interval_sec": delay_interval,
            "measure_duration_sec": measure_duration_sec,
        },
        "stats": collector.stats_by_message_type(),
        "messages": records_out,
        "estimates": estimates,
        "last_estimate": estimates[-1] if estimates else None,
        "pcap_base64": base64.b64encode(pcap_bytes).decode("ascii"),
        "pcap_size": len(pcap_bytes),
        "pcap_preview_lines": format_hex_preview(pcap_bytes, width=16, max_lines=64),
    }
