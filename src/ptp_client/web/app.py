"""FastAPI: NTP + PTP ACR lab APIs and static UI."""

from __future__ import annotations

import base64
import traceback
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ptp_client.ntp.client import NTPClient
from ptp_client.ntp.pcap import build_ntp_exchange_pcap, format_hex_preview
from ptp_client.ntp.request_builder import build_ntp_packet
from ptp_client.ntp.serde import packet_summary
from ptp_client.ptp.client import is_unavailable_local_address_error
from ptp_client.ptp.g82752_unicast import UnicastDeniedError, UnicastNegotiationError, UnicastNegotiationTimeout
from ptp_client.web.ptp_lab import build_ptp_packet_response, run_g8275_acr_lab

STATIC_DIR = Path(__file__).resolve().parent / "static"


class TsModel(BaseModel):
    seconds: int = 0
    fraction: int = 0


class PacketSpecModel(BaseModel):
    leap_indicator: int = 0
    version: int = 4
    mode: int = 3
    stratum: int = 0
    poll: int = 0
    precision: int = 0
    root_delay_sec: float | None = None
    root_dispersion_sec: float | None = None
    reference_id: str | None = None
    reference_id_hex: str | None = None
    reference_id_ascii: str | None = None
    reference_timestamp: TsModel | None = None
    receive_timestamp: TsModel | None = None
    transmit_timestamp: TsModel | None = None
    origin_auto_now: bool = True
    origin_unix: float | None = None
    origin_ntp: TsModel | None = None


class ExchangeRequestModel(BaseModel):
    host: str = Field(..., description="NTP server hostname or IP")
    port: int = 123
    timeout: float = 10.0
    packet: PacketSpecModel = Field(default_factory=PacketSpecModel)


class PtpTimestampModel(BaseModel):
    seconds: int = 0
    nanoseconds: int = 0


class PtpPortIdentityModel(BaseModel):
    clock_identity: str = "0001020304050607"
    port_number: int = 1


class PtpPacketSpecModel(BaseModel):
    message_type: str = "delay_req"
    domain_number: int = 44
    version_ptp: int = 2
    flags: int = 1024
    correction_field_ns: int = 0
    transport_specific: int = 0
    sequence_id: int = 0
    log_message_interval: int = -127
    clock_identity: str = "0001020304050607"
    port_number: int = 1
    origin_timestamp: PtpTimestampModel | None = None
    precise_origin_timestamp: PtpTimestampModel | None = None
    receive_timestamp: PtpTimestampModel | None = None
    requesting_port_identity: PtpPortIdentityModel | None = None


class PtpDelayRequestModel(BaseModel):
    flags: int = 1024
    correction_field_ns: int = 0
    clock_identity: str | None = None
    port_number: int | None = None
    origin_timestamp: PtpTimestampModel | None = None
    request_interval_sec: float | None = None


class G8275AcrRequestModel(BaseModel):
    master: str
    domain: int = 44
    clock_identity: str = "0001020304050607"
    port_number: int = 1
    bind: str | None = None
    bind_port: int = 0
    announce_log: int = 0
    sync_log: int = 0
    duration_sec: int = 300
    sync_timeout: float = 8.0
    delay_timeout: float = 8.0
    delay_request_interval_sec: float | None = None
    measure_duration_sec: int | None = None
    negotiate_delay_resp: bool = False
    delay_resp_log: int = 0
    delay_request: PtpDelayRequestModel = Field(default_factory=PtpDelayRequestModel)


def _invalid_bind_address_detail(bind: str | None) -> str:
    addr = str(bind).strip() if bind else "the selected source address"
    return (
        f"Invalid local Bind IP {addr!r}: this address is not assigned to the host running the "
        "web service. Leave Bind IP empty, use 0.0.0.0 to listen on all IPv4 interfaces, or choose "
        "a local NIC IPv4 address from ipconfig (Windows) / ip addr (Linux)."
    )


def create_app() -> FastAPI:
    app = FastAPI(title="Time Sync Client Lab", version="0.2.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "services": "ntp,ptp-acr"}

    @app.post("/api/ntp/exchange")
    def ntp_exchange(body: ExchangeRequestModel) -> dict:
        spec = body.packet.model_dump(mode="python", exclude_none=True)
        try:
            pkt = build_ntp_packet(spec)
            res = NTPClient().exchange(
                body.host,
                body.port,
                request=pkt,
                timeout=body.timeout,
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        except TimeoutError as e:
            raise HTTPException(status_code=504, detail="NTP response timeout") from e
        except OSError as e:
            raise HTTPException(status_code=502, detail=str(e)) from e
        except Exception:
            traceback.print_exc()
            raise HTTPException(status_code=500, detail="internal error") from None

        pcap_bytes = build_ntp_exchange_pcap(
            client_ip=res.client_ip,
            server_ip=res.server_ip,
            client_port=res.client_port,
            server_port=res.server_port,
            request_udp=res.request_udp,
            response_udp=res.response_udp,
            wall_send_unix=res.wall_send_unix,
            wall_recv_unix=res.wall_recv_unix,
        )

        req_sum = packet_summary(res.request)
        rsp_sum = packet_summary(res.response)

        return {
            "offset_seconds": res.offset_seconds,
            "round_trip_delay_seconds": res.round_trip_delay_seconds,
            "t1_unix": res.t1_unix,
            "t2_unix": res.t2_unix,
            "t3_unix": res.t3_unix,
            "t4_unix": res.t4_unix,
            "client": {"ip": res.client_ip, "port": res.client_port},
            "server": {"ip": res.server_ip, "port": res.server_port},
            "request_packet": req_sum,
            "response_packet": rsp_sum,
            "request_udp_hex": res.request_udp.hex(),
            "response_udp_hex": res.response_udp.hex(),
            "pcap_base64": base64.b64encode(pcap_bytes).decode("ascii"),
            "pcap_size": len(pcap_bytes),
            "pcap_preview_lines": format_hex_preview(pcap_bytes, width=16, max_lines=48),
        }

    @app.post("/api/ptp/build")
    def ptp_build(body: PtpPacketSpecModel) -> dict[str, Any]:
        spec = body.model_dump(mode="python", exclude_none=True)
        if body.requesting_port_identity is not None:
            spec["requesting_port_identity"] = body.requesting_port_identity.model_dump()
        try:
            return build_ptp_packet_response(spec)
        except (ValueError, TypeError) as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/ptp/g8275-acr")
    def ptp_g8275_acr(body: G8275AcrRequestModel) -> dict[str, Any]:
        payload = body.model_dump(mode="python", exclude_none=True)
        dr = payload.get("delay_request") or {}
        if body.delay_request.origin_timestamp:
            dr["origin_timestamp"] = body.delay_request.origin_timestamp.model_dump()
        if body.delay_request.request_interval_sec is not None:
            dr["requestIntervalSec"] = body.delay_request.request_interval_sec
        payload["delay_request"] = dr
        if payload.get("delay_request_interval_sec") is None and dr.get("requestIntervalSec"):
            payload["delay_request_interval_sec"] = dr["requestIntervalSec"]
        try:
            return run_g8275_acr_lab(payload)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        except UnicastNegotiationTimeout as e:
            raise HTTPException(status_code=504, detail=str(e)) from e
        except (UnicastDeniedError, UnicastNegotiationError) as e:
            raise HTTPException(status_code=502, detail=str(e)) from e
        except TimeoutError as e:
            raise HTTPException(status_code=504, detail=str(e)) from e
        except OSError as e:
            if is_unavailable_local_address_error(e):
                raise HTTPException(status_code=400, detail=_invalid_bind_address_detail(body.bind)) from e
            raise HTTPException(status_code=502, detail=str(e)) from e
        except Exception:
            traceback.print_exc()
            raise HTTPException(status_code=500, detail="internal error") from None

    @app.get("/")
    def index() -> FileResponse:
        path = STATIC_DIR / "index.html"
        if not path.is_file():
            raise HTTPException(status_code=500, detail=f"Missing UI file: {path}")
        return FileResponse(path)

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    return app


app = create_app()


def main() -> None:
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="info")
