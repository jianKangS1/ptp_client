"""FastAPI: NTP exchange API + static UI."""

from __future__ import annotations

import base64
import traceback
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ptp_client.ntp.client import NTPClient
from ptp_client.ntp.pcap import build_ntp_exchange_pcap, format_hex_preview
from ptp_client.ntp.request_builder import build_ntp_packet
from ptp_client.ntp.serde import packet_summary

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


def create_app() -> FastAPI:
    app = FastAPI(title="NTP Client Lab", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

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

    # 直接传入 app，避免 Windows 下按字符串加载模块时工作目录/PYTHONPATH 不一致导致立即退出
    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="info")
