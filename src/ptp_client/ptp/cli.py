"""CLI: PTPv2 unicast delay exchange / optional offset+delay estimate (lab / debug)."""

from __future__ import annotations

import argparse
import socket
import sys

from ptp_client.ptp.client import PTPAcrUnicastClient
from ptp_client.ptp.g82752_unicast import (
    G82752UnicastSession,
    UnicastDeniedError,
    UnicastNegotiationError,
    UnicastNegotiationTimeout,
)
from ptp_client.ptp.header import PortIdentity
from ptp_client.ptp.request_builder import build_ptp_udp_payload
from ptp_client.ptp.serde import message_summary


def _parse_clock_identity_cli(s: str) -> bytes:
    s = s.strip().replace(":", "").replace("-", "")
    if len(s) != 16 or any(c not in "0123456789abcdefABCDEF" for c in s):
        raise argparse.ArgumentTypeError("clock-identity must be 16 hex digits")
    return bytes.fromhex(s)


def _add_common_delay_spec(p: argparse.ArgumentParser) -> None:
    p.add_argument("--domain", type=int, default=0, help="PTP domainNumber (default 0)")
    p.add_argument(
        "--clock-identity",
        type=str,
        default="0001020304050607",
        help="16 hex digits (8 octets) for source PortIdentity.clockIdentity",
    )
    p.add_argument("--port-number", type=int, default=1, help="source PortIdentity.portNumber")
    p.add_argument("--flags", type=lambda x: int(x, 0), default=0, help="message flags (e.g. 0x0200)")
    p.add_argument("--correction-ns", type=int, default=0, help="correctionField as int64 ns (lab)")
    p.add_argument(
        "--bind",
        type=str,
        default=None,
        help="Optional local bind IPv4; ephemeral if --bind-port 0 (default omit)",
    )
    p.add_argument(
        "--bind-port",
        type=int,
        default=0,
        help="0=dual ephemeral on --bind host; 319=bind 319/320 pair (may require privileges)",
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="PTPv2 unicast ACR-oriented client (UDP 319/320).")
    sub = p.add_subparsers(dest="cmd", required=True)

    pd = sub.add_parser("delay", help="Send Delay_Req, wait Delay_Resp on general port")
    pd.add_argument("master", help="Grandmaster / master hostname or IPv4")
    _add_common_delay_spec(pd)
    pd.add_argument("--timeout", type=float, default=5.0)

    pe = sub.add_parser("estimate", help="Wait for Sync (+Follow_Up), then run one delay exchange")
    pe.add_argument("master")
    _add_common_delay_spec(pe)
    pe.add_argument("--sync-timeout", type=float, default=5.0)
    pe.add_argument("--delay-timeout", type=float, default=5.0)

    pb = sub.add_parser("build", help="Print hex of a built PTP UDP payload (offline)")
    pb.add_argument("message_type", choices=("delay_req", "sync", "follow_up", "delay_resp"))
    _add_common_delay_spec(pb)
    pb.add_argument("--sequence-id", type=int, default=1)

    pg = sub.add_parser(
        "g8275-negotiate",
        help="G.8275.2 unicast negotiation (Signalling REQUEST/GRANT; Announce first)",
    )
    pg.add_argument("master", help="T-GM / grant-port IP or hostname")
    pg.add_argument("--domain", type=int, default=44, help="PTP domainNumber (G.8275.2 default 44)")
    pg.add_argument("--clock-identity", type=_parse_clock_identity_cli, default="0001020304050607")
    pg.add_argument("--port-number", type=int, default=1)
    pg.add_argument("--announce-log", type=int, default=0, help="logInterMessagePeriod for Announce (Annex A.3.4)")
    pg.add_argument("--sync-log", type=int, default=0, help="logInterMessagePeriod for Sync")
    pg.add_argument("--delay-resp-log", type=int, default=0, help="logInterMessagePeriod for Delay_Resp")
    pg.add_argument("--duration", type=int, default=300, help="durationField seconds (60–1000 typical)")
    pg.add_argument("--one-way", action="store_true", help="do not request Delay_Resp (omit two-way contract)")
    pg.add_argument("--cancel-after", action="store_true", help="send CANCEL after successful negotiate")
    pg.add_argument("--bind", type=str, default=None)
    pg.add_argument("--bind-port", type=int, default=0)

    ns = p.parse_args(argv)

    if ns.cmd == "build":
        spec: dict = {
            "message_type": ns.message_type,
            "domain_number": ns.domain,
            "flags": ns.flags,
            "correction_field_ns": ns.correction_ns,
            "sequence_id": ns.sequence_id,
            "clock_identity": ns.clock_identity,
            "port_number": ns.port_number,
        }
        payload = build_ptp_udp_payload(spec)
        print(payload.hex())
        return 0

    source_address = None
    if ns.bind:
        source_address = (ns.bind, int(ns.bind_port))

    if ns.cmd == "delay":
        client = PTPAcrUnicastClient(ns.master, domain_number=ns.domain)
        spec = {
            "clock_identity": ns.clock_identity,
            "port_number": ns.port_number,
            "flags": ns.flags,
            "correction_field_ns": ns.correction_ns,
        }
        try:
            client.start(source_address=source_address)
            res = client.exchange_delay(spec, timeout=ns.timeout)
        except OSError as e:
            print(f"network error: {e}", file=sys.stderr)
            return 1
        except TimeoutError:
            print("timeout waiting for Delay_Resp", file=sys.stderr)
            return 1
        finally:
            client.close()

        print(f"master {ns.master} server_ip={res.server_ip}")
        print(
            f"t3_send_unix={res.t3_send_unix:.9f} t4_master_rx_approx={res.t4_master_rx_posix_approx:.9f} "
            f"resp_wall={res.wall_recv_resp_unix:.9f}"
        )
        print("delay_req:", message_summary(res.delay_req_udp))
        print("delay_resp:", message_summary(res.delay_resp_udp))
        return 0

    if ns.cmd == "estimate":
        client = PTPAcrUnicastClient(ns.master, domain_number=ns.domain)
        spec = {
            "clock_identity": ns.clock_identity,
            "port_number": ns.port_number,
            "flags": ns.flags,
            "correction_field_ns": ns.correction_ns,
        }
        try:
            client.start(source_address=source_address)
            est = client.estimate_offset_and_delay(
                delay_spec=spec,
                sync_timeout=ns.sync_timeout,
                delay_timeout=ns.delay_timeout,
            )
        except OSError as e:
            print(f"network error: {e}", file=sys.stderr)
            return 1
        except TimeoutError as e:
            print(f"timeout: {e}", file=sys.stderr)
            return 1
        finally:
            client.close()

        print(f"master {ns.master} server_ip={est.delay.server_ip}")
        print(f"offset_seconds={est.offset_seconds:.9f} mean_path_delay_seconds={est.mean_path_delay_seconds:.9f}")
        print(f"sync one_step={est.sync.one_step} t1_approx={est.sync.t1_master_posix_approx:.9f} t2={est.sync.t2_sync_recv_unix:.9f}")
        return 0

    if ns.cmd == "g8275-negotiate":
        src_adr = (ns.bind, int(ns.bind_port)) if ns.bind else None
        our = PortIdentity(bytes(ns.clock_identity), int(ns.port_number))
        client = PTPAcrUnicastClient(ns.master, domain_number=ns.domain)
        session = G82752UnicastSession(
            client=client,
            our_identity=our,
            domain_number=ns.domain,
            announce_log_period=ns.announce_log,
            sync_log_period=ns.sync_log,
            delay_resp_log_period=ns.delay_resp_log,
            duration_sec=ns.duration,
            two_way=not ns.one_way,
        )
        try:
            client.start(source_address=src_adr)
            st = session.negotiate()
            sip = socket.getaddrinfo(ns.master, 319, socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]
            print(f"master {ns.master} server_ip={sip}")
            print(f"gm_clock_identity={st.grandmaster_port_identity.clock_identity.hex()}")
            print(f"gm_port_number={st.grandmaster_port_identity.port_number}")
            print(f"grants_sec={st.grants}")
            if ns.cancel_after:
                session.cancel_unicast(wait_ack=False)
        except OSError as e:
            print(f"network error: {e}", file=sys.stderr)
            return 1
        except (UnicastNegotiationTimeout, UnicastDeniedError, UnicastNegotiationError) as e:
            print(f"negotiation failed: {e}", file=sys.stderr)
            return 1
        finally:
            client.close()
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
