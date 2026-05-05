"""CLI: talk to an NTP server with customizable packet fields."""

from __future__ import annotations

import argparse
import sys

from ptp_client.ntp.cli_args import packet_from_namespace
from ptp_client.ntp.client import NTPClient


def _parse_ref_id(s: str) -> bytes:
    s = s.strip()
    if len(s) == 8 and all(c in "0123456789abcdefABCDEF" for c in s):
        return bytes.fromhex(s)
    if len(s) == 4:
        return s.encode("ascii", errors="strict")
    raise argparse.ArgumentTypeError("ref-id must be 4 ASCII chars or 8 hex digits")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="NTP/SNTP client with customizable packet fields.")
    p.add_argument("host", help="NTP server hostname or IP")
    p.add_argument("--port", type=int, default=123, help="UDP port (default 123)")
    p.add_argument("--timeout", type=float, default=5.0, help="UDP timeout seconds")

    p.add_argument("--leap", type=int, default=0, help="Leap indicator 0–3")
    p.add_argument("--version", type=int, default=4, help="NTP version (3 or 4)")
    p.add_argument("--mode", type=int, default=3, help="NTP mode (client=3)")
    p.add_argument("--stratum", type=int, default=0, help="Stratum (client often 0)")
    p.add_argument("--poll", type=int, default=0, help="Poll exponent")
    p.add_argument("--precision", type=int, default=0, help="Precision signed exponent (int8)")
    p.add_argument(
        "--root-delay",
        type=float,
        default=None,
        help="Root delay in seconds (NTP short format); default 0",
    )
    p.add_argument(
        "--root-dispersion",
        type=float,
        default=None,
        help="Root dispersion in seconds (unsigned short format); default 0",
    )
    p.add_argument(
        "--ref-id",
        type=_parse_ref_id,
        default=b"\x00\x00\x00\x00",
        help='Reference id: 4 ASCII chars or 8 hex digits (e.g. LOCL or "47505300")',
    )

    p.add_argument(
        "--origin-unix",
        type=float,
        default=None,
        help="Origin timestamp as Unix time (omit for send-time 'now')",
    )
    p.add_argument("--origin-ntp-sec", type=int, default=None, help="Origin NTP seconds (1900 epoch)")
    p.add_argument(
        "--origin-ntp-frac",
        type=lambda x: int(x, 0),
        default=0,
        help="Origin NTP fraction (uint32, default 0)",
    )

    p.add_argument("--ref-ts-sec", type=int, default=0)
    p.add_argument("--ref-ts-frac", type=lambda x: int(x, 0), default=0)
    p.add_argument("--recv-ts-sec", type=int, default=0)
    p.add_argument("--recv-ts-frac", type=lambda x: int(x, 0), default=0)
    p.add_argument("--xmit-ts-sec", type=int, default=0)
    p.add_argument("--xmit-ts-frac", type=lambda x: int(x, 0), default=0)

    ns = p.parse_args(argv)

    if ns.origin_unix is not None and ns.origin_ntp_sec is not None:
        p.error("Use only one of --origin-unix or --origin-ntp-sec")

    req = packet_from_namespace(ns)
    client = NTPClient()
    try:
        res = client.exchange(ns.host, ns.port, request=req, timeout=ns.timeout)
    except OSError as e:
        print(f"network error: {e}", file=sys.stderr)
        return 1
    except TimeoutError:
        print("timeout waiting for NTP reply", file=sys.stderr)
        return 1

    rsp = res.response
    kiss = res.kiss_code
    print(f"server {ns.host}:{ns.port}")
    print(f"stratum={rsp.stratum} version={rsp.version} mode={rsp.mode} leap={rsp.leap_indicator}")
    if kiss:
        print(f"kiss_code={kiss!r}")
    print(f"ref_id={rsp.reference_id_as_text()!r} precision_exp={rsp.precision}")
    print(f"offset_seconds={res.offset_seconds:.6f} rtt_seconds={res.round_trip_delay_seconds:.6f}")
    print(
        f"t1(origin)={res.t1_unix:.6f} t2(recv)={res.t2_unix:.6f} "
        f"t3(xmit)={res.t3_unix:.6f} t4(dest)={res.t4_unix:.6f}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
