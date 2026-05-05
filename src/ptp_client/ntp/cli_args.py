"""Map argparse Namespace to `build_ntp_packet` spec dict."""

from __future__ import annotations

import argparse

from ptp_client.ntp.request_builder import build_ntp_packet


def namespace_to_spec(ns: argparse.Namespace) -> dict:
    spec: dict = {
        "leap_indicator": ns.leap,
        "version": ns.version,
        "mode": ns.mode,
        "stratum": ns.stratum,
        "poll": ns.poll,
        "precision": ns.precision,
        "reference_timestamp": {"seconds": ns.ref_ts_sec, "fraction": ns.ref_ts_frac},
        "receive_timestamp": {"seconds": ns.recv_ts_sec, "fraction": ns.recv_ts_frac},
        "transmit_timestamp": {"seconds": ns.xmit_ts_sec, "fraction": ns.xmit_ts_frac},
    }
    if ns.root_delay is not None:
        spec["root_delay_sec"] = ns.root_delay
    if ns.root_dispersion is not None:
        spec["root_dispersion_sec"] = ns.root_dispersion
    if ns.ref_id != b"\x00\x00\x00\x00":
        spec["reference_id_hex"] = ns.ref_id.hex()
    if ns.origin_unix is not None:
        spec["origin_unix"] = ns.origin_unix
        spec["origin_auto_now"] = False
    elif ns.origin_ntp_sec is not None:
        spec["origin_ntp"] = {"seconds": ns.origin_ntp_sec, "fraction": ns.origin_ntp_frac}
        spec["origin_auto_now"] = False
    else:
        spec["origin_auto_now"] = True
    return spec


def packet_from_namespace(ns: argparse.Namespace):
    return build_ntp_packet(namespace_to_spec(ns))
