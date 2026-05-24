from argparse import Namespace

from ptp_client.ptp.constants import FLAG_UNICAST
from ptp_client.ptp.delay_request import (
    build_delay_request_spec,
    delay_request_interval_from_namespace,
    delay_request_spec_from_namespace,
    parse_delay_request_interval_sec,
)
from ptp_client.ptp.request_builder import build_ptp_udp_payload


def test_build_delay_request_spec_from_config_camel_case() -> None:
    spec = build_delay_request_spec(
        {
            "flags": 1024,
            "correctionFieldNs": 0,
            "originTimestamp": {"seconds": 0, "nanoseconds": 0},
        },
        domain_number=44,
        clock_identity="0001020304050607",
        port_number=1,
    )
    assert spec["domain_number"] == 44
    assert spec["flags"] == FLAG_UNICAST
    assert spec["log_message_interval"] == -127
    payload = build_ptp_udp_payload(spec)
    assert len(payload) == 44


def test_request_interval_sec_not_in_wire_spec() -> None:
    spec = build_delay_request_spec(
        {"requestIntervalSec": 1.0, "logPeriod": 0},
        domain_number=44,
        clock_identity="0001020304050607",
        port_number=1,
    )
    assert spec["log_message_interval"] == -127


def test_parse_delay_request_interval_sec() -> None:
    assert parse_delay_request_interval_sec({"requestIntervalSec": 1.0}) == 1.0
    assert parse_delay_request_interval_sec({"requestIntervalSec": 0}) is None
    assert parse_delay_request_interval_sec({}) is None


def test_delay_request_interval_from_namespace() -> None:
    assert delay_request_interval_from_namespace(Namespace(delay_req_interval=2.5)) == 2.5
    assert delay_request_interval_from_namespace(Namespace(delay_req_interval=0)) is None
    assert delay_request_interval_from_namespace(Namespace()) is None


def test_delay_request_spec_from_namespace_overrides() -> None:
    ns = Namespace(
        delay_req_flags=0x400,
        delay_req_correction_ns=100,
        delay_req_origin_sec=1,
        delay_req_origin_ns=500,
        clock_identity="0001020304050607",
        port_number=1,
    )
    spec = delay_request_spec_from_namespace(
        ns,
        domain_number=44,
        clock_identity="aabbccddeeff0011",
        port_number=2,
        default_flags=0,
    )
    assert spec["flags"] == 0x400
    assert spec["correction_field_ns"] == 100
    assert spec["origin_timestamp"] == {"seconds": 1, "nanoseconds": 500}
    assert spec["clock_identity"] == "0001020304050607"
