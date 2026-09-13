"""Unit tests for the L2 E2E grandmaster (messages, config, scheduler, transport framing, master loop, E2E delay)."""

from __future__ import annotations

import struct
import time

import pytest

from ptp_client.ptp.constants import FLAG_TWO_STEP, FLAG_UNICAST, MessageType
from ptp_client.ptp.header import PTPHeader, PortIdentity
from ptp_client.ptp.packet import parse_delay_resp_body
from ptp_client.ptp.timestamp import PTPTimestamp

from ptp_client.ptp.l2master import constants as l2
from ptp_client.ptp.l2master.config import MasterConfig, config_from_dict, load_config
from ptp_client.ptp.l2master.master import PtpL2Master, clock_identity_from_mac
from ptp_client.ptp.l2master.messages import (
    AnnounceBody,
    ClockQuality,
    build_announce,
    build_delay_resp,
    build_follow_up,
    build_sync,
    parse_delay_req,
)
from ptp_client.ptp.l2master.scheduler import PeriodicScheduler, next_boundary
from ptp_client.ptp.l2master.session import SessionTable
from ptp_client.ptp.l2master.transport import ReceivedFrame, build_ethernet_frame


SRC = PortIdentity(bytes.fromhex("0011223344556677"), 1)


# ---------------- messages ----------------


def test_announce_layout_and_roundtrip():
    body = AnnounceBody(
        origin_timestamp=PTPTimestamp(1_700_000_000, 123_456_789),
        current_utc_offset=37,
        grandmaster_priority1=128,
        grandmaster_clock_quality=ClockQuality(6, 0x31, 0xFFFF),
        grandmaster_priority2=200,
        grandmaster_identity=SRC.clock_identity,
        steps_removed=0,
        time_source=0x48,
    )
    payload = build_announce(
        source=SRC,
        domain_number=43,
        body=body,
        sequence_id=7,
        log_announce_interval=-3,
    )
    assert len(payload) == l2.ANNOUNCE_MSG_LEN == 64
    assert struct.unpack_from("!H", payload, 2)[0] == 64  # messageLength
    assert payload[0] & 0xF == MessageType.ANNOUNCE
    assert payload[4] == 43  # domainNumber
    assert payload[32] == 0x05  # controlField
    assert struct.unpack_from("!b", payload, 33)[0] == -3  # logAnnounceInterval
    # body fields at design-doc offsets
    assert PTPTimestamp.unpack10(payload, 34) == body.origin_timestamp
    assert struct.unpack_from("!H", payload, 44)[0] == 37  # currentUtcOffset
    assert payload[46] == 0  # reserved
    assert payload[47] == 128  # priority1
    assert payload[48] == 6  # clockClass
    assert payload[49] == 0x31  # clockAccuracy
    assert struct.unpack_from("!H", payload, 50)[0] == 0xFFFF  # variance
    assert payload[52] == 200  # priority2
    assert payload[53:61] == SRC.clock_identity  # grandmasterIdentity
    assert struct.unpack_from("!H", payload, 61)[0] == 0  # stepsRemoved
    assert payload[63] == 0x48  # timeSource
    assert AnnounceBody.unpack(payload, 34) == body


def test_announce_default_flags():
    body = AnnounceBody(
        origin_timestamp=PTPTimestamp.zero(),
        current_utc_offset=0,
        grandmaster_priority1=128,
        grandmaster_clock_quality=ClockQuality(6, 0x31, 0xFFFF),
        grandmaster_priority2=128,
        grandmaster_identity=SRC.clock_identity,
        steps_removed=0,
        time_source=0x48,
    )
    payload = build_announce(
        source=SRC, domain_number=43, body=body, sequence_id=0, log_announce_interval=-3
    )
    flags = struct.unpack_from("!H", payload, 6)[0]
    assert flags == l2.ANNOUNCE_DEFAULT_FLAGS  # ptpTimescale|timeTraceable|freqTraceable in octet 1
    assert flags & (1 << 9) == 0  # no twoStep on Announce


def test_sync_and_follow_up():
    ts = PTPTimestamp(1_700_000_000, 500)
    sync = build_sync(
        source=SRC,
        domain_number=43,
        origin_timestamp=ts,
        sequence_id=0xFFFE,
        log_sync_interval=-4,
        two_step=True,
    )
    assert len(sync) == l2.SYNC_MSG_LEN == 44
    assert sync[0] & 0xF == MessageType.SYNC
    assert sync[32] == l2.CONTROL_SYNC
    assert struct.unpack_from("!H", sync, 6)[0] == FLAG_TWO_STEP
    assert struct.unpack_from("!H", sync, 30)[0] == 0xFFFE
    assert PTPTimestamp.unpack10(sync, 34) == ts

    fu = build_follow_up(
        source=SRC,
        domain_number=43,
        precise_origin_timestamp=ts,
        sequence_id=0xFFFE,
        log_sync_interval=-4,
    )
    assert len(fu) == l2.FOLLOW_UP_MSG_LEN == 44
    assert fu[0] & 0xF == MessageType.FOLLOW_UP
    assert fu[32] == l2.CONTROL_FOLLOW_UP
    # sequenceId must pair with the Sync
    assert struct.unpack_from("!H", fu, 30) == struct.unpack_from("!H", sync, 30)

    one_step = build_sync(
        source=SRC,
        domain_number=43,
        origin_timestamp=ts,
        sequence_id=1,
        log_sync_interval=0,
        two_step=False,
    )
    assert struct.unpack_from("!H", one_step, 6)[0] == 0


def test_sequence_id_wraps():
    seq = 0xFFFF
    seq = (seq + 1) & 0xFFFF
    assert seq == 0


# ---------------- config ----------------


def test_profile_defaults_g82751():
    cfg = config_from_dict({"profile": "g82751", "interface": "eth0"})
    assert cfg.domain_number == 43
    assert cfg.log_announce_interval == -3
    assert cfg.log_sync_interval == -4
    assert cfg.dst_mac == l2.G82751_PTP_MAC


def test_profile_defaults_1588v2():
    cfg = config_from_dict({"profile": "1588v2", "interface": "eth0"})
    assert cfg.domain_number == 0
    assert cfg.log_announce_interval == 0
    assert cfg.log_sync_interval == 0
    assert cfg.dst_mac == l2.IEEE1588_PTP_MAC


def test_explicit_values_not_overridden_by_profile():
    cfg = config_from_dict({"profile": "1588v2", "interface": "eth0", "domainNumber": 7, "logSyncInterval": -4})
    assert cfg.domain_number == 7
    assert cfg.log_sync_interval == -4


def test_validation_ranges():
    with pytest.raises(ValueError, match="domain_number"):
        config_from_dict({"profile": "g82751", "interface": "eth0", "domainNumber": 44})
    with pytest.raises(ValueError, match="log_sync_interval"):
        config_from_dict({"profile": "g82751", "interface": "eth0", "logSyncInterval": 0})
    with pytest.raises(ValueError, match="interface"):
        config_from_dict({"profile": "1588v2"})
    with pytest.raises(ValueError, match="clock_identity"):
        config_from_dict({"profile": "1588v2", "interface": "e", "clockIdentity": "FFFFFFFFFFFFFFFF"})


def test_load_jsonc_config_file():
    cfg = load_config("config/ptp-l2-master.json")
    assert cfg.profile == "g82751"
    assert cfg.domain_number == 43
    assert cfg.vlan_id is None


# ---------------- transport framing ----------------


def test_ethernet_frame_plain():
    frame = build_ethernet_frame(l2.G82751_PTP_MAC, bytes.fromhex("aabbccddeeff"), b"\x01\x02")
    assert frame[0:6] == l2.G82751_PTP_MAC
    assert frame[6:12] == bytes.fromhex("aabbccddeeff")
    assert struct.unpack_from("!H", frame, 12)[0] == l2.ETHERTYPE_PTP
    assert frame[14:] == b"\x01\x02"


def test_ethernet_frame_vlan():
    frame = build_ethernet_frame(
        l2.IEEE1588_PTP_MAC, bytes.fromhex("aabbccddeeff"), b"\x03", vlan_id=100, vlan_pcp=6
    )
    assert struct.unpack_from("!H", frame, 12)[0] == l2.ETHERTYPE_VLAN
    tci = struct.unpack_from("!H", frame, 14)[0]
    assert tci == (6 << 13) | 100
    assert struct.unpack_from("!H", frame, 16)[0] == l2.ETHERTYPE_PTP
    assert frame[18:] == b"\x03"


def test_clock_identity_from_mac():
    ci = clock_identity_from_mac(bytes.fromhex("00155d1e3baf"))
    assert ci == bytes.fromhex("00155dfffe1e3baf")


# ---------------- scheduler ----------------


def test_next_boundary_alignment():
    assert next_boundary(10.3, 1.0) == 11.0
    assert next_boundary(10.0, 0.125) == pytest.approx(10.125)


def test_scheduler_skips_stale_tick():
    s = PeriodicScheduler(0, 100.0)  # 1 s interval
    assert s.deadline == 101.0
    # Wake up 10 s late → more than half an interval past deadline → skipped.
    skipped = s.advance(111.0)
    assert skipped
    assert s.skipped == 1
    assert s.deadline == 112.0
    # Normal on-time advance.
    assert not s.advance(112.0)
    assert s.deadline == 113.0


# ---------------- master loop (fake transport) ----------------


class FakeTransport:
    def __init__(self) -> None:
        self.src_mac = bytes.fromhex("001122334455")
        self.frames: list[bytes] = []
        self.closed = False

    def open(self) -> None:
        pass

    def send(self, frame: bytes) -> None:
        self.frames.append(frame)

    def recv(self, timeout: float):
        # Mimic a blocking socket: park until the timeout instead of busy-looping
        # (a tight RX poll would starve the TX thread on the GIL).
        time.sleep(min(timeout, 0.05))
        return None

    def close(self) -> None:
        self.closed = True


def test_master_sends_announce_sync_followup(monkeypatch):
    import ptp_client.ptp.l2master.master as master_mod

    fake = FakeTransport()
    monkeypatch.setattr(master_mod, "open_transport", lambda iface, **_: fake)

    cfg = MasterConfig(
        interface="fake0",
        profile="1588v2",
        domain_number=0,
        log_announce_interval=-3,  # 125 ms (1588v2 range is -3..1)
        log_sync_interval=-7,  # 7.8 ms
        vlan_id=None,
    )
    m = PtpL2Master(cfg)
    m.start()
    try:
        time.sleep(0.3)
    finally:
        m.stop()
    st = m.get_stats()
    assert st.announce_sent >= 1
    assert st.sync_sent > 5
    assert st.follow_up_sent >= st.sync_sent - 1  # two-step: one Follow_Up per Sync (last tick may race stop)
    assert st.tx_errors == 0

    # Validate the first Sync/Follow_Up pair share sequenceId and use the right MAC.
    syncs = []
    fus = []
    for f in fake.frames:
        assert f[0:6] == cfg.dst_mac
        assert f[6:12] == fake.src_mac
        assert struct.unpack_from("!H", f, 12)[0] == l2.ETHERTYPE_PTP
        ptp = f[14:]
        mt = ptp[0] & 0xF
        if mt == MessageType.SYNC:
            syncs.append(ptp)
        elif mt == MessageType.FOLLOW_UP:
            fus.append(ptp)
        else:
            assert mt == MessageType.ANNOUNCE
    assert syncs and fus
    assert struct.unpack_from("!H", syncs[0], 30)[0] == struct.unpack_from("!H", fus[0], 30)[0]
    # Follow_Up preciseOriginTimestamp >= Sync originTimestamp (both from same clock).
    t_sync = PTPTimestamp.unpack10(syncs[0], 34)
    t_fu = PTPTimestamp.unpack10(fus[0], 34)
    assert (t_fu.seconds, t_fu.nanoseconds) >= (t_sync.seconds, t_sync.nanoseconds)
    assert fake.closed


def test_master_one_step_no_followup(monkeypatch):
    import ptp_client.ptp.l2master.master as master_mod

    fake = FakeTransport()
    monkeypatch.setattr(master_mod, "open_transport", lambda iface, **_: fake)
    cfg = MasterConfig(
        interface="fake0",
        profile="1588v2",
        log_announce_interval=-3,
        log_sync_interval=-7,
        two_step=False,
        vlan_id=None,
    )
    m = PtpL2Master(cfg)
    m.start()
    try:
        time.sleep(0.2)
    finally:
        m.stop()
    st = m.get_stats()
    assert st.sync_sent > 3
    assert st.follow_up_sent == 0


# ---------------- Delay_Req / Delay_Resp encoding ----------------


def _build_delay_req_payload(*, slave: PortIdentity, domain: int, seq: int, ts: PTPTimestamp) -> bytes:
    hdr = PTPHeader(
        message_type=int(MessageType.DELAY_REQ),
        version_ptp=2,
        message_length=l2.DELAY_REQ_MSG_LEN,
        domain_number=domain,
        minor_sdo_id=0,
        flags=0,
        correction_field_ns=0,
        source_identity=slave,
        sequence_id=seq,
        control_field=0x01,
        log_message_interval=0x7F,
        transport_specific=0,
    )
    return hdr.pack() + ts.pack10()


def test_parse_delay_req_roundtrip():
    slave = PortIdentity(bytes.fromhex("aabbccddeeff0011"), 2)
    ts = PTPTimestamp(1_700_000_000, 987_654_321)
    payload = _build_delay_req_payload(slave=slave, domain=43, seq=1234, ts=ts)
    assert len(payload) == l2.DELAY_REQ_MSG_LEN == 44
    req = parse_delay_req(payload)
    assert req.header.source_identity.clock_identity == slave.clock_identity
    assert req.header.source_identity.port_number == 2
    assert req.header.sequence_id == 1234
    assert req.header.domain_number == 43
    assert req.origin_timestamp == ts
    # Reject non-Delay_Req.
    with pytest.raises(ValueError, match="not a Delay_Req"):
        parse_delay_req(build_sync(source=slave, domain_number=43, origin_timestamp=ts, sequence_id=0, log_sync_interval=0, two_step=True))


def test_delay_resp_layout_and_fields():
    slave = PortIdentity(bytes.fromhex("aabbccddeeff0011"), 2)
    t2 = PTPTimestamp(1_700_000_000, 555_000_000)
    payload = build_delay_resp(
        source=SRC,
        domain_number=43,
        receive_timestamp=t2,
        requesting_port_identity=slave,
        sequence_id=777,
        unicast=True,
    )
    assert len(payload) == l2.DELAY_RESP_MSG_LEN == 54
    assert struct.unpack_from("!H", payload, 2)[0] == 54  # messageLength
    assert payload[0] & 0xF == MessageType.DELAY_RESP
    assert payload[4] == 43  # domainNumber
    assert payload[32] == 0x03  # controlField
    assert struct.unpack_from("!b", payload, 33)[0] == 0x7F  # logMessageInterval = -1 (NA)
    assert struct.unpack_from("!H", payload, 30)[0] == 777  # sequenceId echoes Delay_Req
    assert struct.unpack_from("!H", payload, 6)[0] == FLAG_UNICAST  # unicast flag
    # Body: receiveTimestamp at 34, requestingPortIdentity at 44.
    assert PTPTimestamp.unpack10(payload, 34) == t2
    assert payload[44:52] == slave.clock_identity
    assert struct.unpack_from("!H", payload, 52)[0] == slave.port_number
    # Cross-check against the shared packet.py decoder.
    hdr = PTPHeader.unpack(payload, 0)
    body = parse_delay_resp_body(payload, hdr)
    assert body.receive_timestamp == t2
    assert body.requesting_port_identity.clock_identity == slave.clock_identity
    assert body.requesting_port_identity.port_number == 2


def test_delay_resp_multicast_no_unicast_flag():
    slave = PortIdentity(bytes.fromhex("aabbccddeeff0011"), 1)
    payload = build_delay_resp(
        source=SRC,
        domain_number=0,
        receive_timestamp=PTPTimestamp.zero(),
        requesting_port_identity=slave,
        sequence_id=1,
        unicast=False,
    )
    assert struct.unpack_from("!H", payload, 6)[0] == 0


# ---------------- session table ----------------


def test_session_register_and_count():
    table = SessionTable(max_slaves=4, rate_limit_pps=0, session_timeout_sec=1.0)
    s1 = PortIdentity(bytes.fromhex("0000000000000001"), 1)
    s2 = PortIdentity(bytes.fromhex("0000000000000002"), 1)
    sess, allowed = table.register_or_touch(s1, b"\x01" * 6, now=100.0)
    assert allowed and sess is not None
    # Touch again refreshes and increments.
    sess2, allowed2 = table.register_or_touch(s1, b"\x02" * 6, now=100.5)
    assert allowed2 and sess2.delay_req_count == 2
    assert sess2.src_mac == b"\x02" * 6
    table.register_or_touch(s2, b"\x03" * 6, now=100.5)
    assert table.count() == 2
    snap = table.snapshot()
    assert {s.port_identity.clock_identity for s in snap} == {s1.clock_identity, s2.clock_identity}


def test_session_rate_limit_drops():
    # 1 pps: first allowed, immediate second dropped.
    table = SessionTable(max_slaves=4, rate_limit_pps=1.0, session_timeout_sec=10.0)
    sp = PortIdentity(bytes.fromhex("0000000000000009"), 1)
    _, a1 = table.register_or_touch(sp, b"\xaa" * 6, now=200.0)
    _, a2 = table.register_or_touch(sp, b"\xaa" * 6, now=200.01)
    assert a1 is True
    assert a2 is False
    # After enough time, tokens refill.
    _, a3 = table.register_or_touch(sp, b"\xaa" * 6, now=201.5)
    assert a3 is True


def test_session_overflow_evicts_oldest():
    table = SessionTable(max_slaves=2, rate_limit_pps=0, session_timeout_sec=100.0)
    a = PortIdentity(bytes.fromhex("000000000000000a"), 1)
    b = PortIdentity(bytes.fromhex("000000000000000b"), 1)
    c = PortIdentity(bytes.fromhex("000000000000000c"), 1)
    table.register_or_touch(a, b"\x01" * 6, now=300.0)
    table.register_or_touch(b, b"\x02" * 6, now=301.0)
    # Table full; adding c evicts the oldest (a).
    sess, allowed = table.register_or_touch(c, b"\x03" * 6, now=302.0)
    assert allowed and sess is not None
    ids = {s.port_identity.clock_identity for s in table.snapshot()}
    assert a.clock_identity not in ids
    assert b.clock_identity in ids and c.clock_identity in ids


def test_session_age_out():
    table = SessionTable(max_slaves=4, rate_limit_pps=0, session_timeout_sec=1.0)
    sp = PortIdentity(bytes.fromhex("00000000000000ff"), 1)
    table.register_or_touch(sp, b"\x01" * 6, now=500.0)
    assert table.age_out(now=500.5) == 0
    assert table.age_out(now=502.0) == 1
    assert table.count() == 0


# ---------------- full E2E flow: Delay_Req → Delay_Resp ----------------


class QueueTransport(FakeTransport):
    """Fake transport that can be fed inbound frames for the RX thread."""

    def __init__(self) -> None:
        super().__init__()
        self._inbox: list[ReceivedFrame] = []

    def feed(self, src_mac: bytes, payload: bytes, rx_realtime_ns: int) -> None:
        self._inbox.append(
            ReceivedFrame(
                src_mac=src_mac,
                ethertype=l2.ETHERTYPE_PTP,
                payload=payload,
                rx_realtime_ns=rx_realtime_ns,
                rx_monotonic_ns=rx_realtime_ns,
            )
        )

    def recv(self, timeout: float):
        if self._inbox:
            return self._inbox.pop(0)
        return super().recv(timeout)


def test_master_answers_delay_req_with_delay_resp(monkeypatch):
    import ptp_client.ptp.l2master.master as master_mod

    fake = QueueTransport()
    monkeypatch.setattr(master_mod, "open_transport", lambda iface, **_: fake)

    cfg = MasterConfig(
        interface="fake0",
        profile="g82751",
        domain_number=43,
        clock_identity=bytes.fromhex("0001020304050607"),
        log_announce_interval=-3,
        log_sync_interval=-4,
        vlan_id=None,
        delay_resp_unicast=True,
    )
    m = PtpL2Master(cfg)

    slave = PortIdentity(bytes.fromhex("aabbccddeeff0011"), 2)
    slave_mac = bytes.fromhex("deadc0de0001")
    t3 = PTPTimestamp(1_700_000_000, 111_000_000)
    req_payload = _build_delay_req_payload(slave=slave, domain=43, seq=9001, ts=t3)
    # t2 the master should echo back (ns).
    t2_ns = 1_700_000_000_500_000_000
    fake.feed(slave_mac, req_payload, t2_ns)

    m.start()
    try:
        # Wait for the RX/RESP threads to emit a Delay_Resp.
        deadline = time.monotonic() + 2.0
        resp = None
        while time.monotonic() < deadline:
            for f in fake.frames:
                ptp = f[14:]
                if len(ptp) >= 1 and (ptp[0] & 0xF) == MessageType.DELAY_RESP:
                    resp = (f, ptp)
                    break
            if resp:
                break
            time.sleep(0.02)
    finally:
        m.stop()

    assert resp is not None, "no Delay_Resp emitted"
    frame, ptp = resp
    st = m.get_stats()
    assert st.delay_req_recv >= 1
    assert st.delay_resp_sent >= 1
    assert st.tx_errors == 0

    # Unicast reply goes back to the slave's MAC.
    assert frame[0:6] == slave_mac
    assert frame[6:12] == fake.src_mac
    # sequenceId echoes the Delay_Req.
    assert struct.unpack_from("!H", ptp, 30)[0] == 9001
    # receiveTimestamp == t2 we fed in.
    echoed = PTPTimestamp.unpack10(ptp, 34)
    assert echoed.seconds == t2_ns // 1_000_000_000
    assert echoed.nanoseconds == t2_ns % 1_000_000_000
    # requestingPortIdentity echoes the slave.
    assert ptp[44:52] == slave.clock_identity
    assert struct.unpack_from("!H", ptp, 52)[0] == slave.port_number
    # Slave session recorded.
    slaves = m.list_slaves()
    assert any(s.port_identity.clock_identity == slave.clock_identity for s in slaves)


def test_master_ignores_wrong_domain_and_version(monkeypatch):
    import ptp_client.ptp.l2master.master as master_mod

    fake = QueueTransport()
    monkeypatch.setattr(master_mod, "open_transport", lambda iface, **_: fake)
    cfg = MasterConfig(
        interface="fake0",
        profile="g82751",
        domain_number=43,
        clock_identity=bytes.fromhex("0001020304050607"),
        log_announce_interval=-3,
        log_sync_interval=-4,
        vlan_id=None,
    )
    m = PtpL2Master(cfg)

    slave = PortIdentity(bytes.fromhex("aabbccddeeff0011"), 1)
    ts = PTPTimestamp(1_700_000_000, 0)
    # Wrong domain (44) → ignored.
    fake.feed(bytes.fromhex("deadc0de0002"), _build_delay_req_payload(slave=slave, domain=44, seq=1, ts=ts), 1_700_000_000_000_000_000)
    # Correct domain but a Sync (other type) → ignored.
    sync_payload = build_sync(source=slave, domain_number=43, origin_timestamp=ts, sequence_id=2, log_sync_interval=0, two_step=True)
    fake.feed(bytes.fromhex("deadc0de0003"), sync_payload, 1_700_000_000_000_000_000)

    m.start()
    try:
        time.sleep(0.4)
    finally:
        m.stop()
    st = m.get_stats()
    assert st.rx_other_domain >= 1
    assert st.rx_other_type >= 1
    assert st.delay_resp_sent == 0
    assert st.delay_req_recv == 0
