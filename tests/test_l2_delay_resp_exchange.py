"""模拟下游 Slave（ptp4l）发送二层 Delay_Req，验证 Master 回复的 Delay_Resp 报文。

与 test_l2_master.py 中直接喂 PTP payload 的测试不同，本文件构造的是
Slave 在网线上实际发出的完整以太网帧（DstMAC + EtherType 0x88F7 + PTP），
经过与线上一致的 _parse_ethernet_frame 解码路径进入 RX 线程，从而覆盖：
  以太网封装 → PTP 头过滤 → t2 打戳 → 会话登记 → Delay_Resp 组包 → 回帧
"""

from __future__ import annotations

import struct
import time
from collections import deque

from ptp_client.ptp.constants import FLAG_UNICAST, MessageType
from ptp_client.ptp.header import PTPHeader, PortIdentity
from ptp_client.ptp.packet import parse_delay_resp_body
from ptp_client.ptp.timestamp import PTPTimestamp

from ptp_client.ptp.l2master import constants as l2
from ptp_client.ptp.l2master.config import MasterConfig
from ptp_client.ptp.l2master.master import PtpL2Master
from ptp_client.ptp.l2master.transport import ReceivedFrame, build_ethernet_frame


# ---------------- 下游 Slave 模拟器 ----------------


class FakeWire:
    """模拟一段共享 L2 链路：slave 写入原始以太帧，master 的 transport 读出。

    recv() 走与 Linux/Windows 真实传输层完全相同的 _parse_ethernet_frame
    解码逻辑（含 t2 打戳），delivered 记录投递给 RX 线程的帧，供断言 t2。
    """

    def __init__(self, master_mac: bytes) -> None:
        self.src_mac = master_mac
        self.frames_out: list[bytes] = []  # master 发出的帧
        self._inbox: deque[bytes] = deque()
        self.delivered: list[ReceivedFrame] = []
        self.closed = False

    # transport 接口
    def open(self) -> None:
        pass

    def send(self, frame: bytes) -> None:
        self.frames_out.append(frame)

    def recv(self, timeout: float):  # noqa: ARG002
        if self._inbox:
            frame = _parse(self._inbox.popleft())
            if frame is not None:
                self.delivered.append(frame)
            return frame
        time.sleep(0.01)  # 模拟阻塞 socket，避免空转抢 GIL
        return None

    def close(self) -> None:
        self.closed = True

    # 测试用：slave 侧发送
    def slave_sends(self, raw_frame: bytes) -> None:
        self._inbox.append(raw_frame)


def _parse(raw: bytes):
    # 复用生产代码的帧解码（避免在测试里重写一遍，保证解码路径一致）
    from ptp_client.ptp.l2master.transport import _parse_ethernet_frame

    return _parse_ethernet_frame(raw)


def slave_delay_req_frame(
    *,
    slave_mac: bytes,
    slave_port: PortIdentity,
    domain: int,
    sequence_id: int,
    t3: PTPTimestamp,
    dst_mac: bytes = l2.IEEE1588_PTP_MAC,
) -> bytes:
    """构造下游 Slave 实际发出的完整 Delay_Req 以太帧（44B PTP + 14B 以太头）。"""
    hdr = PTPHeader(
        message_type=int(MessageType.DELAY_REQ),
        version_ptp=2,
        message_length=l2.DELAY_REQ_MSG_LEN,
        domain_number=domain,
        minor_sdo_id=0,
        flags=0,  # ptp4l 的 E2E Delay_Req：组播、非两步标志
        correction_field_ns=0,
        source_identity=slave_port,
        sequence_id=sequence_id,
        control_field=0x01,
        log_message_interval=0x7F,
        transport_specific=0,
    )
    payload = hdr.pack() + t3.pack10()
    return build_ethernet_frame(dst_mac, slave_mac, payload)


def _wait_for_responses(wire: FakeWire, count: int, timeout: float = 3.0) -> list[bytes]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        resps = [f for f in wire.frames_out if f[14] & 0xF == MessageType.DELAY_RESP]
        if len(resps) >= count:
            return resps[:count]
        time.sleep(0.01)
    raise AssertionError(f"超时：期望 {count} 个 Delay_Resp，实际 {_count_resp(wire)} 个")


def _count_resp(wire: FakeWire) -> int:
    return sum(1 for f in wire.frames_out if f[14] & 0xF == MessageType.DELAY_RESP)


def _start_master(monkeypatch, wire: FakeWire, **overrides) -> tuple[PtpL2Master, MasterConfig]:
    import ptp_client.ptp.l2master.master as master_mod

    monkeypatch.setattr(master_mod, "open_transport", lambda iface: wire)
    cfg_kwargs = dict(
        interface="fake0",
        profile="g82751",
        domain_number=43,
        clock_identity=bytes.fromhex("0001020304050607"),  # 与 ptp4l 联调时显式指定的 GM 标识
        log_announce_interval=-3,
        log_sync_interval=-4,
        vlan_id=None,
        dst_mac=l2.IEEE1588_PTP_MAC,  # 与 scripts/wsl ptp4l 联调一致
        delay_resp_unicast=False,
    )
    cfg_kwargs.update(overrides)
    cfg = MasterConfig(**cfg_kwargs)
    master = PtpL2Master(cfg)
    master.start()
    return master, cfg


# ---------------- 测试用例 ----------------


def test_slave_delay_req_gets_correct_delay_resp(monkeypatch):
    """主用例：下游 ptp4l 风格 Slave 连发两个 Delay_Req，逐字段验证两个 Delay_Resp。"""
    wire = FakeWire(master_mac=bytes.fromhex("00051d112233"))
    master, cfg = _start_master(monkeypatch, wire)

    slave_mac = bytes.fromhex("0ca3e2b1c0d4")
    slave_port = PortIdentity(bytes.fromhex("0ca3e2fffeb1c0d4"), 1)
    t3_values = [PTPTimestamp(1_760_000_000, 100_000_000), PTPTimestamp(1_760_000_000, 200_000_000)]

    try:
        for seq, t3 in ((100, t3_values[0]), (101, t3_values[1])):
            wire.slave_sends(
                slave_delay_req_frame(
                    slave_mac=slave_mac, slave_port=slave_port, domain=43, sequence_id=seq, t3=t3
                )
            )
        resps = _wait_for_responses(wire, 2)
    finally:
        master.stop()

    assert wire.closed
    st = master.get_stats()
    assert st.delay_req_recv == 2
    assert st.delay_resp_sent == 2
    assert st.tx_errors == 0
    assert st.rx_bad_version == 0 and st.rx_other_domain == 0 and st.rx_parse_errors == 0

    for i, frame in enumerate(resps):
        seq = 100 + i
        ptp = frame[14:]

        # ---- 以太网封装（组播回发）----
        assert len(frame) == 14 + l2.DELAY_RESP_MSG_LEN  # 14 + 54 = 68
        assert frame[0:6] == cfg.dst_mac == l2.IEEE1588_PTP_MAC  # 组播回发
        assert frame[6:12] == wire.src_mac  # 源 MAC = master 网卡
        assert struct.unpack_from("!H", frame, 12)[0] == l2.ETHERTYPE_PTP

        # ---- PTP 公共头（设计文档 §4.1 / §4.5）----
        assert ptp[0] & 0xF == MessageType.DELAY_RESP  # messageType=0x9
        assert (ptp[0] >> 4) & 0xF == 0  # transportSpecific=0
        assert ptp[1] & 0xF == 2  # versionPTP=2
        assert struct.unpack_from("!H", ptp, 2)[0] == 54  # messageLength
        assert ptp[4] == 43  # domainNumber
        assert struct.unpack_from("!H", ptp, 6)[0] == 0  # 组播：无 unicast/twoStep 标志
        assert struct.unpack_from("!q", ptp, 8)[0] == 0  # correctionField=0
        assert ptp[20:28] == cfg.clock_identity  # sourcePortIdentity = GM
        assert struct.unpack_from("!H", ptp, 28)[0] == 1  # GM portNumber
        assert struct.unpack_from("!H", ptp, 30)[0] == seq  # sequenceId 必须与请求配对
        assert ptp[32] == l2.CONTROL_DELAY_RESP  # controlField=0x3
        assert struct.unpack_from("!b", ptp, 33)[0] == l2.LOG_MSG_INTERVAL_NA  # 0x7F

        # ---- body（设计文档 §4.5）----
        hdr = PTPHeader.unpack(ptp, 0)
        body = parse_delay_resp_body(ptp, hdr)  # 与仓库通用解码器交叉验证
        # t2 = master 收到该请求帧的接收时刻（与投递给 RX 线程的帧严格一致）
        assert body.receive_timestamp.pack10() == _t2(wire, i)
        # t2 必须是收到的时刻，而不是回显 slave 的 t3
        assert body.receive_timestamp != t3_values[i]
        # requestingPortIdentity 原样回填，slave 靠它认领应答
        assert body.requesting_port_identity.clock_identity == slave_port.clock_identity
        assert body.requesting_port_identity.port_number == 1

    # ---- 会话表：一个 Slave、2 次请求、2 次应答 ----
    slaves = master.list_slaves()
    assert len(slaves) == 1
    sess = slaves[0]
    assert sess.port_identity.clock_identity == slave_port.clock_identity
    assert sess.src_mac == slave_mac
    assert sess.delay_req_count == 2
    assert sess.delay_resp_sent == 2
    assert sess.delay_resp_dropped == 0


def test_delay_resp_unicast_mode_goes_back_to_slave_mac(monkeypatch):
    """delayRespUnicast=true 时：目的 MAC = Slave MAC，且 unicastFlag 置位。"""
    wire = FakeWire(master_mac=bytes.fromhex("00051d112233"))
    master, cfg = _start_master(monkeypatch, wire, delay_resp_unicast=True)

    slave_mac = bytes.fromhex("0ca3e2b1c0d5")
    slave_port = PortIdentity(bytes.fromhex("aabbccddeeff0022"), 1)
    try:
        wire.slave_sends(
            slave_delay_req_frame(
                slave_mac=slave_mac,
                slave_port=slave_port,
                domain=43,
                sequence_id=7,
                t3=PTPTimestamp(1_760_000_001, 1),
            )
        )
        (frame,) = _wait_for_responses(wire, 1)
    finally:
        master.stop()

    assert frame[0:6] == slave_mac  # 单播回给请求者
    hdr = PTPHeader.unpack(frame[14:], 0)
    assert hdr.flags & FLAG_UNICAST


def test_two_slaves_each_get_their_own_response(monkeypatch):
    """两个下游 Slave 同时发 Delay_Req：应答中的 requestingPortIdentity 不得串号。"""
    wire = FakeWire(master_mac=bytes.fromhex("00051d112233"))
    master, _ = _start_master(monkeypatch, wire)

    slave_a = (bytes.fromhex("0ca3e2b1c0d6"), PortIdentity(bytes.fromhex("aaaaaaaaaaaa0001"), 1))
    slave_b = (bytes.fromhex("0ca3e2b1c0d7"), PortIdentity(bytes.fromhex("bbbbbbbbbbbb0002"), 2))
    try:
        wire.slave_sends(slave_delay_req_frame(slave_mac=slave_a[0], slave_port=slave_a[1], domain=43, sequence_id=1, t3=PTPTimestamp(1_760_000_002, 10)))
        wire.slave_sends(slave_delay_req_frame(slave_mac=slave_b[0], slave_port=slave_b[1], domain=43, sequence_id=9, t3=PTPTimestamp(1_760_000_002, 20)))
        resps = _wait_for_responses(wire, 2)
    finally:
        master.stop()

    # 按 sequenceId 找到每个 slave 的应答，验证请求者身份回填正确
    by_seq = {struct.unpack_from("!H", f[14:], 30)[0]: f for f in resps}
    for seq, port in ((1, slave_a[1]), (9, slave_b[1])):
        body = parse_delay_resp_body(by_seq[seq][14:], PTPHeader.unpack(by_seq[seq][14:], 0))
        assert body.requesting_port_identity.clock_identity == port.clock_identity
        assert body.requesting_port_identity.port_number == port.port_number
    assert {s.port_identity.clock_identity for s in master.list_slaves()} == {
        slave_a[1].clock_identity,
        slave_b[1].clock_identity,
    }


def test_delay_req_from_other_domain_is_not_answered(monkeypatch):
    """域号不匹配的 Delay_Req 必须被静默丢弃，不回 Delay_Resp（设计文档 §5.4 第 4 步）。"""
    wire = FakeWire(master_mac=bytes.fromhex("00051d112233"))
    master, _ = _start_master(monkeypatch, wire)

    foreign = PortIdentity(bytes.fromhex("cccccccccccc0003"), 1)
    try:
        wire.slave_sends(
            slave_delay_req_frame(
                slave_mac=bytes.fromhex("0ca3e2b1c0d8"),
                slave_port=foreign,
                domain=0,  # 其他域（1588v2 默认域）
                sequence_id=1,
                t3=PTPTimestamp(1_760_000_003, 0),
            )
        )
        time.sleep(0.3)
    finally:
        master.stop()

    assert _count_resp(wire) == 0
    st = master.get_stats()
    assert st.rx_other_domain >= 1
    assert st.delay_req_recv == 0
    assert master.list_slaves() == []


def _t2(wire: FakeWire, index: int) -> bytes:
    """master 打在应答里的 t2 应当等于第 index 个投递给 RX 线程的帧的接收时间戳。"""
    ns = wire.delivered[index].rx_realtime_ns
    return PTPTimestamp(seconds=ns // 1_000_000_000, nanoseconds=ns % 1_000_000_000).pack10()
