"""Web「Master 模式」页按钮与报文字段注入测试。

覆盖页面 4 个入口（启动 / 停止 / 网卡列表 / 参数校验）背后的处理函数，
并逐字节断言：页面上每一个可配置项都会真正出现在 master 发出的
Announce / Sync / Follow_Up / Delay_Resp 报文（含以太网/VLAN 封装）中。

用假 L2 传输层替换真实网卡，不依赖 Npcap/AF_PACKET。
"""

from __future__ import annotations

import shutil
import struct
import subprocess
import time
from collections import deque
from pathlib import Path

import pytest

from ptp_client.ptp.constants import FLAG_TWO_STEP, FLAG_UNICAST, MessageType
from ptp_client.ptp.header import PTPHeader, PortIdentity
from ptp_client.ptp.timestamp import PTPTimestamp
from ptp_client.ptp.l2master import constants as l2
from ptp_client.ptp.l2master.transport import ReceivedFrame, build_ethernet_frame
from ptp_client.web import l2_master_lab
from ptp_client.web.l2_master_lab import (
    poll_l2_master_lab,
    start_l2_master_lab,
    stop_l2_master_lab,
    update_l2_master_lab,
)


# ---------------- 假 L2 链路 ----------------


class FakeWire:
    def __init__(self) -> None:
        self.src_mac = bytes.fromhex("00051d95ec41")
        self.frames_out: list[bytes] = []
        self._inbox: deque[bytes] = deque()
        self.delivered: list[ReceivedFrame] = []
        self.closed = False

    def open(self) -> None:
        pass

    def send(self, frame: bytes) -> None:
        self.frames_out.append(frame)

    def recv(self, timeout: float):
        if self._inbox:
            from ptp_client.ptp.l2master.transport import _parse_ethernet_frame

            frame = _parse_ethernet_frame(self._inbox.popleft())
            if frame is not None:
                self.delivered.append(frame)
            return frame
        time.sleep(min(timeout, 0.02))
        return None

    def close(self) -> None:
        self.closed = True

    def feed_delay_req(
        self, *, slave_ci: bytes = b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8", slave_port: int = 1,
        slave_mac: bytes = bytes.fromhex("0ca3e2b1c0d4"), domain: int = 43, seq: int = 1,
    ) -> None:
        hdr = PTPHeader(
            message_type=int(MessageType.DELAY_REQ), version_ptp=2, message_length=44,
            domain_number=domain, minor_sdo_id=0, flags=0, correction_field_ns=0,
            source_identity=PortIdentity(slave_ci, slave_port), sequence_id=seq,
            control_field=1, log_message_interval=0x7F, transport_specific=0,
        )
        payload = hdr.pack() + PTPTimestamp(1_760_000_000, 1).pack10()
        self._inbox.append(build_ethernet_frame(l2.IEEE1588_PTP_MAC, slave_mac, payload))


@pytest.fixture
def wires(monkeypatch):
    fake_wires: list[FakeWire] = []

    def _factory(iface, **kwargs):  # noqa: ANN001
        w = FakeWire()
        fake_wires.append(w)
        return w

    monkeypatch.setattr("ptp_client.ptp.l2master.master.open_transport", _factory)
    yield fake_wires
    stop_l2_master_lab()  # 保证每个用例结束后后台线程退出、全局会话清空


def _start(**overrides) -> dict:
    body: dict = {
        "interface": "fake0",
        "profile": "g82751",
        "clockIdentity": "0001020304050607",
        "dstMac": "01-1B-19-00-00-00",
    }
    body.update(overrides)
    return start_l2_master_lab(body)


def _ptp_offset(frame: bytes) -> int:
    # 802.1Q tag 占 4 字节：dst(6) src(6) 0x8100(2) TCI(2) ethertype(2)
    return 18 if len(frame) >= 14 and struct.unpack_from("!H", frame, 12)[0] == 0x8100 else 14


def _frames_of_type(wire: FakeWire, mt: int) -> list[bytes]:
    return [f for f in wire.frames_out if len(f) >= 15 and (f[_ptp_offset(f)] & 0xF) == mt]


def _wait_for(wire: FakeWire, mt: int, count: int = 1, timeout: float = 2.0) -> list[bytes]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        got = _frames_of_type(wire, mt)
        if len(got) >= count:
            return got[:count]
        time.sleep(0.01)
    raise AssertionError(f"等待 messageType={mt} x{count} 超时，实际 {len(_frames_of_type(wire, mt))}")


# ================= 按钮 1：启动 / 轮询 / 停止 =================


def test_start_button_runs_and_poll_shows_counters(wires):
    info = _start(logAnnounceInterval=-3, logSyncInterval=-4)
    assert info["state"] in ("LISTENING", "ACTIVE")
    assert info["config"]["profile"] == "g82751"
    assert info["src_mac"] == "00:05:1d:95:ec:41"

    wire = wires[0]
    _wait_for(wire, int(MessageType.ANNOUNCE))
    _wait_for(wire, int(MessageType.FOLLOW_UP))

    polled = poll_l2_master_lab(0)
    assert polled["status"] == "running"
    assert polled["state"] == "ACTIVE"
    assert polled["stats"]["announce_sent"] >= 1
    assert polled["stats"]["sync_sent"] >= 1
    assert polled["stats"]["follow_up_sent"] >= 1
    # 实时报文列表里的摘要可被前端直接渲染
    names = {m["summary"]["message_type_name"] for m in polled["messages"]}
    assert {"ANNOUNCE", "SYNC", "FOLLOW_UP"}.issubset(names)

    stop_l2_master_lab()
    assert poll_l2_master_lab()["status"] == "stopped"
    assert wire.closed  # 停止按钮真正关闭了传输层


def test_stop_button_without_run_is_idempotent():
    # 没有运行中的 master 时点停止：不报错、返回 stopping=False
    assert stop_l2_master_lab() == {"stopping": False}


def test_start_again_replaces_previous_run(wires):
    first = _start(logAnnounceInterval=-3)
    _wait_for(wires[0], int(MessageType.ANNOUNCE))
    second = _start(logAnnounceInterval=-3, domainNumber=24)
    assert first["run_id"] != second["run_id"]
    assert wires[0].closed  # 前一个实例被替换时关闭
    _wait_for(wires[1], int(MessageType.ANNOUNCE))
    polled = poll_l2_master_lab(0)
    assert polled["config"]["domain_number"] == 24


# ================= 按钮 2：参数校验（页面弹错来源） =================


def test_empty_interface_rejected():
    with pytest.raises(ValueError, match="interface"):
        start_l2_master_lab({"interface": "   ", "profile": "g82751"})


def test_pydantic_model_requires_interface():
    # 对应 HTTP 422：L2MasterStartModel.interface 是必填非空字符串
    from pydantic import ValidationError

    from ptp_client.web.app import L2MasterStartModel

    with pytest.raises(ValidationError):
        L2MasterStartModel.model_validate({"interface": ""})
    m = L2MasterStartModel.model_validate({"interface": "eth0"})
    assert m.profile == "g82751" and m.domainNumber is None  # None 时走 profile 默认


def test_out_of_range_domain_rejected():
    # G.8275.1 允许 domain 24..43，越界必须在启动时被拒绝（页面显示 400 错误）
    with pytest.raises(ValueError, match="domain_number"):
        _start(domainNumber=100)


def test_interfaces_button_returns_list():
    # 网卡列表按钮：Windows 走 Npcap、Linux 走 /sys/class/net；至少不崩溃
    items = l2_master_lab.list_interfaces()
    assert isinstance(items, list)
    for it in items:
        assert "name" in it and "description" in it


# ================= Announce 报文字段注入 =================


def test_every_announce_field_is_injected(wires):
    custom_ci = bytes.fromhex("abcdef0123456789")
    _start(
        domainNumber=37,
        clockIdentity=custom_ci.hex(),
        portNumber=0x1234,
        transportSpecific=5,
        vlanId=100,
        vlanPcp=6,
        dstMac="01-0C-CD-01-00-66",
        # Announce 专属
        logAnnounceInterval=-1,
        announceReceiptTimeout=7,
        currentUtcOffset=37,
        priority1=200,
        priority2=100,
        clockClass=7,
        clockAccuracy=0x20,
        offsetScaledLogVariance=0x1234,
        timeSource=0xA0,
    )
    frame = _wait_for(wires[0], int(MessageType.ANNOUNCE))[0]

    # ---- 以太网 / VLAN 封装 ----
    assert frame[0:6] == bytes.fromhex("010CCD010066")  # dstMac 注入
    assert frame[6:12] == wires[0].src_mac
    assert struct.unpack_from("!H", frame, 12)[0] == 0x8100  # 802.1Q tag 注入
    tci = struct.unpack_from("!H", frame, 14)[0]
    assert (tci >> 13) & 0x7 == 6 and (tci & 0xFFF) == 100  # PCP + VID
    assert struct.unpack_from("!H", frame, 16)[0] == 0x88F7
    p = frame[18:]  # VLAN 帧的 PTP 载荷起点

    # ---- 公共头 ----
    assert (p[0] >> 4) & 0xF == 5  # transportSpecific 注入
    assert p[0] & 0xF == MessageType.ANNOUNCE
    assert p[1] & 0xF == 2
    assert struct.unpack_from("!H", p, 2)[0] == 64  # Announce 固定 64 字节
    assert p[4] == 37  # domainNumber
    assert p[20:28] == custom_ci  # source clockIdentity
    assert struct.unpack_from("!H", p, 28)[0] == 0x1234  # portNumber
    assert struct.unpack_from("b", p, 33)[0] == -1  # logAnnounceInterval（有符号）
    assert p[32] == 0x5  # controlField=Announce

    # ---- Announce body（header=34B）----
    assert struct.unpack_from("!H", p, 44)[0] == 37  # currentUtcOffset
    assert p[47] == 200  # grandmasterPriority1
    assert p[48] == 7  # clockClass
    assert p[49] == 0x20  # clockAccuracy
    assert struct.unpack_from("!H", p, 50)[0] == 0x1234  # offsetScaledLogVariance
    assert p[52] == 100  # grandmasterPriority2
    assert p[53:61] == custom_ci  # grandmasterIdentity（E2E GM 与 source 相同）
    assert struct.unpack_from("!H", p, 61)[0] == 0  # stepsRemoved
    assert p[63] == 0xA0  # timeSource

    # announceReceiptTimeout 不进报文，但必须进会话老化配置（影响运行期行为）
    polled = poll_l2_master_lab(0)
    assert polled["config"]["clock_class"] == 7
    # 前端拿到的 Announce 摘要中必须能看到注入的 GM 字段
    an = next(m["summary"] for m in polled["messages"] if m["summary"]["message_type_name"] == "ANNOUNCE")
    assert an["body"]["grandmaster_priority1"] == 200
    assert an["body"]["grandmaster_clock_quality"]["clock_accuracy"] == 0x20
    assert an["body"]["current_utc_offset"] == 37


# ================= Sync / Follow_Up 字段注入 =================


def test_sync_and_follow_up_fields_are_injected(wires):
    _start(logSyncInterval=-5, twoStep=True)
    wire = wires[0]
    sync = _wait_for(wire, int(MessageType.SYNC))[0][14:]
    fu = _wait_for(wire, int(MessageType.FOLLOW_UP))[0][14:]

    assert struct.unpack_from("!b", sync, 33)[0] == -5  # logSyncInterval
    assert sync[32] == 0x0  # controlField=Sync
    assert struct.unpack_from("!H", sync, 6)[0] & FLAG_TWO_STEP  # 两步标志
    assert struct.unpack_from("!H", sync, 2)[0] == 44

    assert fu[0] & 0xF == MessageType.FOLLOW_UP
    assert fu[32] == 0x2  # controlField=Follow_Up
    assert struct.unpack_from("!b", fu, 33)[0] == -5  # Follow_Up 携带相同 interval
    assert struct.unpack_from("!H", fu, 2)[0] == 44
    # 同序号配对
    syncs = _frames_of_type(wire, int(MessageType.SYNC))
    fus = _frames_of_type(wire, int(MessageType.FOLLOW_UP))
    paired = {struct.unpack_from("!H", f[14:], 30)[0] for f in syncs}
    assert {struct.unpack_from("!H", f[14:], 30)[0] for f in fus} & paired


def test_one_step_switch_removes_follow_up(wires):
    # 页面对应「时间戳模式」开关：一步法 → 不发 Follow_Up
    _start(logSyncInterval=-3, twoStep=False)
    _wait_for(wires[0], int(MessageType.SYNC), count=3)
    time.sleep(0.15)
    assert _frames_of_type(wires[0], int(MessageType.FOLLOW_UP)) == []
    sync = _frames_of_type(wires[0], int(MessageType.SYNC))[0][14:]
    assert not (struct.unpack_from("!H", sync, 6)[0] & FLAG_TWO_STEP)
    assert poll_l2_master_lab()["stats"]["follow_up_sent"] == 0


# ================= Delay_Resp 字段注入 =================


def test_delay_resp_unicast_switch_is_injected(wires):
    _start(delayRespUnicast=True)
    wire = wires[0]
    _wait_for(wire, int(MessageType.SYNC))
    wire.feed_delay_req(seq=4242)

    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and not _frames_of_type(wire, int(MessageType.DELAY_RESP)):
        time.sleep(0.01)
    frame = _frames_of_type(wire, int(MessageType.DELAY_RESP))[0]
    p = frame[14:]

    assert frame[0:6] == bytes.fromhex("0ca3e2b1c0d4")  # 单播回给 Slave MAC
    assert struct.unpack_from("!H", p, 6)[0] & FLAG_UNICAST  # unicastFlag
    assert struct.unpack_from("!H", p, 30)[0] == 4242  # sequenceId 配对
    assert p[44:52] == b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8"  # requestingPortIdentity
    assert struct.unpack_from("!H", p, 52)[0] == 1
    assert p[32] == 0x3 and struct.unpack_from("!b", p, 33)[0] == 0x7F
    # t2 = 接收时刻（48bit 秒 + 32bit 纳秒），而非回显请求里的 t3
    t2_sec = int.from_bytes(p[34:40], "big")
    assert abs(t2_sec - time.time()) < 30

    polled = poll_l2_master_lab(0)
    assert polled["slaves"][0]["delay_resp_sent"] == 1
    assert polled["slaves"][0]["src_mac"] == "0c:a3:e2:b1:c0:d4"


def test_delay_resp_multicast_default(wires):
    _start(delayRespUnicast=False, dstMac="01-1B-19-00-00-00")
    wire = wires[0]
    _wait_for(wire, int(MessageType.SYNC))
    wire.feed_delay_req(seq=9)
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and not _frames_of_type(wire, int(MessageType.DELAY_RESP)):
        time.sleep(0.01)
    frame = _frames_of_type(wire, int(MessageType.DELAY_RESP))[0]
    assert frame[0:6] == bytes.fromhex("011b19000000")  # 组播回发
    assert struct.unpack_from("!H", frame[14:], 6)[0] & FLAG_UNICAST == 0


def test_rate_limit_field_is_injected(wires):
    # 1 pps：同一 Slave 立刻发两个 Delay_Req，第二个必须被丢弃（页面「限速」输入生效）
    _start(delayRespRateLimit=1, delayRespUnicast=True)
    wire = wires[0]
    _wait_for(wire, int(MessageType.SYNC))
    wire.feed_delay_req(seq=1)
    wire.feed_delay_req(seq=2)
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        st = poll_l2_master_lab()["stats"]
        if st["delay_req_recv"] >= 2 and st["delay_resp_sent"] + st["delay_resp_dropped"] >= 2:
            break
        time.sleep(0.01)
    st = poll_l2_master_lab()["stats"]
    assert st["delay_req_recv"] == 2
    assert st["delay_resp_sent"] == 1
    assert st["delay_resp_dropped"] == 1
    assert len(_frames_of_type(wire, int(MessageType.DELAY_RESP))) == 1


def test_delay_req_from_other_domain_not_answered(wires):
    _start(domainNumber=43)
    wire = wires[0]
    _wait_for(wire, int(MessageType.SYNC))
    wire.feed_delay_req(domain=0, seq=1)  # 其他域
    time.sleep(0.3)
    assert _frames_of_type(wire, int(MessageType.DELAY_RESP)) == []
    st = poll_l2_master_lab()["stats"]
    assert st["rx_other_domain"] >= 1 and st["delay_req_recv"] == 0


# ================= profile 子项切换 =================


def test_1588v2_profile_defaults_injected(wires):
    # 页面选 1588v2 且不覆盖任何可选字段：domain 0、组播 MAC 01-1B、interval=0
    start_l2_master_lab({"interface": "fake0", "profile": "1588v2", "clockIdentity": "0001020304050607"})
    frame = _wait_for(wires[0], int(MessageType.ANNOUNCE))[0]
    assert frame[0:6] == bytes.fromhex("011b19000000")  # 1588v2 默认目的 MAC
    p = frame[14:]
    assert p[4] == 0
    assert struct.unpack_from("!b", p, 33)[0] == 0
    sync = _wait_for(wires[0], int(MessageType.SYNC))[0][14:]
    assert struct.unpack_from("!b", sync, 33)[0] == 0
    assert poll_l2_master_lab()["config"]["domain_number"] == 0


# ================= 运行期动态修改报文字段 =================


def _last_frame_of_type(wire: FakeWire, mt: int) -> bytes:
    return _frames_of_type(wire, mt)[-1]


def test_runtime_announce_field_update_applies_without_restart(wires):
    _start(clockClass=6, priority1=128, domainNumber=37)
    wire = wires[0]
    first = _wait_for(wire, int(MessageType.ANNOUNCE))[0][14:]
    assert first[48] == 6 and first[47] == 128 and first[4] == 37

    # 不重启，直接改报文属性
    res = update_l2_master_lab({"clockClass": 7, "priority1": 200, "domainNumber": 24})
    assert res["updated"] == ["clock_class", "domain_number", "priority1"]
    assert res["config"]["clock_class"] == 7

    # 下一个 Announce 即用新值（domain 变了，回包过滤也按新域）
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        frames = _frames_of_type(wire, int(MessageType.ANNOUNCE))
        if len(frames) >= 2 and frames[-1][14 + 48] == 7:
            break
        time.sleep(0.01)
    latest = _last_frame_of_type(wire, int(MessageType.ANNOUNCE))[14:]
    assert latest[48] == 7  # clockClass
    assert latest[47] == 200  # priority1
    assert latest[4] == 24  # domainNumber
    assert poll_l2_master_lab()["status"] == "running"  # 未重启，仍在运行


def test_runtime_sync_interval_update_reschedules(wires):
    # 1588v2：-7（≈7.8ms）改到 0（1s），更新后 Sync 周期明显变长
    _start(profile="1588v2", logSyncInterval=-7, twoStep=False)
    wire = wires[0]
    _wait_for(wire, int(MessageType.SYNC), count=3, timeout=3)
    update_l2_master_lab({"logSyncInterval": 0})
    time.sleep(0.3)
    n_after = len(_frames_of_type(wire, int(MessageType.SYNC)))
    time.sleep(0.4)
    assert len(_frames_of_type(wire, int(MessageType.SYNC))) - n_after <= 1  # 1s 周期内至多 1 帧


def test_runtime_two_step_switch_applies_to_next_sync(wires):
    _start(logSyncInterval=-4, twoStep=True)
    wire = wires[0]
    sync = _wait_for(wire, int(MessageType.SYNC))[0][14:]
    assert struct.unpack_from("!H", sync, 6)[0] & FLAG_TWO_STEP
    _wait_for(wire, int(MessageType.FOLLOW_UP))

    update_l2_master_lab({"twoStep": False})
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        syncs = _frames_of_type(wire, int(MessageType.SYNC))
        if len(syncs) >= 2 and not (struct.unpack_from("!H", syncs[-1][14:], 6)[0] & FLAG_TWO_STEP):
            break
        time.sleep(0.01)
    assert not (struct.unpack_from("!H", _last_frame_of_type(wire, int(MessageType.SYNC))[14:], 6)[0] & FLAG_TWO_STEP)


def test_runtime_update_rejects_non_message_fields(wires):
    _start()
    with pytest.raises(ValueError, match="不可在线修改"):
        update_l2_master_lab({"maxSlaves": 128})
    with pytest.raises(ValueError, match="不可在线修改"):
        update_l2_master_lab({"profile": "1588v2"})


def test_runtime_update_rejects_out_of_range(wires):
    _start(profile="g82751")
    with pytest.raises(ValueError, match="domain_number"):
        update_l2_master_lab({"domainNumber": 100})  # g82751 合法域 24..43


def test_runtime_update_without_run_raises():
    with pytest.raises(RuntimeError):
        update_l2_master_lab({"clockClass": 7})


def test_runtime_dst_mac_and_vlan_update(wires):
    _start(dstMac="01-1B-19-00-00-00")
    wire = wires[0]
    _wait_for(wire, int(MessageType.ANNOUNCE))
    update_l2_master_lab({"dstMac": "01-0C-CD-01-00-66", "vlanId": 100, "vlanPcp": 3})
    deadline = time.monotonic() + 2
    frame = b""
    while time.monotonic() < deadline:
        cands = [f for f in wire.frames_out if f[0:6] == bytes.fromhex("010CCD010066") and len(f) >= 18]
        if cands:
            frame = cands[-1]
            break
        time.sleep(0.01)
    assert frame  # 新目的 MAC + VLAN tag 生效
    assert struct.unpack_from("!H", frame, 12)[0] == 0x8100
    tci = struct.unpack_from("!H", frame, 14)[0]
    assert (tci >> 13) & 0x7 == 3 and (tci & 0xFFF) == 100


# ================= flagField 逐位修改 =================


def test_start_flags_are_injected(wires):
    # 页面 flags 整数直接进入线上报文（bit6 置位的 Announce / bit6+bit9 的 Sync）
    _start(announceFlags=0x0078, syncFlags=0x0240, twoStep=True, followUpFlags=0x0240)
    wire = wires[0]
    ann = _wait_for(wire, int(MessageType.ANNOUNCE))[0]
    assert struct.unpack_from("!H", ann, _ptp_offset(ann) + 6)[0] == 0x0078
    sync = _wait_for(wire, int(MessageType.SYNC))[0]
    assert struct.unpack_from("!H", sync, _ptp_offset(sync) + 6)[0] == 0x0240
    fu = _wait_for(wire, int(MessageType.FOLLOW_UP))[0]
    assert struct.unpack_from("!H", fu, _ptp_offset(fu) + 6)[0] == 0x0240


def test_runtime_announce_flags_update_applies_without_restart(wires):
    _start(announceFlags=0x0038, logAnnounceInterval=-3)
    wire = wires[0]
    first = _wait_for(wire, int(MessageType.ANNOUNCE))[0]
    assert struct.unpack_from("!H", first, _ptp_offset(first) + 6)[0] == 0x0038

    update_l2_master_lab({"announceFlags": 0x8038})  # 点击 PTP_SECURITY(bit15)
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        anns = _frames_of_type(wire, int(MessageType.ANNOUNCE))
        if len(anns) >= 2 and struct.unpack_from("!H", anns[-1], _ptp_offset(anns[-1]) + 6)[0] == 0x8038:
            break
        time.sleep(0.01)
    latest = _last_frame_of_type(wire, int(MessageType.ANNOUNCE))
    assert struct.unpack_from("!H", latest, _ptp_offset(latest) + 6)[0] == 0x8038


def test_runtime_sync_flags_two_step_reconcile(wires):
    # twoStep 语义位恒以布尔开关为准：syncFlags 提供其余位
    _start(logSyncInterval=-4, twoStep=True, syncFlags=0x0000)
    wire = wires[0]
    sync = _wait_for(wire, int(MessageType.SYNC))[0]
    assert struct.unpack_from("!H", sync, _ptp_offset(sync) + 6)[0] == FLAG_TWO_STEP

    update_l2_master_lab({"syncFlags": 0x0040})  # 只点 SYNCHRONIZATION_UNCERTAIN(bit6)
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        syncs = _frames_of_type(wire, int(MessageType.SYNC))
        if len(syncs) >= 2 and struct.unpack_from("!H", syncs[-1], _ptp_offset(syncs[-1]) + 6)[0] == 0x0240:
            break
        time.sleep(0.01)
    latest = _last_frame_of_type(wire, int(MessageType.SYNC))
    assert struct.unpack_from("!H", latest, _ptp_offset(latest) + 6)[0] == 0x0240  # bit9 仍由 twoStep 置位

    update_l2_master_lab({"twoStep": False})  # 取消两步法 → bit9 清零、bit6 保留
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        syncs = _frames_of_type(wire, int(MessageType.SYNC))
        if len(syncs) >= 2 and struct.unpack_from("!H", syncs[-1], _ptp_offset(syncs[-1]) + 6)[0] == 0x0040:
            break
        time.sleep(0.01)
    latest = _last_frame_of_type(wire, int(MessageType.SYNC))
    assert struct.unpack_from("!H", latest, _ptp_offset(latest) + 6)[0] == 0x0040


def test_runtime_update_rejects_out_of_range_flags(wires):
    _start()
    with pytest.raises(ValueError, match="sync_flags"):
        update_l2_master_lab({"syncFlags": 70000})  # 超出 uint16


# ================= 通用头联动开关 =================


def _hdr(frame: bytes) -> PTPHeader:
    return PTPHeader.unpack(frame, _ptp_offset(frame))


def test_header_link_on_shares_common_header(wires):
    # 默认联动开启：改共享 domainNumber，四类报文同步生效
    _start(domainNumber=30, logAnnounceInterval=-3, logSyncInterval=-4)
    wire = wires[0]
    ann = _wait_for(wire, int(MessageType.ANNOUNCE))[0]
    sync = _wait_for(wire, int(MessageType.SYNC))[0]
    assert _hdr(ann).domain_number == 30
    assert _hdr(sync).domain_number == 30
    assert _hdr(ann).source_identity == _hdr(sync).source_identity  # 共享 clockIdentity/portNumber


def test_header_link_off_per_message_override(wires):
    # 联动关闭：Sync 独立 domain/CI/port，Announce 沿用共享值
    _start(
        domainNumber=30,
        clockIdentity="0001020304050607",
        logAnnounceInterval=-3,
        logSyncInterval=-4,
        headerLink=False,
        messageOverrides={"sync": {"domainNumber": 41, "clockIdentity": "aabbccddeeff0011", "portNumber": 9}},
    )
    wire = wires[0]
    ann = _hdr(_wait_for(wire, int(MessageType.ANNOUNCE))[0])
    sync = _hdr(_wait_for(wire, int(MessageType.SYNC))[0])
    assert ann.domain_number == 30 and sync.domain_number == 41  # 各自独立
    assert sync.source_identity.clock_identity == bytes.fromhex("aabbccddeeff0011")
    assert sync.source_identity.port_number == 9
    assert ann.source_identity.clock_identity == bytes.fromhex("0001020304050607")


def test_header_link_off_runtime_update_sync_domain(wires):
    _start(domainNumber=30, logAnnounceInterval=-3, logSyncInterval=-4)
    wire = wires[0]
    _wait_for(wire, int(MessageType.SYNC))
    # 运行中关闭联动并给 Delay_Resp/Sync 设独立 domain
    update_l2_master_lab({"headerLink": False, "messageOverrides": {"sync": {"domainNumber": 35}}})
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        syncs = [_hdr(f) for f in _frames_of_type(wire, int(MessageType.SYNC))]
        if syncs and syncs[-1].domain_number == 35:
            break
        time.sleep(0.01)
    assert _hdr(_last_frame_of_type(wire, int(MessageType.SYNC))).domain_number == 35
    # Announce 仍走共享 domain=30
    assert _hdr(_last_frame_of_type(wire, int(MessageType.ANNOUNCE))).domain_number == 30


def test_header_link_off_rx_accepts_override_domain(wires):
    # 联动关闭时 Delay_Resp 用独立 domain，Slave 的 Delay_Req 也需匹配该 domain 才被应答
    _start(
        domainNumber=30,
        logAnnounceInterval=-3,
        logSyncInterval=-4,
        headerLink=False,
        messageOverrides={"delayresp": {"domainNumber": 42}},
    )
    wire = wires[0]
    _wait_for(wire, int(MessageType.ANNOUNCE))
    wire.feed_delay_req(domain=42)  # 落在 delayresp 覆盖的 domain 内
    dr = _hdr(_wait_for(wire, int(MessageType.DELAY_RESP))[0])
    assert dr.domain_number == 42  # Delay_Resp 使用独立 domain


def test_message_overrides_reject_unknown_field():
    with pytest.raises(ValueError, match="unknown field"):
        _start(headerLink=False, messageOverrides={"sync": {"priority1": 5}})


def test_message_overrides_reject_unknown_message():
    with pytest.raises(ValueError, match="unknown message key"):
        _start(headerLink=False, messageOverrides={"ping": {"domainNumber": 5}})


# ================= 前端 main.js 按钮逻辑（node 沙箱） =================


def test_main_js_button_logic_via_node():
    node = shutil.which("node")
    if node is None:
        pytest.skip("需要 node 运行前端逻辑测试")
    js = Path(__file__).with_name("master_ui_logic_test.js")
    proc = subprocess.run([node, str(js)], capture_output=True, text=True, timeout=60, cwd=Path(__file__).parents[1])
    assert proc.returncode == 0, f"前端按钮逻辑测试失败:\n{proc.stdout}\n{proc.stderr}"
