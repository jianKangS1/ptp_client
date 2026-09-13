"""离线演练（虚拟链路）模式测试。

需求：CLI / Web 上仍然选择一张「网卡」（名称标签），但指定 offline 后
不打开真实网卡、不在线路上发送任何层二报文 —— 由 VirtualTransport 在
内存中生成并留存报文。本文件覆盖：

* VirtualTransport 自身行为（合成 MAC 确定性、帧留存、有界缓冲、不收包）
* open_transport(offline=True) 不触碰真实平台传输层
* config / CLI(--offline) / Web handler / Pydantic 模型全链路
* PtpL2Master 以不存在的网卡名真实启动（不打桩 open_transport），
  四类报文照常生成，停止后无线发送、线程干净退出
"""

from __future__ import annotations

import json
import re
import struct
import time
from pathlib import Path

import pytest

from ptp_client.ptp.constants import MessageType
from ptp_client.ptp.l2master import transport as tmod
from ptp_client.ptp.l2master.cli import build_arg_parser, main as cli_main
from ptp_client.ptp.l2master.config import config_from_dict
from ptp_client.ptp.l2master.master import PtpL2Master
from ptp_client.ptp.l2master.transport import (
    VirtualTransport,
    open_transport,
    resolve_virtual_src_mac,
)
from ptp_client.web import l2_master_lab
from ptp_client.web.l2_master_lab import poll_l2_master_lab, start_l2_master_lab, stop_l2_master_lab

BOGUS_IFACE = "ptp-no-such-interface-xyzzz"


@pytest.fixture(autouse=True)
def _stop_web_run():
    yield
    stop_l2_master_lab()


# ---------------- VirtualTransport 单元行为 ----------------


def test_virtual_open_accepts_unknown_interface():
    vt = VirtualTransport(BOGUS_IFACE)
    vt.open()  # 不存在的网卡名也能「打开」
    assert len(vt.src_mac) == 6
    assert vt.src_mac[0] & 0x01 == 0  # 单播（最低位为 0）
    assert vt.src_mac[0] & 0x02 == 0x02  # 本地管理位（LAA）
    assert vt.closed is False
    vt.close()
    assert vt.closed is True


def test_virtual_mac_is_deterministic_per_name(monkeypatch):
    # 屏蔽真实网卡探测，强制走合成 MAC
    monkeypatch.setattr(tmod, "_read_linux_sysfs_mac", lambda name: None)
    monkeypatch.setattr(tmod, "_read_windows_iface_mac", lambda name: None)

    a1 = resolve_virtual_src_mac("eth-lab-a")
    a2 = resolve_virtual_src_mac("eth-lab-a")
    b = resolve_virtual_src_mac("eth-lab-b")
    assert a1 == a2  # 同名稳定
    assert a1 != b  # 异名区分


def test_virtual_mac_prefers_real_nic_mac(monkeypatch):
    real = bytes.fromhex("00155d95ec41")
    monkeypatch.setattr(tmod.sys, "platform", "linux")
    monkeypatch.setattr(tmod, "_read_linux_sysfs_mac", lambda name: real)
    assert resolve_virtual_src_mac("eth0") == real


def test_virtual_mac_reader_missing_iface_returns_none():
    # Windows 上 /sys/class/net 不存在；Linux 上该名字也不存在
    assert tmod._read_linux_sysfs_mac(BOGUS_IFACE) is None


def test_virtual_send_records_and_recv_is_idle():
    vt = VirtualTransport("veth0")
    vt.open()
    assert vt.sent_frames() == []
    vt.send(b"\x01" * 20)
    vt.send(b"\x02" * 20)
    frames = vt.sent_frames()
    assert frames == [b"\x01" * 20, b"\x02" * 20]
    assert vt.sent_frames() == frames  # 返回快照，不随后续变化
    assert vt.recv(0.02) is None  # 虚拟链路永远收不到包
    vt.close()


def test_virtual_buffer_is_bounded():
    vt = VirtualTransport("veth0", max_frames=3)
    vt.open()
    for i in range(5):
        vt.send(bytes([i]))
    kept = vt.sent_frames()
    assert kept == [b"\x02", b"\x03", b"\x04"]  # 仅保留最新 3 帧


def test_open_transport_offline_never_touches_platform(monkeypatch):
    def _boom(*_a, **_kw):
        raise AssertionError("offline 模式不允许实例化真实平台传输层")

    monkeypatch.setattr(tmod, "LinuxPacketTransport", _boom)
    monkeypatch.setattr(tmod, "WindowsScapyTransport", _boom)

    t = open_transport(BOGUS_IFACE, offline=True)
    assert isinstance(t, VirtualTransport)
    t.send(b"\xaa")
    assert t.sent_frames() == [b"\xaa"]
    t.close()


# ---------------- 配置 ----------------


def test_config_offline_default_false():
    assert config_from_dict({"interface": "eth0"}).offline is False


def test_config_offline_enabled():
    cfg = config_from_dict({"interface": BOGUS_IFACE, "offline": True})
    assert cfg.offline is True
    cfg.validate()  # offline 不影响其它校验


# ---------------- Master 真实启动（不打桩传输层） ----------------


def _wait_callback(frames: list[bytes], mt: int, count: int = 1, timeout: float = 3.0) -> list[bytes]:
    # on_frame 回调给出的 payload 是裸 PTP 报文（messageType 在首字节低 4 位）
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        got = [f for f in frames if f and (f[0] & 0xF) == mt]
        if len(got) >= count:
            return got[:count]
        time.sleep(0.01)
    raise AssertionError(f"offline master 未产生 messageType={mt}（共 {len(frames)} 帧）")


def test_offline_master_runs_without_real_nic():
    seen: list[bytes] = []
    cfg = config_from_dict(
        {"interface": BOGUS_IFACE, "offline": True, "logAnnounceInterval": -3, "logSyncInterval": -4}
    )
    master = PtpL2Master(cfg, on_frame=lambda _d, _mt, payload, _x: seen.append(payload))
    master.start()  # 真实代码路径：若误用真实传输层，此处会因网卡不存在而 OSError
    try:
        assert isinstance(master._transport, VirtualTransport)
        # clockIdentity 缺省时由（合成）MAC 经 EUI-64 派生
        ci = master.source_port.clock_identity
        assert len(ci) == 8 and b"\xff\xfe" in ci[2:5]

        _wait_callback(seen, int(MessageType.ANNOUNCE))
        _wait_callback(seen, int(MessageType.SYNC))
        _wait_callback(seen, int(MessageType.FOLLOW_UP))

        st = master.get_stats()
        assert st.state.value == "ACTIVE"
        assert st.announce_sent >= 1 and st.sync_sent >= 1 and st.follow_up_sent >= 1
        assert st.tx_errors == 0

        # on_frame 与传输层留存缓冲看到的是同一批「未上线」的帧
        buffered = master._transport.sent_frames()
        assert len(buffered) >= 3
        # 每一帧都是完整以太网帧：dst(6)+src(6)+ethertype(2)+PTP
        assert all(len(f) >= 14 + 34 for f in buffered)
        assert all(struct.unpack_from("!H", f, 12)[0] == 0x88F7 for f in buffered)
    finally:
        master.stop()

    assert master._transport is None  # stop 关闭并释放传输层
    # 停止后线程退出
    assert all(t is None for t in (master._tx_thread, master._rx_thread, master._resp_thread))


def test_offline_master_never_receives_delay_req():
    # 虚拟链路收不到任何外部帧：Delay_Req 计数始终为 0
    cfg = config_from_dict({"interface": BOGUS_IFACE, "offline": True})
    master = PtpL2Master(cfg)
    master.start()
    try:
        time.sleep(0.4)
        assert master.get_stats().delay_req_recv == 0
        assert master.list_slaves() == []
    finally:
        master.stop()


# ---------------- CLI ----------------


def test_cli_parser_offline_flag():
    ns = build_arg_parser().parse_args(["--iface", "veth0", "--offline"])
    assert ns.offline is True
    assert build_arg_parser().parse_args(["--iface", "veth0"]).offline is False


def test_cli_config_from_args_offline():
    # 复用主模块里的私有转换：直接走 main 更重，这里验证 args→cfg 映射
    from ptp_client.ptp.l2master.cli import _config_from_args

    ns = build_arg_parser().parse_args(["--iface", "virt0", "--offline", "--domain", "30"])
    cfg = _config_from_args(ns)
    assert cfg.offline is True
    assert cfg.interface == "virt0"
    assert cfg.domain_number == 30


def test_cli_offline_config_file(tmp_path: Path):
    cfg_file = tmp_path / "offline.json"
    cfg_file.write_text(json.dumps({"interface": "virt-from-file", "offline": True}), encoding="utf-8")
    from ptp_client.ptp.l2master.cli import _config_from_args

    ns = build_arg_parser().parse_args(["--config", str(cfg_file)])
    cfg = _config_from_args(ns)
    assert cfg.offline is True and cfg.interface == "virt-from-file"


def test_cli_main_offline_end_to_end(capsys):
    rc = cli_main(
        ["--iface", BOGUS_IFACE, "--offline", "--duration", "0.6",
         "--stats-period", "0", "--announce-log", "-3", "--sync-log", "-4"]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "[master] final:" in out
    m = re.search(r"announce=(\d+) sync=(\d+) follow_up=(\d+)", out)
    assert m is not None
    assert int(m.group(1)) >= 1 and int(m.group(2)) >= 1 and int(m.group(3)) >= 1


def test_cli_main_missing_interface_errors(capsys):
    rc = cli_main(["--offline"])  # 即使离线也必须选择（命名）一张网卡
    assert rc == 2
    assert "interface is required" in capsys.readouterr().err


# ---------------- Web handler / Pydantic ----------------


def test_web_start_offline_uses_virtual_transport():
    info = start_l2_master_lab(
        {"interface": BOGUS_IFACE, "offline": True, "profile": "g82751", "clockIdentity": "0001020304050607"}
    )
    assert info["transport"] == "virtual"
    assert info["config"]["offline"] is True
    assert info["src_mac"]  # 即使没有真实网卡也回填了源 MAC

    # 等待后台线程在虚拟链路上产出报文
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        polled = poll_l2_master_lab(0)
        if polled["stats"]["announce_sent"] >= 1:
            break
        time.sleep(0.02)
    polled = poll_l2_master_lab(0)
    assert polled["status"] == "running"
    assert polled["stats"]["announce_sent"] >= 1
    assert polled["stats"]["sync_sent"] >= 1
    names = {m["summary"]["message_type_name"] for m in polled["messages"]}
    assert "ANNOUNCE" in names  # 页面实时报文列表照常工作

    assert stop_l2_master_lab()["stopping"] is True
    assert poll_l2_master_lab()["status"] == "stopped"


def test_web_start_default_is_live_transport(monkeypatch):
    created: list[object] = []

    class _Spy(VirtualTransport):
        def __init__(self, interface, **kw):
            super().__init__(interface, **kw)
            created.append(self)

    # 默认（offline 省略）走平台分支；用 spy 替换 Windows/Linux 实现验证选择逻辑
    monkeypatch.setattr(tmod, "VirtualTransport", _Spy)
    monkeypatch.setattr(tmod, "LinuxPacketTransport", _Spy)
    monkeypatch.setattr(tmod, "WindowsScapyTransport", _Spy)

    start_l2_master_lab({"interface": "any", "clockIdentity": "0001020304050607"})
    try:
        assert l2_master_lab._RUN is not None  # noqa: SLF001
        run = l2_master_lab._RUN  # noqa: SLF001
        assert run.cfg.offline is False
        polled = poll_l2_master_lab()
        assert polled["config"]["offline"] is False
    finally:
        stop_l2_master_lab()
    assert len(created) == 1  # 仅创建了一个传输实例（平台分支）


def test_pydantic_model_offline_field():
    from pydantic import ValidationError

    from ptp_client.web.app import L2MasterStartModel

    m = L2MasterStartModel.model_validate({"interface": "eth0", "offline": True})
    assert m.offline is True
    assert L2MasterStartModel.model_validate({"interface": "eth0"}).offline is None
    with pytest.raises(ValidationError):
        L2MasterStartModel.model_validate({"interface": "eth0", "offline": ["not-a-bool"]})
