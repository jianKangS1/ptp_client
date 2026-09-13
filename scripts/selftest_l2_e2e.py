"""Live L2 self-test: run the master on a real Npcap interface, inject a
Delay_Req frame, and verify the master answers with a correct Delay_Resp.

Run:  python scripts/selftest_l2_e2e.py [iface]
Requires Npcap + scapy. iface defaults to the Hyper-V Virtual Ethernet Adapter.
"""

from __future__ import annotations

import sys
import time

from scapy.all import Ether, sendp, AsyncSniffer  # noqa: E402

from ptp_client.ptp.constants import FLAG_UNICAST, MessageType  # noqa: E402
from ptp_client.ptp.header import PortIdentity  # noqa: E402
from ptp_client.ptp.l2master import constants as l2  # noqa: E402
from ptp_client.ptp.l2master.config import MasterConfig  # noqa: E402
from ptp_client.ptp.l2master.master import PtpL2Master  # noqa: E402
from ptp_client.ptp.l2master.messages import build_delay_resp  # noqa: E402
from ptp_client.ptp.timestamp import PTPTimestamp  # noqa: E402
import struct  # noqa: E402
from ptp_client.ptp.header import PTPHeader  # noqa: E402

IFACE = sys.argv[1] if len(sys.argv) > 1 else "Hyper-V Virtual Ethernet Adapter"
DOMAIN = 43
SLAVE_CI = bytes.fromhex("aabbccddeeff0011")
SLAVE_PORT = 2
SLAVE_MAC = bytes.fromhex("0ca3e2b1c0d4")
SEQ = 4242


def build_delay_req() -> bytes:
    hdr = PTPHeader(
        message_type=int(MessageType.DELAY_REQ),
        version_ptp=2,
        message_length=l2.DELAY_REQ_MSG_LEN,
        domain_number=DOMAIN,
        minor_sdo_id=0,
        flags=0,
        correction_field_ns=0,
        source_identity=PortIdentity(SLAVE_CI, SLAVE_PORT),
        sequence_id=SEQ,
        control_field=0x01,
        log_message_interval=0x7F,
        transport_specific=0,
    )
    ts = PTPTimestamp(seconds=int(time.time()), nanoseconds=123456789)
    return hdr.pack() + ts.pack10()


def main() -> int:
    cfg = MasterConfig(
        interface=IFACE,
        profile="g82751",
        domain_number=DOMAIN,
        clock_identity=bytes.fromhex("0001020304050607"),
        log_announce_interval=-3,
        log_sync_interval=-3,
        vlan_id=None,
        dst_mac=l2.IEEE1588_PTP_MAC,
        delay_resp_unicast=True,
    )
    master = PtpL2Master(cfg)

    # Sniffer to independently capture the Delay_Resp the master emits.
    captured: list[bytes] = []

    def on_pkt(pkt):
        data = bytes(pkt)
        if len(data) >= 14 and struct.unpack_from("!H", data, 12)[0] == l2.ETHERTYPE_PTP:
            ptp = data[14:]
            if len(ptp) >= 34 and (ptp[0] & 0xF) == MessageType.DELAY_RESP:
                captured.append(data)

    sniffer = AsyncSniffer(iface=IFACE, filter="ether proto 0x88f7", prn=on_pkt, store=False)
    sniffer.start()
    time.sleep(1.0)  # let the sniffer settle

    master.start()
    try:
        time.sleep(1.5)  # let TX/RX threads warm up
        frame = Ether(dst=l2.IEEE1588_PTP_MAC, src=SLAVE_MAC, type=l2.ETHERTYPE_PTP) / build_delay_req()
        print(f"[selftest] injecting Delay_Req seq={SEQ} on {IFACE!r}")
        sendp(frame, iface=IFACE, verbose=False, count=3, inter=0.3)
        # Wait for the master to answer.
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and not captured:
            time.sleep(0.1)
    finally:
        st = master.get_stats()
        master.stop()
        sniffer.stop()

    print(f"[selftest] master stats: delay_req_recv={st.delay_req_recv} delay_resp_sent={st.delay_resp_sent} "
          f"announce={st.announce_sent} sync={st.sync_sent} tx_errors={st.tx_errors}")
    print(f"[selftest] sniffer captured {len(captured)} Delay_Resp frame(s)")

    ok = True
    if st.delay_req_recv < 1:
        print("[selftest] FAIL: master did not receive the Delay_Req"); ok = False
    if st.delay_resp_sent < 1:
        print("[selftest] FAIL: master did not send a Delay_Resp"); ok = False
    if captured:
        data = captured[0]
        ptp = data[14:]
        hdr = PTPHeader.unpack(ptp, 0)
        recv_ts = PTPTimestamp.unpack10(ptp, 34)
        req_ci = ptp[44:52]
        req_port = struct.unpack_from("!H", ptp, 52)[0]
        checks = [
            ("dst MAC = slave MAC (unicast reply)", data[0:6] == SLAVE_MAC),
            ("messageType == Delay_Resp", (ptp[0] & 0xF) == MessageType.DELAY_RESP),
            ("domainNumber == 43", hdr.domain_number == DOMAIN),
            ("controlField == 0x03", hdr.control_field == 0x03),
            ("logMessageInterval == 0x7F", hdr.log_message_interval == 0x7F),
            ("sequenceId echoes 4242", hdr.sequence_id == SEQ),
            ("requestingPortIdentity.clockIdentity == slave", req_ci == SLAVE_CI),
            ("requestingPortIdentity.portNumber == 2", req_port == SLAVE_PORT),
            ("receiveTimestamp sane (±10 s of now)", abs(recv_ts.seconds - time.time()) < 10),
            ("unicast flag set", bool(hdr.flags & FLAG_UNICAST)),
        ]
        for name, passed in checks:
            print(f"  [{'OK' if passed else 'FAIL'}] {name}")
            ok = ok and passed
    else:
        print("[selftest] FAIL: no Delay_Resp captured on the wire"); ok = False

    print("[selftest] RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
