"""Layer-2 Ethernet transport for the PTP master.

Linux:   AF_PACKET / SOCK_RAW (needs root or CAP_NET_RAW).
Windows: scapy + Npcap (needs Npcap installed, WinPcap-compatible mode).

Frames are built here (14 B Ethernet header, optional 4 B 802.1Q tag) so the
master only deals with PTP payloads.
"""

from __future__ import annotations

import hashlib
import socket
import struct
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Optional

from ptp_client.ptp.l2master import constants as l2


class L2TransportError(RuntimeError):
    pass


def build_ethernet_frame(
    dst_mac: bytes,
    src_mac: bytes,
    payload: bytes,
    *,
    ethertype: int = l2.ETHERTYPE_PTP,
    vlan_id: Optional[int] = None,
    vlan_pcp: int = 0,
) -> bytes:
    if len(dst_mac) != l2.ETH_ADDR_LEN or len(src_mac) != l2.ETH_ADDR_LEN:
        raise ValueError("MAC addresses must be 6 octets")
    header = dst_mac + src_mac
    if vlan_id is not None:
        if not 0 <= vlan_id <= 0xFFF:
            raise ValueError("vlan_id must be 0..4095")
        tci = ((vlan_pcp & 7) << 13) | (vlan_id & 0xFFF)
        header += struct.pack("!HH", l2.ETHERTYPE_VLAN, tci)
    return header + struct.pack("!H", ethertype) + payload


@dataclass(frozen=True, slots=True)
class ReceivedFrame:
    src_mac: bytes
    ethertype: int
    payload: bytes  # PTP message (after Ethernet / VLAN header)
    rx_realtime_ns: int = 0  # CLOCK_REALTIME at syscall return (t2 for Delay_Resp)
    rx_monotonic_ns: int = 0  # CLOCK_MONOTONIC at syscall return (scheduling/ageing)


class L2Transport:
    """Open/close + frame send/recv on one interface. Platform-specific."""

    def __init__(self, interface: str) -> None:
        self.interface = interface
        self.src_mac: bytes = b""

    def open(self) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    def send(self, frame: bytes) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    def recv(self, timeout: float) -> Optional[ReceivedFrame]:  # pragma: no cover - overridden
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover - overridden
        pass


def _mac_str_to_bytes(s: str) -> bytes:
    return bytes.fromhex(s.replace(":", "").replace("-", ""))


# socket.ETH_P_ALL / ETH_P_RARP are not exported on every Python build, so define
# the protocol numbers here (linux/if_ether.h).
ETH_P_ALL = 0x0003


class LinuxPacketTransport(L2Transport):
    """AF_PACKET SOCK_RAW bound to one interface."""

    def open(self) -> None:
        try:
            self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        except PermissionError as e:
            raise L2TransportError(
                f"cannot open AF_PACKET socket: {e} (run as root or grant CAP_NET_RAW)"
            ) from e
        try:
            self._sock.bind((self.interface, socket.htons(ETH_P_ALL)))
        except OSError as e:
            self._sock.close()
            raise L2TransportError(f"cannot bind interface {self.interface!r}: {e}") from e
        self.src_mac = _linux_interface_mac(self._sock, self.interface)

    def send(self, frame: bytes) -> None:
        self._sock.send(frame)

    def recv(self, timeout: float) -> Optional[ReceivedFrame]:
        self._sock.settimeout(timeout)
        try:
            data = self._sock.recv(2048)
        except (TimeoutError, socket.timeout):
            return None
        except OSError:
            return None
        return _parse_ethernet_frame(data)

    def close(self) -> None:
        sock = getattr(self, "_sock", None)
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


class WindowsScapyTransport(L2Transport):
    """Raw L2 send/recv via scapy + Npcap."""

    def open(self) -> None:
        try:
            from scapy.all import conf, get_if_list  # noqa: PLC0415
        except ImportError as e:
            raise L2TransportError(
                "Windows L2 transport requires 'scapy' with Npcap installed "
                "(https://npcap.com, enable WinPcap API-compatible mode)"
            ) from e
        from scapy.all import get_if_hwaddr  # noqa: PLC0415

        try:
            mac = get_if_hwaddr(self.interface)
        except Exception:
            available = ", ".join(conf.ifaces) or "(none)"
            raise L2TransportError(
                f"interface {self.interface!r} not found via Npcap; available: {available}"
            ) from None
        self._dev = self.interface
        self.src_mac = _mac_str_to_bytes(mac)
        self._iface_obj = conf.ifaces[self._dev] if self._dev in conf.ifaces else self._dev
        self._sniffer = None

    def send(self, frame: bytes) -> None:
        from scapy.all import Ether  # noqa: PLC0415
        from scapy.all import sendp  # noqa: PLC0415

        sendp(Ether(frame), iface=self._iface_obj, verbose=False)

    def recv(self, timeout: float) -> Optional[ReceivedFrame]:
        """Return the next PTP (0x88F7) frame, or None on timeout.

        A background AsyncSniffer with a BPF filter feeds a queue; frames are
        parsed (and timestamped) in the sniffer callback so t2 reflects the
        arrival time, not the dequeue time.
        """
        import queue  # noqa: PLC0415

        if self._sniffer is None:
            from scapy.all import AsyncSniffer  # noqa: PLC0415

            self._q: "queue.Queue[ReceivedFrame]" = queue.Queue(maxsize=1024)
            sniffer = AsyncSniffer(
                iface=self._iface_obj,
                filter=f"ether proto {l2.ETHERTYPE_PTP:#x}",
                prn=self._on_packet,
                store=False,
            )
            try:
                sniffer.start()
            except Exception as e:  # Npcap open failure, etc.
                raise L2TransportError(f"cannot start L2 sniffer on {self.interface!r}: {e}") from e
            self._sniffer = sniffer
        try:
            return self._q.get(timeout=max(0.0, timeout))
        except queue.Empty:
            return None

    def _on_packet(self, pkt) -> None:
        # Timestamp + parse in the callback thread; drop (not block) on bursts
        # so the RX loop stays responsive.
        frame = _parse_ethernet_frame(bytes(pkt))
        if frame is None:
            return
        try:
            self._q.put_nowait(frame)
        except Exception:
            pass

    def close(self) -> None:
        sniffer = self._sniffer
        self._sniffer = None
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception:
                pass


def _linux_interface_mac(sock: socket.socket, iface: str) -> bytes:
    import fcntl  # noqa: PLC0415

    SIOCGIFHWADDR = 0x8927
    req = struct.pack("256s", iface[:15].encode("ascii"))
    try:
        info = fcntl.ioctl(sock.fileno(), SIOCGIFHWADDR, req)
    except OSError as e:
        raise L2TransportError(f"cannot query MAC of {iface!r}: {e}") from e
    return info[18:24]


def _parse_ethernet_frame(data: bytes) -> Optional[ReceivedFrame]:
    if len(data) < 14:
        return None
    dst, src = data[0:6], data[6:12]
    off = 12
    (ethertype,) = struct.unpack_from("!H", data, off)
    off += 2
    if ethertype == l2.ETHERTYPE_VLAN:
        if len(data) < off + 2:
            return None
        off += 2  # skip TCI
        (ethertype,) = struct.unpack_from("!H", data, off)
        off += 2
    if ethertype != l2.ETHERTYPE_PTP:
        return None
    return ReceivedFrame(
        src_mac=src,
        ethertype=ethertype,
        payload=data[off:],
        rx_realtime_ns=time.time_ns(),
        rx_monotonic_ns=time.monotonic_ns(),
    )


def _read_linux_sysfs_mac(iface: str) -> Optional[bytes]:
    """Read a NIC MAC from sysfs without opening a socket (offline mode)."""
    import os

    path = os.path.join("/sys/class/net", iface, "address")
    try:
        with open(path, encoding="ascii") as f:  # noqa: PTH123
            text = f.read().strip()
    except OSError:
        return None
    try:
        return _mac_str_to_bytes(text)
    except ValueError:
        return None


def _read_windows_iface_mac(iface: str) -> Optional[bytes]:
    """Look up a NIC MAC in the scapy interface table without opening Npcap."""
    try:
        from scapy.all import conf  # noqa: PLC0415
    except Exception:  # scapy missing → caller falls back to a synthetic MAC
        return None
    wanted = iface.strip().lower()
    try:
        for _dev, entry in conf.ifaces.items():
            name = (getattr(entry, "name", "") or "").lower()
            desc = (getattr(entry, "description", "") or "").lower()
            if wanted not in (name, desc):
                continue
            mac = (getattr(entry, "mac", "") or "").strip()
            if mac:
                return _mac_str_to_bytes(mac)
    except Exception:  # noqa: BLE001 — never let interface probing break open()
        return None
    return None


def _synthetic_laa_mac(seed: str) -> bytes:
    """Deterministic, locally-administered unicast MAC derived from a label."""
    digest = hashlib.sha256(seed.encode("utf-8", "replace")).digest()
    return bytes((0x02, 0x00)) + digest[:4]  # 0x02 = locally administered, unicast


def resolve_virtual_src_mac(iface: str) -> bytes:
    """Pick a source MAC for offline mode: real NIC MAC if discoverable, else synthetic."""
    if sys.platform.startswith("linux"):
        mac = _read_linux_sysfs_mac(iface)
    elif sys.platform in ("win32", "cygwin"):
        mac = _read_windows_iface_mac(iface)
    else:
        mac = None
    return mac or _synthetic_laa_mac(iface)


class VirtualTransport(L2Transport):
    """Offline loopback transport.

    The interface name is only a label: no socket/Npcap handle is opened and no
    frame ever reaches the wire. Sent frames are retained in a bounded buffer
    for inspection (tests / dry-run) and recv() always times out.
    """

    def __init__(self, interface: str, *, max_frames: int = 10000) -> None:
        super().__init__(interface)
        self._max_frames = max_frames
        self._sent: "deque[bytes]" = deque(maxlen=max_frames)
        self._lock = threading.Lock()
        self._closed = False

    def open(self) -> None:
        self.src_mac = resolve_virtual_src_mac(self.interface)

    def send(self, frame: bytes) -> None:
        with self._lock:
            self._sent.append(bytes(frame))

    def recv(self, timeout: float) -> Optional[ReceivedFrame]:
        # Keep the RX loop calm; nothing is ever received on a virtual wire.
        time.sleep(min(max(0.0, timeout), 0.05))
        return None

    def close(self) -> None:
        self._closed = True

    @property
    def closed(self) -> bool:
        return self._closed

    def sent_frames(self) -> list[bytes]:
        with self._lock:
            return list(self._sent)


def open_transport(interface: str, *, offline: bool = False) -> L2Transport:
    """Create and open a transport for ``interface``.

    ``offline=True`` returns a VirtualTransport: the interface name is accepted
    as-is (it need not exist) and layer-2 frames are never put on the wire.
    """
    if offline:
        t: L2Transport = VirtualTransport(interface)
    elif sys.platform.startswith("linux"):
        t = LinuxPacketTransport(interface)
    elif sys.platform in ("win32", "cygwin"):
        t = WindowsScapyTransport(interface)
    else:
        raise L2TransportError(f"unsupported platform for L2 transport: {sys.platform!r}")
    t.open()
    return t
