"""
Packet Sniffer — Live ArtNet / sACN DMX Monitor

Capture modes (tried in order):
  1. scapy  — raw packet capture via Npcap/libpcap (requires admin on Windows,
               sudo on Linux/macOS). Captures ALL traffic including outgoing.
  2. socket — pure UDP socket bind (no Npcap needed). Captures incoming packets
               and broadcast traffic delivered locally by the OS.

Requirements for scapy mode:
    pip install scapy
    Windows: Npcap (https://npcap.com) + run as Administrator
    Linux/macOS: run with sudo
"""

import select
import socket
import struct
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Deque, Dict, List, Optional

ARTNET_HEADER = b"Art-Net\x00"
ARTNET_OP_DMX = 0x5000

ACN_IDENTIFIER = b"ASC-E1.17\x00\x00\x00"


def _get_local_ips() -> set:
    local: set = {"127.0.0.1"}
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
            for addr in addrs:
                local.add(addr["addr"])
    except Exception:
        pass
    return local


def _is_admin() -> bool:
    """Returns True if the process has elevated privileges."""
    try:
        if sys.platform == "win32":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            import os
            return os.geteuid() == 0
    except Exception:
        return False


@dataclass
class DMXPacket:
    source_ip: str
    universe: int
    channels: List[int]    # up to 512 values (0-255)
    protocol: str          # "ArtNet" or "sACN"
    timestamp: float       # time.monotonic()


class PacketSniffer:
    def __init__(self) -> None:
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callback: Optional[Callable[[DMXPacket], None]] = None
        self._universe_filter: Optional[int] = None
        self._ip_filter: Optional[str] = None
        self._iface: Optional[str] = None
        # per-universe FPS tracking: deque of timestamps (last 2s)
        self._fps_data: Dict[int, Deque[float]] = {}
        # per-universe last packet time (for freeze detection)
        self._last_packet: Dict[int, float] = {}
        self._lock = threading.Lock()
        self._local_ips: set = _get_local_ips()
        # capture state
        self._error: Optional[str] = None
        self._capture_mode: str = "starting"   # starting | scapy | socket | error

    def start(
        self,
        callback: Callable[[DMXPacket], None],
        universe_filter: Optional[int] = None,
        ip_filter: Optional[str] = None,
        iface: Optional[str] = None,
    ) -> None:
        self._callback = callback
        self._universe_filter = universe_filter
        self._ip_filter = ip_filter
        self._iface = iface
        self._running = True
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)

    def get_fps(self, universe: int) -> float:
        now = time.monotonic()
        cutoff = now - 2.0
        with self._lock:
            q = self._fps_data.get(universe, deque())
            recent = sum(1 for t in q if t >= cutoff)
        return recent / 2.0

    def get_active_universes(self) -> List[int]:
        with self._lock:
            return sorted(self._last_packet.keys())

    def get_local_ips(self) -> set:
        return self._local_ips

    def get_capture_mode(self) -> str:
        return self._capture_mode

    def get_error(self) -> Optional[str]:
        return self._error

    def is_frozen(self, universe: int) -> bool:
        with self._lock:
            last = self._last_packet.get(universe)
        if last is None:
            return False
        return (time.monotonic() - last) > 1.0

    # ── Internal ──────────────────────────────────────────────────────────────

    def _record_packet(self, pkt: DMXPacket) -> None:
        now = pkt.timestamp
        with self._lock:
            if pkt.universe not in self._fps_data:
                self._fps_data[pkt.universe] = deque()
            q = self._fps_data[pkt.universe]
            q.append(now)
            cutoff = now - 2.0
            while q and q[0] < cutoff:
                q.popleft()
            self._last_packet[pkt.universe] = now

    def _handle_raw(self, src_ip: str, payload: bytes) -> None:
        if self._ip_filter and src_ip != self._ip_filter:
            return

        pkt = _parse_artnet(src_ip, payload) or _parse_sacn(src_ip, payload)
        if pkt is None:
            return

        if self._universe_filter is not None and pkt.universe != self._universe_filter:
            return

        self._record_packet(pkt)
        if self._callback:
            self._callback(pkt)

    def _sniff_loop(self) -> None:
        # ── Try scapy (raw capture, requires Npcap/admin) ─────────────────────
        scapy_error: Optional[str] = None
        try:
            from scapy.all import sniff, UDP, Raw, IP

            self._capture_mode = "scapy"

            def _handler(scapy_pkt):
                if not self._running:
                    return
                if UDP not in scapy_pkt or Raw not in scapy_pkt:
                    return
                if IP not in scapy_pkt:
                    return
                self._handle_raw(scapy_pkt[IP].src, bytes(scapy_pkt[Raw].load))

            sniff(
                filter="udp and (port 6454 or port 5568)",
                iface=self._iface,
                prn=_handler,
                store=False,
                stop_filter=lambda _: not self._running,
            )
            return  # clean stop via stop_filter

        except Exception as exc:
            scapy_error = str(exc)
            if not exc and not _is_admin():
                scapy_error = (
                    "Permissão negada. "
                    + ("Execute como Administrador." if sys.platform == "win32"
                       else "Execute com sudo.")
                )

        # ── Fallback: UDP socket bind (no Npcap needed) ───────────────────────
        # Captures incoming packets + broadcast traffic from local apps.
        self._capture_mode = "socket"
        self._error = scapy_error
        self._socket_sniff_loop()

    def _socket_sniff_loop(self) -> None:
        """
        Pure socket fallback. Binds to ArtNet (6454) and sACN (5568) ports.
        Receives all packets delivered to this machine, including broadcast
        ArtNet packets sent by local applications (e.g. Resolume, MadMapper).
        """
        socks: List[socket.socket] = []
        try:
            for port in (6454, 5568):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.bind(("", port))
                s.setblocking(False)
                socks.append(s)

            while self._running:
                readable, _, _ = select.select(socks, [], [], 0.5)
                for s in readable:
                    try:
                        data, addr = s.recvfrom(600)
                        self._handle_raw(addr[0], data)
                    except Exception:
                        pass

        except Exception as sock_exc:
            prev = self._error or ""
            self._error = f"{prev} | socket: {sock_exc}"
            self._capture_mode = "error"
        finally:
            for s in socks:
                try:
                    s.close()
                except Exception:
                    pass
            self._running = False


def _parse_artnet(src_ip: str, data: bytes) -> Optional[DMXPacket]:
    if len(data) < 18:
        return None
    if data[0:8] != ARTNET_HEADER:
        return None
    opcode = struct.unpack("<H", data[8:10])[0]
    if opcode != ARTNET_OP_DMX:
        return None
    universe = (data[15] << 8) | data[14]
    length = (data[16] << 8) | data[17]
    raw = data[18: 18 + min(length, 512)]
    channels = list(raw) + [0] * (512 - len(raw))
    return DMXPacket(
        source_ip=src_ip,
        universe=universe,
        channels=channels,
        protocol="ArtNet",
        timestamp=time.monotonic(),
    )


def _parse_sacn(src_ip: str, data: bytes) -> Optional[DMXPacket]:
    if len(data) < 127:
        return None
    if data[4:16] != ACN_IDENTIFIER:
        return None
    universe = struct.unpack(">H", data[113:115])[0]
    raw = data[126: 126 + 512]
    channels = list(raw) + [0] * (512 - len(raw))
    return DMXPacket(
        source_ip=src_ip,
        universe=universe,
        channels=channels,
        protocol="sACN",
        timestamp=time.monotonic(),
    )
