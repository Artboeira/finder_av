"""
Packet Sniffer — Live ArtNet / sACN DMX Monitor
Passively captures DMX traffic using scapy raw sockets.

Requirements:
    pip install scapy
    Windows: Npcap must be installed (https://npcap.com)
    Linux/macOS: run with sudo for raw socket access
"""

import struct
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Deque, Dict, List, Optional

ARTNET_HEADER = b"Art-Net\x00"
ARTNET_OP_DMX = 0x5000

ACN_IDENTIFIER = b"ASC-E1.17\x00\x00\x00"


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
        # per-universe FPS tracking: deque of timestamps (last 2s)
        self._fps_data: Dict[int, Deque[float]] = {}
        # per-universe last packet time (for freeze detection)
        self._last_packet: Dict[int, float] = {}
        self._lock = threading.Lock()

    def start(
        self,
        callback: Callable[[DMXPacket], None],
        universe_filter: Optional[int] = None,
        ip_filter: Optional[str] = None,
    ) -> None:
        self._callback = callback
        self._universe_filter = universe_filter
        self._ip_filter = ip_filter
        self._running = True
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        # Thread will exit via stop_filter on next packet, or when join times out
        if self._thread:
            self._thread.join(timeout=2.0)

    def get_fps(self, universe: int) -> float:
        now = time.monotonic()
        cutoff = now - 2.0
        with self._lock:
            q = self._fps_data.get(universe, deque())
            # Count timestamps within last 2 seconds
            recent = sum(1 for t in q if t >= cutoff)
        return recent / 2.0

    def get_active_universes(self) -> List[int]:
        with self._lock:
            return sorted(self._last_packet.keys())

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
            # Prune older than 2s
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
        try:
            from scapy.all import sniff, UDP, Raw, IP

            def _handler(scapy_pkt):
                if not self._running:
                    return
                if UDP not in scapy_pkt or Raw not in scapy_pkt:
                    return
                if IP not in scapy_pkt:
                    return
                src_ip = scapy_pkt[IP].src
                payload = bytes(scapy_pkt[Raw].load)
                self._handle_raw(src_ip, payload)

            sniff(
                filter="udp and (port 6454 or port 5568)",
                prn=_handler,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except Exception:
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
