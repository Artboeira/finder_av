"""
Module 4 — ArtNet Poll
Sends an ArtPoll UDP broadcast and collects ArtPollReply responses from nodes.

ArtNet spec: https://artisticlicence.com/WebSiteMaster/User%20Guides/art-net.pdf
"""

import asyncio
import socket
import struct
from dataclasses import dataclass, field
from typing import List

ARTNET_PORT = 6454
ARTNET_HEADER = b"Art-Net\x00"
OP_POLL = 0x2000
OP_POLL_REPLY = 0x2100

BROADCAST_ADDR = "255.255.255.255"
LISTEN_TIMEOUT = 2.0


@dataclass
class ArtNetNode:
    ip: str
    short_name: str
    long_name: str
    num_ports: int
    port_types: List[int] = field(default_factory=list)
    universe: int = 0


def _build_artpoll() -> bytes:
    """Build a minimal ArtPoll packet (14 bytes)."""
    # Header: "Art-Net\0"  (8 bytes)
    # OpCode: 0x2000 little-endian (2 bytes)
    # ProtVer: 14 big-endian (2 bytes)
    # TalkToMe: 0x02 — send reply on change (1 byte)
    # Priority: 0x00 (1 byte)
    packet = (
        ARTNET_HEADER
        + struct.pack("<H", OP_POLL)  # OpCode LE
        + struct.pack(">H", 14)       # ProtVer BE
        + bytes([0x02, 0x00])         # TalkToMe, Priority
    )
    return packet


def _parse_artpoll_reply(data: bytes, sender_ip: str) -> ArtNetNode:
    """
    Parse an ArtPollReply packet.
    Minimum 239 bytes per spec.
    """
    if len(data) < 239:
        return ArtNetNode(ip=sender_ip, short_name="", long_name="", num_ports=0)

    # Offset 10: IP address (4 bytes) — but we use the UDP sender
    ip_bytes = data[10:14]
    ip = ".".join(str(b) for b in ip_bytes) if any(ip_bytes) else sender_ip

    # Offset 26: ShortName (18 bytes, null-terminated)
    short_name = data[26:44].split(b"\x00")[0].decode("utf-8", errors="replace").strip()

    # Offset 44: LongName (64 bytes, null-terminated)
    long_name = data[44:108].split(b"\x00")[0].decode("utf-8", errors="replace").strip()

    # Offset 173: NumPortsHi, offset 174: NumPortsLo
    num_ports = struct.unpack(">H", data[173:175])[0]

    # Offset 175: PortTypes (4 bytes)
    port_types = list(data[175:179])

    # Offset 188: SwIn (4 bytes) — universe inputs
    sw_in = list(data[188:192])
    universe = sw_in[0] if sw_in else 0

    return ArtNetNode(
        ip=ip or sender_ip,
        short_name=short_name,
        long_name=long_name,
        num_ports=num_ports,
        port_types=port_types,
        universe=universe,
    )


async def artnet_poll(timeout: float = LISTEN_TIMEOUT) -> List[ArtNetNode]:
    """
    Send ArtPoll broadcast and collect ArtPollReply responses.

    Returns:
        List of ArtNetNode objects discovered.
    """
    nodes: List[ArtNetNode] = []
    packet = _build_artpoll()

    def _run_poll():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            # Try to bind on ArtNet port to receive replies
            sock.bind(("", ARTNET_PORT))
        except OSError:
            # Port in use (e.g., QLab, Resolume) — bind on ephemeral port
            sock.bind(("", 0))

        sock.settimeout(timeout)

        try:
            sock.sendto(packet, (BROADCAST_ADDR, ARTNET_PORT))
        except Exception:
            pass

        import time
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(1024)
            except socket.timeout:
                break
            except Exception:
                break

            # Validate ArtNet header
            if not data.startswith(ARTNET_HEADER):
                continue

            # Check OpCode (bytes 8-9, little-endian)
            if len(data) < 10:
                continue
            opcode = struct.unpack("<H", data[8:10])[0]
            if opcode == OP_POLL_REPLY:
                node = _parse_artpoll_reply(data, addr[0])
                nodes.append(node)

        sock.close()

    await asyncio.to_thread(_run_poll)
    return nodes
