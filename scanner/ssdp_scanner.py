"""
SSDP / UPnP Scanner
Broadcasts M-SEARCH to discover UPnP devices on the local network.
Uses only stdlib (socket) — no extra dependencies.
"""

import asyncio
import socket
import time
from typing import Dict

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
SSDP_MX = 2

_M_SEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
    'MAN: "ssdp:discover"\r\n'
    f"MX: {SSDP_MX}\r\n"
    "ST: upnp:rootdevice\r\n"
    "\r\n"
).encode()

# Server string substrings → device type (lowercase match)
_SERVER_TYPE_MAP = [
    ("sonos",       "Sonos"),
    ("samsung",     "Smart TV"),
    ("lg ",         "Smart TV"),
    ("sony",        "Smart TV"),
    ("philips",     "Smart TV"),
    ("synology",    "NAS"),
    ("qnap",        "NAS"),
    ("roku",        "Streaming Device"),
    ("chromecast",  "Chromecast"),
    ("apple",       "Apple Device"),
    ("amazon",      "Amazon Device"),
    ("windows",     "Windows PC"),
    ("linux",       "Linux Device"),
]


def _classify_server(server: str) -> str:
    s = server.lower()
    for keyword, label in _SERVER_TYPE_MAP:
        if keyword in s:
            return label
    return "UPnP Device"


def _parse_ssdp_response(data: bytes) -> Dict:
    text = data.decode("utf-8", errors="replace")
    info = {"server": "", "location": "", "st": "", "usn": ""}
    for line in text.splitlines():
        lower = line.lower()
        if lower.startswith("server:"):
            info["server"] = line[7:].strip()
        elif lower.startswith("location:"):
            info["location"] = line[9:].strip()
        elif lower.startswith("st:"):
            info["st"] = line[3:].strip()
        elif lower.startswith("usn:"):
            info["usn"] = line[4:].strip()
    return info


def _run_ssdp(timeout: float) -> Dict[str, Dict]:
    results: Dict[str, Dict] = {}

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)

    try:
        sock.sendto(_M_SEARCH, (SSDP_ADDR, SSDP_PORT))
    except Exception:
        sock.close()
        return results

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            data, addr = sock.recvfrom(2048)
        except socket.timeout:
            break
        except Exception:
            break

        ip = addr[0]
        if ip in results:
            continue  # Keep first response per IP

        parsed = _parse_ssdp_response(data)
        parsed["device_type"] = _classify_server(parsed["server"])
        results[ip] = parsed

    sock.close()
    return results


async def ssdp_scan(timeout: float = 3.0) -> Dict[str, Dict]:
    """
    Broadcast SSDP M-SEARCH and collect UPnP device responses.

    Returns:
        Dict[ip -> {"server": str, "location": str, "device_type": str}]
    """
    return await asyncio.to_thread(_run_ssdp, timeout)
