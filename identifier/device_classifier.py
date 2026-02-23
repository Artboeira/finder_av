"""
Classifier — Device Classifier
Combines results from all modules and classifies devices with priority logic.
"""

import asyncio
import socket
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from scanner.artnet_poll import ArtNetNode
from scanner.port_scanner import DeviceInfo


@dataclass
class Device:
    ip: str
    hostname: Optional[str]          # via mDNS or reverse DNS
    device_type: str                  # Tasmota, Shelly, ArtNet Node, Windows PC, iPad, Android, Unknown...
    friendly_name: Optional[str]      # Friendly name (e.g., "Dimmer Palco Esquerdo")
    details: Dict = field(default_factory=dict)
    discovery_method: str = "ping"


# ── Async DNS resolution (aiodns if available, fallback to sync) ──────────────

async def resolve_hostnames(
    ips: List[str],
    mdns_map: Dict[str, str],
) -> Dict[str, str]:
    """
    Async reverse DNS for IPs not already resolved via mDNS.
    Uses aiodns if installed, otherwise falls back to threaded sync DNS.

    Returns:
        Dict[ip -> hostname]
    """
    unresolved = [ip for ip in ips if ip not in mdns_map]
    if not unresolved:
        return {}

    results: Dict[str, str] = {}

    try:
        import aiodns
        resolver = aiodns.DNSResolver()

        async def _aiodns_one(ip: str) -> tuple:
            try:
                result = await resolver.gethostbyaddr(ip)
                name = result.name
                return ip, (name if name and name != ip else None)
            except Exception:
                return ip, None

        resolved = await asyncio.gather(*[_aiodns_one(ip) for ip in unresolved])

    except ImportError:
        # Fallback: use thread pool with blocking socket.gethostbyaddr
        def _sync_dns(ip: str) -> Optional[str]:
            try:
                name = socket.gethostbyaddr(ip)[0]
                return name if name != ip else None
            except Exception:
                return None

        loop = asyncio.get_event_loop()
        coros = [loop.run_in_executor(None, _sync_dns, ip) for ip in unresolved]
        names = await asyncio.gather(*coros)
        resolved = list(zip(unresolved, names))

    results = {ip: name for ip, name in resolved if name}
    return results


# ── Main classifier ───────────────────────────────────────────────────────────

def classify(
    live_ips: List[str],
    mdns_map: Dict[str, str],
    port_results: Dict[str, DeviceInfo],
    artnet_nodes: List[ArtNetNode],
    ssdp_map: Optional[Dict[str, Dict]] = None,
    mac_vendor_map: Optional[Dict[str, Dict]] = None,
    hostname_map: Optional[Dict[str, str]] = None,
) -> List[Device]:
    """
    Consolidate all scanner results into a unified Device list.

    Priority order:
    1. ArtNet Poll
    2. HTTP Fingerprint (Tasmota / Shelly / WLED)
    3. mDNS name
    3.5 SSDP/UPnP
    4. Port scan heuristics
    4.5 MAC vendor hint (for Desconhecido)
    5. Unknown
    """
    ssdp_map = ssdp_map or {}
    mac_vendor_map = mac_vendor_map or {}
    hostname_map = hostname_map or {}

    devices: List[Device] = []
    artnet_by_ip = {node.ip: node for node in artnet_nodes}

    for ip in live_ips:
        artnet    = artnet_by_ip.get(ip)
        port_info = port_results.get(ip)
        mdns_name = mdns_map.get(ip)
        ssdp_info = ssdp_map.get(ip)
        mac_info  = mac_vendor_map.get(ip, {})

        hostname = mdns_name or hostname_map.get(ip)

        # Build base details with vendor if available
        base_details: Dict = {}
        if mac_info.get("vendor"):
            base_details["vendor"] = mac_info["vendor"]

        # Priority 1 — ArtNet
        if artnet:
            friendly = artnet.long_name or artnet.short_name or None
            details = {
                "short_name": artnet.short_name,
                "long_name": artnet.long_name,
                "num_ports": artnet.num_ports,
                "universe": artnet.universe,
                **base_details,
            }
            devices.append(Device(
                ip=ip,
                hostname=hostname,
                device_type="ArtNet Node",
                friendly_name=friendly,
                details=details,
                discovery_method="artnet_poll",
            ))
            continue

        # Priority 2 — Tasmota / Shelly / WLED from HTTP fingerprint
        if port_info and port_info.device_type in ("Tasmota", "Shelly", "WLED"):
            details = {**port_info.details, **base_details}
            devices.append(Device(
                ip=ip,
                hostname=hostname,
                device_type=port_info.device_type,
                friendly_name=port_info.friendly_name,
                details=details,
                discovery_method="http_fingerprint",
            ))
            continue

        # Priority 3 — mDNS name heuristic
        if mdns_name:
            guessed_type = _guess_type_from_mdns(mdns_name)
            devices.append(Device(
                ip=ip,
                hostname=hostname,
                device_type=guessed_type,
                friendly_name=mdns_name,
                details=base_details,
                discovery_method="mdns",
            ))
            continue

        # Priority 3.5 — SSDP/UPnP
        if ssdp_info:
            device_type = ssdp_info.get("device_type", "UPnP Device")
            friendly = ssdp_info.get("server") or None
            details = {
                "server": ssdp_info.get("server", ""),
                "location": ssdp_info.get("location", ""),
                **base_details,
            }
            devices.append(Device(
                ip=ip,
                hostname=hostname,
                device_type=device_type,
                friendly_name=friendly,
                details=details,
                discovery_method="ssdp",
            ))
            continue

        # Priority 4 — Port scan heuristic
        if port_info and port_info.device_type:
            details = {**port_info.details, **base_details}
            devices.append(Device(
                ip=ip,
                hostname=hostname,
                device_type=port_info.device_type,
                friendly_name=port_info.friendly_name,
                details=details,
                discovery_method="port_scan",
            ))
            continue

        # Priority 4.5 — MAC vendor hint for otherwise unknown devices
        vendor_hint = mac_info.get("vendor_hint")
        if vendor_hint == "ESP32/ESP8266":
            devices.append(Device(
                ip=ip,
                hostname=hostname,
                device_type="IoT Device (ESP)",
                friendly_name=None,
                details=base_details,
                discovery_method="mac_vendor",
            ))
            continue

        # Priority 5 — Unknown
        devices.append(Device(
            ip=ip,
            hostname=hostname,
            device_type="Desconhecido",
            friendly_name=None,
            details=base_details,
            discovery_method="ping",
        ))

    devices.sort(key=lambda d: list(map(int, d.ip.split("."))))
    return devices


def _guess_type_from_mdns(name: str) -> str:
    name_lower = name.lower()
    if "tasmota" in name_lower:
        return "Tasmota"
    if "shelly" in name_lower:
        return "Shelly"
    if "wled" in name_lower:
        return "WLED"
    if "iphone" in name_lower or "ipad" in name_lower or "apple" in name_lower:
        return "iPhone/iPad"
    if "android" in name_lower:
        return "Android"
    if "windows" in name_lower or "desktop" in name_lower or "laptop" in name_lower:
        return "Windows PC"
    return "Web Device"
