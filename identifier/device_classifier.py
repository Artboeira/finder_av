"""
Classifier — Device Classifier
Combines results from all 4 modules and classifies devices with priority logic.
"""

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


def _reverse_dns(ip: str) -> Optional[str]:
    try:
        name = socket.gethostbyaddr(ip)[0]
        return name if name != ip else None
    except Exception:
        return None


def classify(
    live_ips: List[str],
    mdns_map: Dict[str, str],
    port_results: Dict[str, DeviceInfo],
    artnet_nodes: List[ArtNetNode],
) -> List[Device]:
    """
    Consolidate all scanner results into a unified Device list.

    Priority order:
    1. ArtNet Poll (most reliable for lighting nodes)
    2. HTTP Fingerprint Tasmota/Shelly
    3. mDNS name
    4. Port scan heuristics
    5. Unknown
    """
    devices: List[Device] = []
    artnet_by_ip = {node.ip: node for node in artnet_nodes}

    for ip in live_ips:
        artnet = artnet_by_ip.get(ip)
        port_info = port_results.get(ip)
        mdns_name = mdns_map.get(ip)
        hostname = mdns_name or _reverse_dns(ip)

        # Priority 1 — ArtNet
        if artnet:
            friendly = artnet.long_name or artnet.short_name or None
            universes = artnet.num_ports
            devices.append(Device(
                ip=ip,
                hostname=hostname,
                device_type="ArtNet Node",
                friendly_name=friendly,
                details={
                    "short_name": artnet.short_name,
                    "long_name": artnet.long_name,
                    "num_ports": artnet.num_ports,
                    "universe": artnet.universe,
                },
                discovery_method="artnet_poll",
            ))
            continue

        # Priority 2 — Tasmota/Shelly from HTTP fingerprint
        if port_info and port_info.device_type in ("Tasmota", "Shelly"):
            devices.append(Device(
                ip=ip,
                hostname=hostname,
                device_type=port_info.device_type,
                friendly_name=port_info.friendly_name,
                details=port_info.details,
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
                details={},
                discovery_method="mdns",
            ))
            continue

        # Priority 4 — Port scan heuristic
        if port_info and port_info.device_type:
            devices.append(Device(
                ip=ip,
                hostname=hostname,
                device_type=port_info.device_type,
                friendly_name=port_info.friendly_name,
                details=port_info.details,
                discovery_method="port_scan",
            ))
            continue

        # Priority 5 — Unknown
        devices.append(Device(
            ip=ip,
            hostname=hostname,
            device_type="Desconhecido",
            friendly_name=None,
            details={},
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
    if "iphone" in name_lower or "ipad" in name_lower or "apple" in name_lower:
        return "iPhone/iPad"
    if "android" in name_lower:
        return "Android"
    if "windows" in name_lower or "desktop" in name_lower or "laptop" in name_lower:
        return "Windows PC"
    return "Web Device"
