"""
Module 3 — Port Scanner + HTTP Fingerprint
For each live IP, tests ports and makes HTTP requests to identify device type.
"""

import asyncio
import socket
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class DeviceInfo:
    ip: str
    open_ports: List[int] = field(default_factory=list)
    device_type: Optional[str] = None
    friendly_name: Optional[str] = None
    details: Dict = field(default_factory=dict)


TCP_PORTS = {
    80: "HTTP",
    22: "SSH",
    3389: "RDP",
    62078: "iPhone-sync",
    5555: "ADB",
}

HTTP_TIMEOUT = 1.0
TCP_TIMEOUT = 0.5


async def _tcp_port_open(ip: str, port: int) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=TCP_TIMEOUT
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _http_get(client, ip: str, path: str) -> Optional[tuple]:
    """Returns (status_code, body_text) or None on failure."""
    try:
        url = f"http://{ip}{path}"
        resp = await client.get(url, timeout=HTTP_TIMEOUT)
        return resp.status_code, resp.text
    except Exception:
        return None


async def _fingerprint_tasmota(client, ip: str) -> Optional[Dict]:
    result = await _http_get(client, ip, "/cm?cmnd=Status")
    if result is None:
        return None
    status_code, body = result
    if status_code == 200 and '"Status"' in body:
        try:
            import json
            data = json.loads(body)
            status = data.get("Status", {})
            return {
                "friendly_name": status.get("FriendlyName", [None])[0],
                "module": status.get("Module"),
            }
        except Exception:
            return {}
    return None


async def _fingerprint_shelly(client, ip: str) -> Optional[Dict]:
    result = await _http_get(client, ip, "/shelly")
    if result is None:
        return None
    status_code, body = result
    if status_code == 200 and '"type"' in body:
        try:
            import json
            data = json.loads(body)
            return {
                "type": data.get("type"),
                "mac": data.get("mac"),
            }
        except Exception:
            return {}
    return None


async def _get_ssh_banner(ip: str) -> bool:
    """Check if SSH banner is present."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, 22), timeout=TCP_TIMEOUT
        )
        banner = await asyncio.wait_for(reader.read(64), timeout=0.5)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return b"SSH" in banner
    except Exception:
        return False


async def _get_adb_banner(ip: str) -> bool:
    """Check if ADB banner is present on port 5555."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, 5555), timeout=TCP_TIMEOUT
        )
        # ADB sends a CNXN packet; just check port is open + read a bit
        data = await asyncio.wait_for(reader.read(32), timeout=0.5)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return len(data) > 0
    except Exception:
        return False


async def _scan_one(ip: str) -> DeviceInfo:
    info = DeviceInfo(ip=ip)

    try:
        import httpx
        async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
            # HTTP fingerprinting (port 80)
            port80_open = await _tcp_port_open(ip, 80)
            if port80_open:
                info.open_ports.append(80)

                # Try Tasmota first
                tasmota = await _fingerprint_tasmota(client, ip)
                if tasmota is not None:
                    info.device_type = "Tasmota"
                    info.friendly_name = tasmota.get("friendly_name")
                    info.details = tasmota
                    return info

                # Try Shelly
                shelly = await _fingerprint_shelly(client, ip)
                if shelly is not None:
                    info.device_type = "Shelly"
                    info.friendly_name = shelly.get("type")
                    info.details = shelly
                    return info

                # Generic web device
                info.device_type = "Web Device"

    except ImportError:
        # httpx not available — skip HTTP fingerprinting
        port80_open = await _tcp_port_open(ip, 80)
        if port80_open:
            info.open_ports.append(80)
            info.device_type = "Web Device"

    # TCP port heuristics (run in parallel)
    checks = await asyncio.gather(
        _tcp_port_open(ip, 22),
        _tcp_port_open(ip, 3389),
        _tcp_port_open(ip, 62078),
        _tcp_port_open(ip, 5555),
    )
    ssh_open, rdp_open, iphone_open, adb_open = checks

    if rdp_open:
        info.open_ports.append(3389)
        if info.device_type is None:
            info.device_type = "Windows PC"
    if ssh_open:
        info.open_ports.append(22)
        if info.device_type is None:
            has_banner = await _get_ssh_banner(ip)
            if has_banner:
                info.device_type = "Linux/Mac"
    if iphone_open:
        info.open_ports.append(62078)
        if info.device_type is None:
            info.device_type = "iPhone/iPad"
    if adb_open:
        info.open_ports.append(5555)
        if info.device_type is None:
            has_banner = await _get_adb_banner(ip)
            if has_banner:
                info.device_type = "Android"

    return info


async def port_scan(live_ips: List[str]) -> Dict[str, DeviceInfo]:
    """
    Scan all live IPs in parallel.

    Returns:
        Dict mapping IP → DeviceInfo
    """
    semaphore = asyncio.Semaphore(64)

    async def _limited(ip: str) -> DeviceInfo:
        async with semaphore:
            return await _scan_one(ip)

    tasks = [_limited(ip) for ip in live_ips]
    results = await asyncio.gather(*tasks)
    return {info.ip: info for info in results}
