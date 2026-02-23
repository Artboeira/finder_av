"""
Module 1 — Ping Sweep
Scans the entire subnet in parallel using threads, returns list of live IPs.
"""

import asyncio
import ipaddress
import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Tuple


def _get_local_ip_and_subnet() -> Tuple[str, str]:
    """Detect the machine's own IP and subnet using netifaces or fallback."""
    try:
        import netifaces
        gateways = netifaces.gateways()
        default_iface = gateways.get("default", {}).get(netifaces.AF_INET, [None, None])[1]
        if default_iface:
            addrs = netifaces.ifaddresses(default_iface).get(netifaces.AF_INET, [])
            if addrs:
                ip = addrs[0]["addr"]
                netmask = addrs[0]["netmask"]
                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                return ip, str(network)
    except Exception:
        pass

    # Fallback: connect to public DNS to find local IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        return ip, str(network)
    except Exception:
        return "127.0.0.1", "127.0.0.0/24"


def _ping_one(ip: str) -> Optional[str]:
    """Ping a single IP. Returns the IP if alive, None otherwise."""
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", "1", "-w", "300", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=1.5,
        )
        return ip if result.returncode == 0 else None
    except Exception:
        return None


async def ping_sweep(subnet: Optional[str] = None) -> Tuple[List[str], str, str]:
    """
    Sweep the entire subnet and return live IPs.

    Returns:
        (live_ips, local_ip, subnet_cidr)
    """
    local_ip, detected_subnet = _get_local_ip_and_subnet()
    target_subnet = subnet or detected_subnet

    network = ipaddress.IPv4Network(target_subnet, strict=False)
    all_ips = [str(h) for h in network.hosts()]

    live_ips: List[str] = []

    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor(max_workers=256) as executor:
        futures = [loop.run_in_executor(executor, _ping_one, ip) for ip in all_ips]
        results = await asyncio.gather(*futures)

    live_ips = [ip for ip in results if ip is not None]
    live_ips.sort(key=lambda x: ipaddress.IPv4Address(x))

    return live_ips, local_ip, target_subnet
