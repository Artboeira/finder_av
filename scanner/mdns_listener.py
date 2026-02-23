"""
Module 2 — mDNS Listener
Listens for mDNS/Bonjour announcements to capture friendly device names.
"""

import asyncio
import socket
from typing import Dict

SERVICE_TYPES = [
    "_http._tcp.local.",          # Tasmota, Shelly, any web device
    "_workstation._tcp.local.",   # Linux/Mac workstations
    "_apple-mobdev2._tcp.local.", # iPhones/iPads
    "_androiddebugbridge._tcp.local.",  # Android in debug mode
]


async def mdns_listen(timeout: float = 5.0) -> Dict[str, str]:
    """
    Browse mDNS service types and collect IP → friendly name mappings.

    Returns:
        Dict mapping IP address strings to mDNS hostnames.
    """
    results: Dict[str, str] = {}

    try:
        from zeroconf import ServiceBrowser, Zeroconf
        from zeroconf._utils.ipaddress import get_ip_address_object_from_record

        class Listener:
            def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
                try:
                    info = zc.get_service_info(type_, name, timeout=1000)
                    if info:
                        for addr_bytes in info.addresses:
                            ip = socket.inet_ntoa(addr_bytes)
                            hostname = info.server or name
                            # Strip trailing dot and .local.
                            hostname = hostname.rstrip(".").removesuffix(".local")
                            results[ip] = hostname
                except Exception:
                    pass

            def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
                pass

            def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
                pass

        zc = Zeroconf()
        listener = Listener()
        browsers = [ServiceBrowser(zc, stype, listener) for stype in SERVICE_TYPES]

        await asyncio.sleep(timeout)

        zc.close()

    except ImportError:
        # zeroconf not installed — skip silently
        pass
    except Exception:
        pass

    return results
