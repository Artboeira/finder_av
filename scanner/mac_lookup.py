"""
MAC Address Lookup
Gets MAC addresses via ARP cache and resolves vendor from OUI database.
"""

import asyncio
from typing import Dict, Optional

# Vendor substrings → device hints (lowercase)
VENDOR_HINTS = {
    "espressif":     "ESP32/ESP8266",   # Tasmota, Shelly, WLED
    "raspberry pi":  "Raspberry Pi",
    "apple":         "Apple",
    "microsoft":     "Microsoft",
    "samsung":       "Samsung",
    "lg electronics":"LG",
    "sony":          "Sony",
    "synology":      "Synology NAS",
    "qnap":          "QNAP NAS",
    "roku":          "Roku",
}


def _vendor_hint(vendor: str) -> Optional[str]:
    v = vendor.lower()
    for key, label in VENDOR_HINTS.items():
        if key in v:
            return label
    return None


def _lookup_one(ip: str) -> Optional[Dict]:
    try:
        from getmac import get_mac_address
        from mac_vendor_lookup import MacLookup

        mac = get_mac_address(ip=ip)
        if not mac or mac == "00:00:00:00:00:00":
            return None

        vendor = ""
        try:
            vendor = MacLookup().lookup(mac) or ""
        except Exception:
            pass

        return {
            "mac": mac,
            "vendor": vendor,
            "vendor_hint": _vendor_hint(vendor),
        }
    except ImportError:
        return None
    except Exception:
        return None


async def get_mac_vendors(live_ips: list) -> Dict[str, Dict]:
    """
    Resolve MAC address and vendor for each live IP via ARP cache.

    Returns:
        Dict[ip -> {"mac": str, "vendor": str, "vendor_hint": str|None}]
    """
    semaphore = asyncio.Semaphore(32)

    async def _one(ip: str):
        async with semaphore:
            result = await asyncio.to_thread(_lookup_one, ip)
            return ip, result

    results = await asyncio.gather(*[_one(ip) for ip in live_ips])
    return {ip: info for ip, info in results if info is not None}
