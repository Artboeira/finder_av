"""
Watchdog — Continuous Device Health Monitor
Runs adaptive health checks per device type and tracks online/offline status.
"""

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional, Tuple

from identifier.device_classifier import Device

PING_INTERVALS: Dict[str, int] = {
    "ArtNet Node":      10,
    "Tasmota":          10,
    "Shelly":           10,
    "WLED":             10,
    "Web Device":       15,
    "IoT Device (ESP)": 15,
    "Windows PC":       30,
    "Linux/Mac":        30,
    "iPhone/iPad":      30,
    "Android":          30,
    "Desconhecido":     30,
}

HTTP_CHECKABLE = {"Tasmota", "Shelly", "WLED"}
HTTP_PATHS = {
    "Tasmota": "/cm?cmnd=Status",
    "Shelly":  "/shelly",
    "WLED":    "/json/info",
}


@dataclass
class DeviceStatus:
    device: Device
    status: str = "online"          # "online" | "offline" | "unstable"
    last_seen: datetime = field(default_factory=datetime.now)
    downtime_count: int = 0
    latency_ms: float = 0.0
    last_check: datetime = field(default_factory=datetime.now)


class Watchdog:
    def __init__(
        self,
        devices: List[Device],
        base_interval: Optional[int] = None,
    ) -> None:
        self._statuses: Dict[str, DeviceStatus] = {
            d.ip: DeviceStatus(device=d) for d in devices
        }
        self._base_interval = base_interval
        self._tasks: List[asyncio.Task] = []
        self._on_change: Optional[Callable[[DeviceStatus], None]] = None

    async def start(self, on_status_change: Optional[Callable[[DeviceStatus], None]] = None) -> None:
        self._on_change = on_status_change
        for ds in self._statuses.values():
            task = asyncio.create_task(self._check_loop(ds))
            self._tasks.append(task)

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

    def get_statuses(self) -> Dict[str, DeviceStatus]:
        return self._statuses

    async def _check_loop(self, ds: DeviceStatus) -> None:
        interval = self._base_interval or PING_INTERVALS.get(ds.device.device_type, 30)
        while True:
            await asyncio.sleep(interval)
            alive, latency = await self._check_once(ds.device)
            prev = ds.status
            if alive:
                ds.latency_ms = latency
                ds.last_seen = datetime.now()
                ds.status = "unstable" if prev == "offline" else "online"
            else:
                if prev in ("online", "unstable"):
                    ds.downtime_count += 1
                ds.status = "offline"
            ds.last_check = datetime.now()
            if ds.status != prev and self._on_change:
                self._on_change(ds)

    async def _check_once(self, device: Device) -> Tuple[bool, float]:
        t0 = time.monotonic()
        if device.device_type in HTTP_CHECKABLE:
            path = HTTP_PATHS[device.device_type]
            try:
                import httpx
                async with httpx.AsyncClient(verify=False, timeout=3.0) as c:
                    r = await c.get(f"http://{device.ip}{path}")
                    elapsed = (time.monotonic() - t0) * 1000
                    return r.status_code == 200, elapsed
            except Exception:
                return False, 0.0
        else:
            from scanner.ping_sweep import _ping_one
            result = await asyncio.to_thread(_ping_one, device.ip)
            elapsed = (time.monotonic() - t0) * 1000
            return result is not None, elapsed
