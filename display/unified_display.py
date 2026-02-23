"""
Unified Display — Watchdog + DMX Sniffer combined view.
Renders device health (top) and live DMX traffic (bottom) at 5fps.
Used when both --watch and --sniff flags are provided.
"""

import asyncio
from collections import deque
from datetime import datetime
from typing import Dict, List, Optional

from scanner.watchdog import DeviceStatus, Watchdog
from scanner.packet_sniffer import DMXPacket, PacketSniffer
from display.watch_display import _build_table
from display.sniff_display import _build_sniff_table


async def run_unified_display(
    watchdog: Watchdog,
    sniffer: PacketSniffer,
    known_devices: Dict[str, str],
    local_ip: str,
    subnet: str,
    scan_start: float,
    universe_filter: Optional[int] = None,
    ip_filter: Optional[str] = None,
    iface: Optional[str] = None,
) -> None:
    # ── Watchdog state ────────────────────────────────────────────────────────
    alert_log = deque(maxlen=5)

    def on_change(ds: DeviceStatus) -> None:
        t = datetime.now().strftime("%H:%M:%S")
        dev = ds.device
        name = dev.friendly_name or dev.hostname or dev.ip
        if ds.status == "offline":
            alert_log.append(f"[bright_red]⚠  {t}  {dev.ip} ({name}) ficou OFFLINE[/bright_red]")
        elif ds.status in ("online", "unstable"):
            alert_log.append(f"[bright_green]✓  {t}  {dev.ip} ({name}) voltou ONLINE[/bright_green]")

    await watchdog.start(on_status_change=on_change)

    # ── Sniffer state ─────────────────────────────────────────────────────────
    last_channels: Dict[int, List[int]] = {}
    universe_sources: Dict[int, str] = {}
    universe_protocols: Dict[int, str] = {}

    def on_packet(pkt: DMXPacket) -> None:
        last_channels[pkt.universe] = pkt.channels
        universe_sources[pkt.universe] = pkt.source_ip
        universe_protocols[pkt.universe] = pkt.protocol

    sniffer.start(
        callback=on_packet,
        universe_filter=universe_filter,
        ip_filter=ip_filter,
        iface=iface,
    )
    local_ips = sniffer.get_local_ips()

    # ── Combined render ───────────────────────────────────────────────────────
    def _build():
        from rich.console import Group
        from rich.rule import Rule
        return Group(
            _build_table(watchdog, local_ip, subnet, scan_start, alert_log),
            Rule(style="dim bright_blue"),
            _build_sniff_table(
                sniffer, last_channels, known_devices,
                universe_filter, universe_sources, universe_protocols, local_ips,
            ),
        )

    try:
        from rich.live import Live
        from rich.console import Console

        console = Console()
        with Live(_build(), console=console, refresh_per_second=5, screen=False) as live:
            while True:
                await asyncio.sleep(0.2)
                live.update(_build())
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        sniffer.stop()
        await watchdog.stop()
