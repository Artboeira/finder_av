"""
Watch Display — Live Watchdog Monitor
Renders continuous device status table with rich.Live, refreshing every second.
"""

import asyncio
import time
from collections import deque
from datetime import datetime
from typing import Deque, Optional, Tuple

from scanner.watchdog import DeviceStatus, Watchdog


def _format_uptime(seconds: float) -> str:
    s = int(seconds)
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{sec:02d}"


def _format_since(dt: datetime) -> str:
    delta = int((datetime.now() - dt).total_seconds())
    if delta < 60:
        return f"{delta}s atrás"
    if delta < 3600:
        return f"{delta // 60}m atrás"
    return f"{delta // 3600}h atrás"


def _status_cell(ds: DeviceStatus) -> str:
    if ds.status == "online":
        return f"[green]🟢 {ds.latency_ms:.0f}ms[/green]"
    if ds.status == "offline":
        return f"[bright_red]🔴 OFFLINE[/bright_red]"
    # unstable
    return f"[yellow]🟡 {ds.latency_ms:.0f}ms[/yellow]"


def _build_table(
    watchdog: Watchdog,
    local_ip: str,
    subnet: str,
    session_start: float,
    alert_log: Deque[str],
):
    from rich import box
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
    from rich.panel import Panel
    from display.reporter import ICONS, TYPE_COLORS

    statuses = watchdog.get_statuses()
    uptime = _format_uptime(time.monotonic() - session_start)
    now_str = datetime.now().strftime("%H:%M:%S")

    table = Table(
        show_header=True,
        header_style="bold bright_blue",
        border_style="bright_blue",
        box=box.SIMPLE_HEAVY,
        expand=False,
        padding=(0, 1),
    )
    table.add_column("IP", style="bold white", min_width=16)
    table.add_column("Tipo", min_width=22)
    table.add_column("Nome", min_width=20)
    table.add_column("Status", min_width=14)
    table.add_column("Último check", style="dim", min_width=12)
    table.add_column("Quedas", style="dim", min_width=7, justify="center")

    sorted_statuses = sorted(
        statuses.values(),
        key=lambda ds: list(map(int, ds.device.ip.split(".")))
    )

    for ds in sorted_statuses:
        dev = ds.device
        icon = ICONS.get(dev.device_type, "❓ ")
        color = TYPE_COLORS.get(dev.device_type, "white")
        type_cell = f"[{color}]{icon}{dev.device_type}[/{color}]"
        name = dev.friendly_name or dev.hostname or "—"
        last_check = _format_since(ds.last_check)

        table.add_row(
            dev.ip,
            type_cell,
            name,
            _status_cell(ds),
            last_check,
            str(ds.downtime_count),
        )

    from rich.columns import Columns
    from rich.text import Text as RText

    header = Text(justify="left")
    header.append("🔭 TOMOE — WATCHDOG", style="bold white")
    header.append(f"   {subnet}   {now_str}   sessão {uptime}", style="dim")

    from rich.console import Group
    from rich.padding import Padding

    parts = [
        Panel(header, border_style="bright_blue", padding=(0, 2)),
        table,
    ]

    if alert_log:
        alert_lines = "\n".join(list(alert_log)[-5:])
        parts.append(Padding(alert_lines, (0, 2)))

    return Group(*parts)


async def run_watch_display(
    watchdog: Watchdog,
    local_ip: str,
    subnet: str,
    scan_start: float,
) -> None:
    alert_log: Deque[str] = deque(maxlen=5)

    def on_change(ds: DeviceStatus) -> None:
        t = datetime.now().strftime("%H:%M:%S")
        dev = ds.device
        name = dev.friendly_name or dev.hostname or dev.ip
        if ds.status == "offline":
            alert_log.append(f"[bright_red]⚠  {t}  {dev.ip} ({name}) ficou OFFLINE[/bright_red]")
        elif ds.status in ("online", "unstable"):
            alert_log.append(f"[bright_green]✓  {t}  {dev.ip} ({name}) voltou ONLINE[/bright_green]")

    await watchdog.start(on_status_change=on_change)

    try:
        from rich.live import Live
        from rich.console import Console

        console = Console()
        with Live(
            _build_table(watchdog, local_ip, subnet, scan_start, alert_log),
            console=console,
            refresh_per_second=1,
            screen=False,
        ) as live:
            while True:
                await asyncio.sleep(1.0)
                live.update(
                    _build_table(watchdog, local_ip, subnet, scan_start, alert_log)
                )
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await watchdog.stop()
