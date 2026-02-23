"""
Sniff Display — Live DMX Traffic Monitor
Renders ArtNet/sACN packet traffic with rich.Live at 200ms refresh (5fps).
"""

import asyncio
import time
from typing import Dict, List, Optional

from scanner.packet_sniffer import DMXPacket, PacketSniffer

# DMX preview bar: 16 channels, unicode block characters
_BAR_CHARS = [" ", "░", "▓", "█"]


def _dmx_preview(channels: List[int], count: int = 16) -> str:
    result = []
    for v in channels[:count]:
        if v == 0:
            result.append(" ")
        elif v <= 127:
            result.append("░")
        elif v <= 254:
            result.append("▓")
        else:
            result.append("█")
    return "".join(result)


def _active_channel_count(channels: List[int]) -> int:
    return sum(1 for v in channels if v > 0)


def _build_sniff_table(
    sniffer: PacketSniffer,
    last_channels: Dict[int, List[int]],
    known_devices: Dict[str, str],
    universe_filter: Optional[int],
    universe_sources: Dict[int, str],
    universe_protocols: Dict[int, str],
    local_ips: set,
):
    from rich import box
    from rich.console import Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    universes = sniffer.get_active_universes()
    if universe_filter is not None:
        universes = [u for u in universes if u == universe_filter]

    header = Text(justify="left")
    header.append("📡 TOMOE — DMX SNIFFER", style="bold white")

    mode = sniffer.get_capture_mode()
    error = sniffer.get_error()
    if mode == "scapy":
        header.append("   ● SCAPY", style="bright_green")
    elif mode == "socket":
        header.append("   ● SOCKET", style="yellow")
        if error:
            header.append(f"   ({error[:70]})", style="dim red")
    elif mode == "error":
        header.append(f"   ● ERRO: {(error or '')[:80]}", style="bright_red")
    else:
        header.append("   iniciando...", style="dim")

    header.append("   Ctrl+C para sair", style="dim")

    table = Table(
        show_header=True,
        header_style="bold bright_blue",
        border_style="bright_blue",
        box=box.SIMPLE_HEAVY,
        expand=False,
        padding=(0, 1),
    )
    table.add_column("Universo", min_width=10, justify="center")
    table.add_column("Proto", min_width=7)
    table.add_column("Source", min_width=26)
    table.add_column("fps", min_width=6, justify="right")
    table.add_column("Ativos", min_width=7, justify="right")
    table.add_column("Preview (16ch)", min_width=18)

    if not universes:
        table.add_row("—", "—", "aguardando pacotes...", "—", "—", "")
    else:
        for univ in universes:
            fps = sniffer.get_fps(univ)
            frozen = sniffer.is_frozen(univ)
            proto = universe_protocols.get(univ, "")
            src_ip = universe_sources.get(univ, "?")
            is_local = src_ip in local_ips
            if is_local:
                name = known_devices.get(src_ip) or "esta máquina"
                source_cell = f"[bright_green]▶ LOCAL — {src_ip} ({name[:14]})[/bright_green]"
            elif src_ip in known_devices:
                source_cell = f"{src_ip} ({known_devices[src_ip][:12]})"
            else:
                source_cell = src_ip

            current = last_channels.get(univ, [0] * 512)
            active = _active_channel_count(current)

            if frozen:
                preview_cell = "[bright_red]🔴 FREEZE[/bright_red]"
                fps_cell = "[bright_red]0.0[/bright_red]"
            else:
                preview_cell = _dmx_preview(current)
                fps_cell = f"{fps:.1f}"

            table.add_row(
                str(univ),
                proto,
                source_cell,
                fps_cell,
                str(active),
                preview_cell,
            )

    return Group(
        Panel(header, border_style="bright_blue", padding=(0, 2)),
        table,
    )


async def run_sniff_display(
    sniffer: PacketSniffer,
    known_devices: Optional[Dict[str, str]] = None,
    universe_filter: Optional[int] = None,
    ip_filter: Optional[str] = None,
    iface: Optional[str] = None,
) -> None:
    known_devices = known_devices or {}
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

    try:
        from rich.live import Live
        from rich.console import Console

        console = Console()
        with Live(
            _build_sniff_table(
                sniffer, last_channels, known_devices,
                universe_filter, universe_sources, universe_protocols, local_ips,
            ),
            console=console,
            refresh_per_second=5,
            screen=False,
        ) as live:
            while True:
                await asyncio.sleep(0.2)
                live.update(
                    _build_sniff_table(
                        sniffer, last_channels, known_devices,
                        universe_filter, universe_sources, universe_protocols, local_ips,
                    )
                )
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        sniffer.stop()
