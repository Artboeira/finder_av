"""
Display — Reporter
Renders the final result in the terminal with colors and icons per device type.
"""

from typing import List, Optional

from identifier.device_classifier import Device

ICONS = {
    "Tasmota":      "🎛️ ",
    "Shelly":       "🔌 ",
    "ArtNet Node":  "💡 ",
    "Windows PC":   "🖥️ ",
    "Linux/Mac":    "🐧 ",
    "iPhone/iPad":  "📱 ",
    "Android":      "🤖 ",
    "WLED":              "🌈 ",
    "UPnP Device":       "📡 ",
    "Smart TV":          "📺 ",
    "NAS":               "🗄️ ",
    "Sonos":             "🎵 ",
    "Streaming Device":  "📺 ",
    "Chromecast":        "📺 ",
    "Apple Device":      "🍎 ",
    "Linux Device":      "🐧 ",
    "IoT Device (ESP)":  "📟 ",
    "Web Device":        "🌐 ",
    "Desconhecido":      "❓ ",
}

TYPE_COLORS = {
    "Tasmota":      "yellow",
    "Shelly":       "cyan",
    "ArtNet Node":  "bright_yellow",
    "Windows PC":   "blue",
    "Linux/Mac":    "green",
    "iPhone/iPad":  "magenta",
    "Android":      "bright_green",
    "WLED":             "bright_magenta",
    "UPnP Device":      "bright_cyan",
    "Smart TV":         "bright_cyan",
    "NAS":              "bright_cyan",
    "Sonos":            "bright_cyan",
    "Streaming Device": "bright_cyan",
    "Chromecast":       "bright_cyan",
    "Apple Device":     "magenta",
    "Linux Device":     "green",
    "IoT Device (ESP)": "yellow",
    "Web Device":       "white",
    "Desconhecido":     "dim white",
}


def _icon(device_type: str) -> str:
    return ICONS.get(device_type, "❓ ")


def _color(device_type: str) -> str:
    return TYPE_COLORS.get(device_type, "white")


def render_report(
    devices: List[Device],
    local_ip: str,
    subnet: str,
    elapsed: float,
) -> None:
    """Render the full scan report using rich."""
    try:
        from rich import box
        from rich.console import Console
        from rich.table import Table
        from rich.text import Text
        from rich.panel import Panel

        console = Console()

        # Header panel
        header_text = Text(justify="center")
        header_text.append("🎭 SALA IMERSIVA — NETWORK SCAN\n", style="bold white")
        header_text.append(f"Sua máquina: {local_ip}  |  Subnet: {subnet}", style="dim")
        console.print(Panel(header_text, border_style="bright_blue", padding=(0, 2)))

        if not devices:
            console.print("[dim]Nenhum dispositivo encontrado.[/dim]")
            return

        table = Table(
            show_header=True,
            header_style="bold bright_blue",
            border_style="bright_blue",
            box=box.DOUBLE_EDGE,
            expand=False,
            padding=(0, 1),
        )

        table.add_column("IP", style="bold white", min_width=16)
        table.add_column("Tipo", min_width=22)
        table.add_column("Nome / Hostname", min_width=24)
        table.add_column("Método", style="dim", min_width=16)
        table.add_column("Detalhes", style="dim", min_width=20)

        for dev in devices:
            icon = _icon(dev.device_type)
            color = _color(dev.device_type)
            type_cell = f"[{color}]{icon}{dev.device_type}[/{color}]"

            name = dev.friendly_name or dev.hostname or "—"

            details_parts = []
            if dev.device_type == "ArtNet Node":
                if dev.details.get("num_ports"):
                    details_parts.append(f"ports={dev.details['num_ports']}")
                if dev.details.get("universe") is not None:
                    details_parts.append(f"univ={dev.details['universe']}")
            elif dev.device_type == "Tasmota":
                if dev.details.get("module"):
                    details_parts.append(f"mod={dev.details['module']}")
            elif dev.device_type == "Shelly":
                if dev.details.get("mac"):
                    details_parts.append(f"mac={dev.details['mac']}")
            elif dev.device_type == "WLED":
                if dev.details.get("leds"):
                    details_parts.append(f"leds={dev.details['leds']}")
                if dev.details.get("version"):
                    details_parts.append(f"v{dev.details['version']}")
            elif dev.device_type in ("UPnP Device", "Smart TV", "NAS", "Sonos",
                                     "Streaming Device", "Chromecast"):
                if dev.details.get("server"):
                    details_parts.append(dev.details["server"][:30])

            # Show MAC vendor for all types if present
            if dev.details.get("vendor") and dev.device_type not in ("Tasmota", "Shelly", "WLED"):
                details_parts.append(f"vendor={dev.details['vendor'][:20]}")

            details_str = ", ".join(details_parts) if details_parts else "—"

            table.add_row(
                dev.ip,
                type_cell,
                name,
                dev.discovery_method,
                details_str,
            )

        console.print(table)

        # Footer
        console.print(
            f"\n  [bold]Total:[/bold] {len(devices)} dispositivo{'s' if len(devices) != 1 else ''}  "
            f"|  [bold]Scan:[/bold] {elapsed:.1f}s\n",
            style="dim",
        )

    except ImportError:
        # Fallback: plain text output
        _render_plain(devices, local_ip, subnet, elapsed)


def _render_plain(
    devices: List[Device],
    local_ip: str,
    subnet: str,
    elapsed: float,
) -> None:
    width = 70
    print("=" * width)
    print(f"  SALA IMERSIVA - NETWORK SCAN")
    print(f"  Maquina: {local_ip}  |  Subnet: {subnet}")
    print("=" * width)
    print(f"  {'IP':<18} {'Tipo':<20} {'Nome':<20}")
    print("-" * width)
    for dev in devices:
        icon = ICONS.get(dev.device_type, "? ").replace("️", "").strip()
        name = dev.friendly_name or dev.hostname or "—"
        print(f"  {dev.ip:<18} {icon} {dev.device_type:<18} {name:<20}")
    print("=" * width)
    print(f"  Total: {len(devices)} dispositivos  |  Scan: {elapsed:.1f}s")
