"""
TOMOE — Network Scanner Toolkit
Discovers and identifies all devices on the local subnet.

Usage:
    python tomoe.py
    python tomoe.py --subnet 192.168.10.0/24
    python tomoe.py --timeout 10
    python tomoe.py --watch
    python tomoe.py --sniff
    python tomoe.py --sniff-only
"""

import argparse
import asyncio
import sys
import time
from pathlib import Path


def print_banner() -> None:
    banner_path = Path(__file__).parent / "capa.txt"
    try:
        text = banner_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return

    lines = text.splitlines()
    delay = 1.3 / max(len(lines), 1)

    try:
        from rich.console import Console
        from rich.text import Text

        console = Console()
        for line in lines:
            styled_line = Text(line)
            if "by Z1t0s" in line:
                styled_line.stylize("bold cyan")
            else:
                styled_line.stylize("red")
            console.print(styled_line)
            time.sleep(delay)
    except ImportError:
        for line in lines:
            print(line)
            time.sleep(delay)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="TOMOE — Network Scanner Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--subnet",
        type=str,
        default=None,
        help="Subnet to scan, e.g. 192.168.1.0/24 (auto-detected if omitted)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="mDNS listen timeout in seconds (default: 5)",
    )
    parser.add_argument(
        "--artnet-timeout",
        type=float,
        default=2.0,
        dest="artnet_timeout",
        help="ArtNet poll listen timeout in seconds (default: 2)",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="After scan, enter continuous watchdog monitor mode",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=None,
        help="Override watchdog check interval in seconds for all devices",
    )
    parser.add_argument(
        "--sniff",
        action="store_true",
        help="After scan, enter live DMX sniffer mode (requires scapy)",
    )
    parser.add_argument(
        "--sniff-only",
        action="store_true",
        dest="sniff_only",
        help="Only run DMX sniffer, skip network scan (requires scapy)",
    )
    parser.add_argument(
        "--universe",
        type=int,
        default=None,
        help="Filter sniffer to a specific ArtNet/sACN universe",
    )
    parser.add_argument(
        "--sniff-ip",
        type=str,
        default=None,
        dest="sniff_ip",
        help="Filter sniffer to packets from a specific source IP",
    )
    return parser.parse_args()


def _run_sniff_mode(known_devices: dict, args: argparse.Namespace) -> None:
    try:
        from scanner.packet_sniffer import PacketSniffer
        from display.sniff_display import run_sniff_display
    except ImportError:
        print("\n[erro] scapy não encontrado. Instale: pip install scapy")
        print("       Windows: instale Npcap em https://npcap.com")
        print("       Linux/macOS: execute com sudo\n")
        return
    sniffer = PacketSniffer()
    asyncio.run(run_sniff_display(
        sniffer,
        known_devices=known_devices,
        universe_filter=args.universe,
        ip_filter=args.sniff_ip,
    ))


async def main() -> None:
    print_banner()
    args = parse_args()

    # ── --sniff-only: skip scan entirely ─────────────────────────────────────
    if args.sniff_only:
        _run_sniff_mode(known_devices={}, args=args)
        return

    start_time = time.monotonic()

    # Lazy imports (so missing optional deps only fail at use time)
    from scanner.ping_sweep import ping_sweep
    from scanner.mdns_listener import mdns_listen
    from scanner.artnet_poll import artnet_poll
    from scanner.ssdp_scanner import ssdp_scan
    from scanner.mac_lookup import get_mac_vendors
    from scanner.port_scanner import port_scan
    from identifier.device_classifier import classify, resolve_hostnames
    from display.reporter import render_report

    print("🔍 Iniciando varredura da rede...\n")

    # ── Step 1: Ping sweep + mDNS + ArtNet + SSDP in parallel ────────────────
    ping_task   = asyncio.create_task(ping_sweep(subnet=args.subnet))
    mdns_task   = asyncio.create_task(mdns_listen(timeout=args.timeout))
    artnet_task = asyncio.create_task(artnet_poll(timeout=args.artnet_timeout))
    ssdp_task   = asyncio.create_task(ssdp_scan(timeout=3.0))

    live_ips, local_ip, subnet = await ping_task
    mdns_map     = await mdns_task
    artnet_nodes = await artnet_task
    ssdp_map     = await ssdp_task

    if not live_ips:
        print("Nenhum host encontrado. Verifique a conectividade de rede.")
        sys.exit(0)

    print(f"  Ping sweep: {len(live_ips)} host(s) encontrado(s)")
    print(f"  mDNS: {len(mdns_map)} nome(s) capturado(s)")
    print(f"  ArtNet: {len(artnet_nodes)} node(s) encontrado(s)")
    print(f"  SSDP: {len(ssdp_map)} dispositivo(s) UPnP encontrado(s)")
    print(f"\n🔎 Identificando dispositivos...\n")

    # ── Step 2: MAC lookup + port scan + DNS resolution in parallel ───────────
    port_task = asyncio.create_task(port_scan(live_ips))
    mac_task  = asyncio.create_task(get_mac_vendors(live_ips))
    dns_task  = asyncio.create_task(resolve_hostnames(live_ips, mdns_map))

    port_results   = await port_task
    mac_vendor_map = await mac_task
    hostname_map   = await dns_task

    print(f"  MAC vendors: {len(mac_vendor_map)} endereço(s) resolvido(s)")

    # ── Step 3: Classify ──────────────────────────────────────────────────────
    devices = classify(
        live_ips, mdns_map, port_results, artnet_nodes,
        ssdp_map=ssdp_map,
        mac_vendor_map=mac_vendor_map,
        hostname_map=hostname_map,
    )

    # ── Step 4: Render ────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start_time
    render_report(devices, local_ip, subnet, elapsed)

    # ── Step 5 (optional): Watch mode ─────────────────────────────────────────
    if args.watch:
        from scanner.watchdog import Watchdog
        from display.watch_display import run_watch_display
        watchdog = Watchdog(devices, base_interval=args.interval)
        await run_watch_display(watchdog, local_ip, subnet, start_time)
        return

    # ── Step 5 (optional): Sniff mode ─────────────────────────────────────────
    if args.sniff:
        known = {d.ip: d.friendly_name or d.hostname for d in devices}
        _run_sniff_mode(known_devices=known, args=args)


if __name__ == "__main__":
    asyncio.run(main())
