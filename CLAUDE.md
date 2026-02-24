# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the tool

```bash
# Windows — must run as Administrator (required for scapy/Npcap and ICMP ping sweep)
python tomoe.py

# Linux / macOS
sudo python tomoe.py

# Scan only (skips watchdog and sniffer)
python tomoe.py --scan-only

# Sniffer without full network scan
python tomoe.py --sniff-only
```

There are no tests, no build step, and no linter configuration.

## Default behavior

`python tomoe.py` with no flags runs **unified mode**: scan → then watchdog + DMX sniffer on the same screen. This is the intended default. Flags `--watch` and `--sniff` are implicitly set to `True` unless `--scan-only`, `--watch`, `--sniff`, or `--sniff-only` is explicitly passed. The escape hatch for scan-only is `--scan-only`.

## Architecture

### Entry point and execution flow

`tomoe.py` orchestrates everything inside `async def main()`:

1. **Phase 1** (parallel tasks): `ping_sweep` → live IPs + subnet; `mdns_listen` → mDNS names; `artnet_poll` → ArtNet nodes; `ssdp_scan` → UPnP devices
2. **Phase 2** (parallel, per live IP): `port_scan` → HTTP fingerprint + state enrichment; `get_mac_vendors`; `resolve_hostnames`
3. **Phase 3**: `classify()` → returns `List[Device]`
4. **Phase 4**: `render_report()` → rich table
5. **Phase 5**: unified/watchdog/sniffer display loop (async, Ctrl+C to exit)

### Central data model

`Device` (in `identifier/device_classifier.py`) is the output of classification:
```python
@dataclass
class Device:
    ip: str
    hostname: Optional[str]
    device_type: str        # "ArtNet Node", "Tasmota", "Shelly", "WLED", "Windows PC", etc.
    friendly_name: Optional[str]
    details: Dict           # device-specific state (power, dimmer, bri, etc.)
    discovery_method: str
```

The intermediate type before classification is `DeviceInfo` in `scanner/port_scanner.py`.

### Classification priority

In `identifier/device_classifier.py → classify()`:
**ArtNet** (artnet_poll) > **HTTP** (Tasmota/Shelly/WLED) > **mDNS** > **SSDP** > **port heuristic** > **MAC vendor** > **Desconhecido**

### Display layer

All display functions are `async` and use `rich.Live`. The key building blocks:

| Function | File | Purpose |
|----------|------|---------|
| `_build_table()` | `display/watch_display.py` | Watchdog table — importable, returns `Group` |
| `_build_sniff_table()` | `display/sniff_display.py` | DMX sniffer table — importable, returns `Group` |
| `run_unified_display()` | `display/unified_display.py` | Stacks both with `rich.Rule`, runs at 5fps |
| `run_watch_display()` | `display/watch_display.py` | Watchdog only, runs at 1fps |
| `run_sniff_display()` | `display/sniff_display.py` | Sniffer only, runs at 5fps |

### Packet capture (`scanner/packet_sniffer.py`)

`PacketSniffer` tries two modes in sequence:
1. **SCAPY** (primary): raw packet capture via Npcap/libpcap — captures all traffic including outgoing. Requires admin/sudo.
2. **SOCKET** (fallback): UDP socket bind on ports 6454/5568 — no admin needed, captures incoming + broadcast. Falls back automatically if scapy raises any exception (stored in `self._error`, exposed via `get_error()`).

The capture mode is exposed via `get_capture_mode()` → `"scapy" | "socket" | "error" | "starting"` and shown live in the sniffer header.

### Watchdog (`scanner/watchdog.py`)

`Watchdog` creates one `asyncio.Task` per device with adaptive check intervals:
- 10s: ArtNet Node, Tasmota, Shelly, WLED (HTTP health check for HTTP-capable devices)
- 15s: Web Device, IoT Device (ESP) (ICMP)
- 30s: Windows PC, Linux/Mac, phones, Unknown (ICMP)

Status values: `"online"` → `"offline"` → `"unstable"` (first check after returning from offline).

## Key conventions

- **All scanner/display imports are lazy** (inside functions) so missing optional deps only fail at use time, not at startup.
- **`packet_sniffer.py` runs in a daemon thread** (not async). It is thread-safe via `threading.Lock`. Everything else is pure asyncio.
- **`_run_sniff_mode` is `async def`** in `tomoe.py` — it must be `await`ed, not called with `asyncio.run()` (which would nest event loops).
- The `Device.details` dict carries device-specific state from HTTP enrichment (`power`, `dimmer`, `uptime` for Tasmota; `ison`, `brightness`, `power_w`, `temp_c` for Shelly; `on`, `bri`, `leds` for WLED). Display in `reporter.py` reads these keys directly.
- Local IPs are detected via `netifaces` at `PacketSniffer.__init__` time and exposed as `get_local_ips() → set`. The sniffer display marks packets from local IPs as `▶ LOCAL`.
