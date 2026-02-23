# TOMOE -  Network Scanner Toolkit

Descobre e identifica automaticamente todos os dispositivos de uma subnet — dimmers Tasmota, relés Shelly, nodes ArtNet, tablets, computadores — e exibe um relatório visual colorido no terminal.

Modos adicionais: **watchdog** contínuo de status e **sniffer** de tráfego DMX ao vivo.

For VJ's, light designers, creative technologists, artists and nerds

```

                                                        .........
                                                ..:::::::::::::::::::::...
                                           ..::::::::::...........:::::::::::..
                                       ..::::::..                        ..::::::.
                                     .::::..                  .               .:::::..
                                  ..:::..                 .... .                 ..:::..
                                ..::..                  ..::...                     ..::..
                              ..::..                   .::. .....                      .::..
                            ..::.                     .::.  .::::..                      .::..
                           .::.                       .:.      ..::                       ..::.
                          .::                         ::         .:.                        .::.
                        .::.                     .... .:.         :. ....                     .::
                       .::.                   ....... .::        .:. .......                   .::.
                      .::                   ..  . ...   :::....:::.  ... . ...                   ::
                      ::                  ..  ...       ..::::::..       ..  ...                 .::
                     .:.                ... ..              .              ..  .                  .:.
                    .:.                .. ..                                 .. ...                .:.
                    ::                .. ..                                     . ..                :.
                   .:.                . ..                                      .. .                .:.
                   :.                . ..                 ..::..                 .. .                :.
                  .:.               .. .               ..::::::::..               . ..               .:.
                  .:.               ...              ..::..    ..::..              ...               .:.
                  ::                ...              ::.          .:.              ...                ::
                  ::                 .              .:.            .:.             ..                 ::
                  ::                                .:             .:.                                ::
                  ::                                .:.            .:.                                ::
                  .:                ...              ::.          .:.              ...                :.
                  .:                :.::::..         ..::..    ..::..         ..::::.:               .:.
                  .:.             ..:..:::::..         ..::::::::..         ..:::::..::.             .:.
                   ::            .::.      .::.           ..::..           .::.      .:::.           :.
                   .:.           .:.        .:.                            .:.         .::          .:.
                    ::           .:          :.                            .:            :.         :.
                    .:.       ..:...       .::.                            .:.       ..:..:.       .:.
                     .:.      .  ...    ..::..                             ...:::::::::.:...      .:.
                      ::.     .::::::::::::.. ...                        ..  ..:::::... ....     .::.
                       ::        ..::::..   ..  . ...                 .. . ...                  .::
                       .::.                   .......  ..:......:..  ......                    .::
                         ::.                      ... ..          ..  ...                     .::
                         ..:..                         .::......::.                         ..:.
                           .::.                                                            .::.
                            ..::.                                                        .::..
                              .:::..                                                   .::..
                                ..::..                                              ..::..
                                  ..:::..                                        ..:::..
                                    ..::::..                                  ..:::..
                                       ..::::::..                        ..::::::..
                                           .:::::::::::... .    ...::::::::::..
                                                ..:::::::::::::::::::::...
                                                        ..........


          __╱╲╲╲╲╲╲╲╲╲╲╲╲╲╲╲__╱╲╲╲╲╲╲╲╲╲╲╲__╱╲╲╲╲╲_____╱╲╲╲__╱╲╲╲╲╲╲╲╲╲╲╲╲_____╱╲╲╲╲╲╲╲╲╲╲╲╲╲╲╲____╱╲╲╲╲╲╲╲╲╲_____
           _╲╱╲╲╲╱╱╱╱╱╱╱╱╱╱╱__╲╱╱╱╱╱╲╲╲╱╱╱__╲╱╲╲╲╲╲╲___╲╱╲╲╲_╲╱╲╲╲╱╱╱╱╱╱╱╱╲╲╲__╲╱╲╲╲╱╱╱╱╱╱╱╱╱╱╱___╱╲╲╲╱╱╱╱╱╱╱╲╲╲___
            _╲╱╲╲╲_________________╲╱╲╲╲_____╲╱╲╲╲╱╲╲╲__╲╱╲╲╲_╲╱╲╲╲______╲╱╱╲╲╲_╲╱╲╲╲_____________╲╱╲╲╲_____╲╱╲╲╲___
             _╲╱╲╲╲╲╲╲╲╲╲╲╲_________╲╱╲╲╲_____╲╱╲╲╲╱╱╲╲╲_╲╱╲╲╲_╲╱╲╲╲_______╲╱╲╲╲_╲╱╲╲╲╲╲╲╲╲╲╲╲_____╲╱╲╲╲╲╲╲╲╲╲╲╲╱____
              _╲╱╲╲╲╱╱╱╱╱╱╱__________╲╱╲╲╲_____╲╱╲╲╲╲╱╱╲╲╲╲╱╲╲╲_╲╱╲╲╲_______╲╱╲╲╲_╲╱╲╲╲╱╱╱╱╱╱╱______╲╱╲╲╲╱╱╱╱╱╱╲╲╲____
               _╲╱╲╲╲_________________╲╱╲╲╲_____╲╱╲╲╲_╲╱╱╲╲╲╱╲╲╲_╲╱╲╲╲_______╲╱╲╲╲_╲╱╲╲╲_____________╲╱╲╲╲____╲╱╱╲╲╲___
                _╲╱╲╲╲_________________╲╱╲╲╲_____╲╱╲╲╲__╲╱╱╲╲╲╲╲╲_╲╱╲╲╲_______╱╲╲╲__╲╱╲╲╲_____________╲╱╲╲╲_____╲╱╱╲╲╲__
                 _╲╱╲╲╲______________╱╲╲╲╲╲╲╲╲╲╲╲_╲╱╲╲╲___╲╱╱╲╲╲╲╲_╲╱╲╲╲╲╲╲╲╲╲╲╲╲╱___╲╱╲╲╲╲╲╲╲╲╲╲╲╲╲╲╲_╲╱╲╲╲______╲╱╱╲╲╲_
                  _╲╱╱╱______________╲╱╱╱╱╱╱╱╱╱╱╱__╲╱╱╱_____╲╱╱╱╱╱__╲╱╱╱╱╱╱╱╱╱╱╱╱_____╲╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱__╲╱╱╱________╲╱╱╱__


                                                         by Z1t0s *-*
```

---

## Funcionalidades

### Detecção de dispositivos

| Ícone | Tipo de dispositivo | Método de detecção |
|-------|---------------------|--------------------|
| 🎛️ | Tasmota (dimmer / relay) | HTTP `/cm?cmnd=Status` + estado atual |
| 🔌 | Shelly | HTTP `/shelly` + estado atual |
| 🌈 | WLED | HTTP `/json/info` + estado atual |
| 💡 | ArtNet Node | ArtPoll UDP broadcast |
| 🖥️ | Windows PC | Porta RDP 3389 |
| 🐧 | Linux / Mac | Banner SSH porta 22 |
| 📱 | iPhone / iPad | Porta 62078 / mDNS |
| 🤖 | Android | Banner ADB porta 5555 |
| 📡 | UPnP Device | SSDP M-SEARCH |
| 📺 | Smart TV (Samsung/LG/Sony) | SSDP server string |
| 🗄️ | NAS (Synology/QNAP) | SSDP server string |
| 🎵 | Sonos | SSDP server string |
| 📟 | IoT Device (ESP) | MAC vendor Espressif |
| 🍎 | Apple Device | MAC vendor Apple |
| 🌐 | Web Device genérico | HTTP porta 80 |
| ❓ | Desconhecido | — |

### Modos de operação

| Modo | Flag | Descrição |
|------|------|-----------|
| **Scan** | *(padrão)* | Varre a subnet, identifica e exibe todos os dispositivos |
| **Watchdog** | `--watch` | Scan + monitoramento contínuo de status (online/offline) |
| **Sniffer** | `--sniff` | Scan + monitor de tráfego DMX ao vivo |
| **Sniffer only** | `--sniff-only` | Apenas sniffer, sem scan de rede |

---

## Instalação

```bash
pip install -r requirements.txt
```

Ou manualmente:

```bash
pip install netifaces zeroconf httpx rich getmac mac-vendor-lookup aiodns
```

### Para o modo `--sniff` (opcional)

```bash
pip install scapy
```

> **Windows:** instale o [Npcap](https://npcap.com) antes do `pip install scapy`.
> **Linux / macOS:** execute com `sudo` para acesso a raw sockets.

---

> **Windows:** o mDNS requer o serviço **Bonjour** instalado (vem junto com iTunes ou Apple Devices).
> **Ping sweep:** execute como **Administrador** se 0 hosts forem encontrados (ICMP pode ser bloqueado).
> **`aiodns`** é opcional — se não estiver instalado, o DNS reverso usa fallback síncrono.
> **`getmac` / `mac-vendor-lookup`** são opcionais — se ausentes, o MAC vendor lookup é silenciosamente ignorado.

---

## Uso

### Scan básico

```bash
# Detecta subnet automaticamente
python tomoe.py

# Subnet específica
python tomoe.py --subnet 192.168.10.0/24

# Rede lenta — aumenta timeouts
python tomoe.py --timeout 10 --artnet-timeout 4
```

### Watchdog — monitoramento contínuo

```bash
# Scan + watchdog com intervalos padrão por tipo de device
python tomoe.py --watch

# Forçar intervalo de 5s para todos os devices
python tomoe.py --watch --interval 5

# Combinar com subnet específica
python tomoe.py --subnet 192.168.1.0/24 --watch
```

O watchdog exibe uma tabela live (atualizada a cada segundo) com:
- 🟢 Online com latência em ms
- 🔴 OFFLINE com tempo desde a última resposta
- 🟡 Instável (voltou de offline, aguardando próximo check)
- Alertas de quedas e retornos no rodapé
- Ctrl+C para sair limpo

Intervalos adaptativos por tipo de device:

| Tipo | Intervalo padrão |
|------|-----------------|
| ArtNet Node, Tasmota, Shelly, WLED | 10s (HTTP) |
| Web Device, IoT Device (ESP) | 15s (ICMP) |
| Windows PC, Linux/Mac, iPhone, Android, Desconhecido | 30s (ICMP) |

### Sniffer DMX — tráfego ao vivo

```bash
# Sniffer após scan (correlaciona IPs com nomes do scan)
python tomoe.py --sniff

# Só sniffer, sem scan de rede
python tomoe.py --sniff-only

# Filtrar por universo específico
python tomoe.py --sniff-only --universe 0

# Filtrar por IP de origem
python tomoe.py --sniff-only --sniff-ip 192.168.1.10
```

O sniffer captura pacotes ArtNet (porta 6454) e sACN/E1.31 (porta 5568) em tempo real, exibindo:
- Universo, protocolo, IP de origem (com nome se scan foi feito)
- FPS de pacotes por universo (média dos últimos 2s)
- Canais ativos e preview visual dos primeiros 16 canais: `█▓░ `
- Indicador 🔴 FREEZE quando universo parar de receber pacotes por >1s
- Ctrl+C para sair

### Formas alternativas de executar

```bash
# Windows — duplo clique ou pelo terminal:
run.bat

# Linux / Mac:
chmod +x run.sh && ./run.sh

# Rodar a pasta diretamente (qualquer SO):
python .
```

### Todos os parâmetros

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `--subnet` | auto | Subnet a varrer, ex: `192.168.1.0/24` |
| `--timeout` | `5.0` | Tempo de escuta mDNS em segundos |
| `--artnet-timeout` | `2.0` | Tempo de escuta ArtNet Poll em segundos |
| `--watch` | — | Ativa watchdog após o scan |
| `--interval` | auto | Override do intervalo do watchdog em segundos |
| `--sniff` | — | Ativa sniffer DMX após o scan |
| `--sniff-only` | — | Só sniffer, pula o scan de rede |
| `--universe` | — | Filtra sniffer por universo específico |
| `--sniff-ip` | — | Filtra sniffer por IP de origem |

---

## Exemplo de saída

### Scan normal

```
╔════════════════════════════════════════════════════════════════════════════════╗
║  IP               Tipo                Nome               Detalhes             ║
╠════════════════════════════════════════════════════════════════════════════════╣
║  192.168.1.20     💡 ArtNet Node      node-palco-01      ports=4              ║
║  192.168.1.21     🎛️  Tasmota         Dimmer Esquerdo    ON 80% | up 3T12:00  ║
║  192.168.1.30     🌈 WLED             Fita Palco         ON bri=200 300leds   ║
║  192.168.1.35     🔌 Shelly           shelly-dimmer-A3   ON 75% 18W 42°C      ║
║  192.168.1.40     📡 UPnP Device      Linux/2.6 UPnP/1.1 —                   ║
║  192.168.1.45     🗄️  NAS              Synology DiskStn   —                   ║
║  192.168.1.50     🖥️  Windows PC      DESKTOP-OPERACAO   —                   ║
║  192.168.1.88     📱 iPhone/iPad      —                  —                   ║
║  192.168.1.90     📟 IoT Device (ESP) —                  vendor=Esp..         ║
║  192.168.1.99     ❓ Desconhecido     —                  —                   ║
╚════════════════════════════════════════════════════════════════════════════════╝

  Total: 10 dispositivos  |  Scan: 14.2s
```

### Watchdog (`--watch`)

```
🔭 TOMOE — WATCHDOG   192.168.1.0/24   sessão 00:04:12

  IP               Tipo              Nome            Status    Último check  Quedas
  192.168.1.20     💡 ArtNet Node    node-palco-01   🟢 8ms    4s atrás      0
  192.168.1.21     🎛️  Tasmota       Dimmer Esq      🟢 12ms   9s atrás      0
  192.168.1.35     🔌 Shelly         Dimmer A3       🔴 OFFLINE 1m atrás     2
  192.168.1.50     🖥️  Windows PC    DESKTOP-OP      🟡 22ms   28s atrás     1

⚠  14:32:01  192.168.1.35 (Dimmer A3) ficou OFFLINE
✓  14:35:44  192.168.1.50 (DESKTOP-OP) voltou ONLINE
```

### Sniffer DMX (`--sniff-only`)

```
📡 TOMOE — DMX SNIFFER   ArtNet + sACN   Ctrl+C para sair

  Universo  Proto   Source                  fps    Ativos  Preview (16ch)
  0         ArtNet  192.168.1.10 (Resolume) 44.0   48      █▓░ █░░▓█░░ █░░▓
  1         ArtNet  192.168.1.10            44.0   12      ░    ░    ░
  5         sACN    192.168.1.20 (MadMap..) 0.0    48      🔴 FREEZE
```

---

## Arquitetura

```
PythonFinder/
├── tomoe.py                       # Orquestra tudo, exibe o relatório
├── __main__.py                    # Permite rodar com "python ."
├── run.bat                        # Launcher Windows
├── run.sh                         # Launcher Linux/Mac
├── capa.txt                       # ASCII art de abertura (animada)
├── requirements.txt
├── scanner/
│   ├── ping_sweep.py              # ICMP sweep paralelo (256 threads)
│   ├── mdns_listener.py           # mDNS/Bonjour (zeroconf)
│   ├── port_scanner.py            # Port scan + HTTP fingerprint + state enrichment
│   ├── artnet_poll.py             # ArtNet Poll UDP broadcast
│   ├── ssdp_scanner.py            # SSDP/UPnP M-SEARCH (stdlib puro)
│   ├── mac_lookup.py              # MAC address + vendor OUI lookup
│   ├── packet_sniffer.py          # DMX sniffer ArtNet/sACN (scapy, opcional)
│   └── watchdog.py                # Health check contínuo por device
├── identifier/
│   └── device_classifier.py       # Consolida e classifica com prioridade
└── display/
    ├── reporter.py                # Tabela colorida com rich (scan)
    ├── watch_display.py           # Live table com status watchdog
    └── sniff_display.py           # Live table com tráfego DMX
```

### Fluxo de execução

```
Fase 1 (paralelo):
   ├── Ping Sweep      → IPs vivos
   ├── mDNS Listener   → nomes amigáveis (5s)
   ├── ArtNet Poll     → nodes de luz (2s)
   └── SSDP Scan       → dispositivos UPnP (3s)

Fase 2 (paralelo, para cada IP vivo):
   ├── Port Scan + HTTP Fingerprint + State Enrichment  → tipo, nome, estado atual
   ├── MAC Vendor Lookup                                → fabricante do hardware (ARP)
   └── DNS Reverso async                               → hostname (aiodns ou fallback sync)

Fase 3:
   Classifier consolida com prioridade:
      ArtNet > HTTP (Tasmota/Shelly/WLED) > mDNS > SSDP > port heuristic > MAC vendor > desconhecido

Fase 4:
   Reporter renderiza tabela colorida no terminal

Fase 5 (opcional):
   --watch  → Watchdog inicia health checks adaptativos + rich.Live 1s
   --sniff  → PacketSniffer captura UDP 6454/5568 + rich.Live 200ms
```

### Identificação HTTP + State Enrichment

| Porta | Endpoint | Classifica como | Estado extraído |
|-------|----------|-----------------|-----------------|
| 80 | `GET /json/info` → `"brand": "WLED"` | **WLED** | `on`, `bri` via `/json/state` |
| 80 | `GET /cm?cmnd=Status` → `"Status"` | **Tasmota** | `POWER`, `Dimmer`, `Uptime` via `Status 0` |
| 80 | `GET /shelly` → `"type"` | **Shelly** | `ison`, `brightness`, `power W`, `temp °C` via `/status` |
| 80 | resposta genérica | Web Device | — |
| 22 | banner SSH | Linux/Mac | — |
| 3389 | porta aberta | Windows PC | — |
| 62078 | porta aberta | iPhone/iPad | — |
| 5555 | banner ADB | Android | — |

---

## Notas

- **ArtNet:** bind na porta `6454`. Se houver conflito (QLab, Resolume), fallback automático para porta efêmera.
- **SSDP:** broadcast UDP para `239.255.255.250:1900` — usa apenas stdlib, sem dependências extras.
- **MAC Vendor:** lê o cache ARP local (hosts recém pingados já estão no cache). Identifica Espressif (ESP32/ESP8266), Apple, Raspberry Pi, Samsung, etc.
- **DNS reverso:** usa `aiodns` em paralelo se disponível; fallback para `socket.gethostbyaddr` em threads.
- **WLED:** extrai nome, versão, LEDs via `/json/info`; estado (on/bri/fx) via `/json/state`.
- **Tasmota:** extrai `FriendlyName` e `Module` via `Status`; extrai `POWER`, `Dimmer`, `Uptime` via `Status 0`.
- **Shelly:** extrai `type` e `mac` via `/shelly`; extrai estado (ison, brightness, W, °C) via `/status`.
- **Watchdog:** Tasmota/Shelly/WLED usam HTTP health check (mais confiável); demais dispositivos usam ICMP ping.
- **Sniffer:** captura passiva com scapy — não injeta tráfego na rede. Detecta freeze por ausência de pacotes por >1s.
