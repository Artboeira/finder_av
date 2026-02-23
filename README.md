# 🎭 Sala Imersiva — Network Scanner

Descobre e identifica automaticamente todos os dispositivos de uma subnet — dimmers Tasmota, relés Shelly, nodes ArtNet, tablets, computadores — e exibe um relatório visual colorido no terminal.

```
 _______ _________ _        ______   _______  _______
(  ____ \\__   __/( (    /|(  __  \ (  ____ \(  ____ )
| (    \/   ) (   |  \  ( || (  \  )| (    \/| (    )|
| (__       | |   |   \ | || |   ) || (__    | (____)|
|  __)      | |   | (\ \) || |   | ||  __)   |     __)
| (         | |   | | \   || |   ) || (      | (\ (
| )      ___) (___| )  \  || (__/  )| (____/\| ) \ \__
|/       \_______/|/    )_)(______/ (_______/|/   \__/

 by Z1t0s
```

---

## Funcionalidades

| Ícone | Tipo de dispositivo |
|-------|---------------------|
| 🎛️ | Tasmota (dimmer / relay) |
| 🔌 | Shelly |
| 💡 | ArtNet Node |
| 🖥️ | Windows PC (RDP) |
| 🐧 | Linux / Mac (SSH) |
| 📱 | iPhone / iPad |
| 🤖 | Android (ADB) |
| 🌐 | Web Device genérico |
| ❓ | Desconhecido |

---

## Instalação

```bash
pip install netifaces zeroconf httpx rich
```

> **Windows:** o mDNS requer o serviço **Bonjour** instalado (vem junto com iTunes ou Apple Devices).
> **Ping sweep:** execute como **Administrador** se 0 hosts forem encontrados (ICMP pode ser bloqueado).

---

## Uso

```bash
# Detecta subnet automaticamente
python main.py

# Subnet específica
python main.py --subnet 192.168.10.0/24

# Rede lenta — aumenta timeouts
python main.py --timeout 10 --artnet-timeout 4
```

### Parâmetros

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `--subnet` | auto | Subnet a varrer, ex: `192.168.1.0/24` |
| `--timeout` | `5.0` | Tempo de escuta mDNS em segundos |
| `--artnet-timeout` | `2.0` | Tempo de escuta ArtNet Poll em segundos |

---

## Exemplo de saída

```
╔══════════════════════════════════════════════════════════════════╗
║  IP               Tipo                Nome             Método   ║
╠══════════════════════════════════════════════════════════════════╣
║  192.168.1.20     💡 ArtNet Node      node-palco-01    artnet   ║
║  192.168.1.21     🎛️  Tasmota         Dimmer Esquerdo  http     ║
║  192.168.1.35     🔌 Shelly           shelly-dimmer-A3 http     ║
║  192.168.1.50     🖥️  Windows PC      DESKTOP-OPERACAO port     ║
║  192.168.1.88     📱 iPhone/iPad      —                mdns     ║
║  192.168.1.99     ❓ Desconhecido     —                ping     ║
╚══════════════════════════════════════════════════════════════════╝

  Total: 6 dispositivos  |  Scan: 12.4s
```

---

## Arquitetura

```
sala_scanner/
├── main.py                        # Orquestra tudo, exibe o relatório
├── capa.txt                       # ASCII art de abertura
├── requirements.txt
├── scanner/
│   ├── ping_sweep.py              # Módulo 1 — Varredura ICMP (256 threads)
│   ├── mdns_listener.py           # Módulo 2 — Descoberta mDNS/Bonjour
│   ├── port_scanner.py            # Módulo 3 — Port scan + HTTP fingerprint
│   └── artnet_poll.py             # Módulo 4 — ArtNet Poll UDP broadcast
├── identifier/
│   └── device_classifier.py       # Consolida resultados, classifica devices
└── display/
    └── reporter.py                # Renderiza tabela colorida (rich)
```

### Fluxo de execução

```
1. Detectar IP e subnet próprios
2. Rodar em paralelo (asyncio):
   ├── Ping Sweep      → IPs vivos
   ├── mDNS Listener   → nomes amigáveis (5s)
   └── ArtNet Poll     → nodes de luz (2s)
3. Port Scan + HTTP Fingerprint em todos os IPs vivos (paralelo)
4. Classifier consolida com prioridade:
      ArtNet > Tasmota/Shelly > mDNS > port heuristic > desconhecido
5. Reporter renderiza tabela no terminal
```

### Identificação HTTP

| Porta | Endpoint | Classifica como |
|-------|----------|-----------------|
| 80 | `GET /cm?cmnd=Status` → JSON `"Status"` | **Tasmota** |
| 80 | `GET /shelly` → JSON `"type"` | **Shelly** |
| 80 | resposta genérica | Web Device |
| 22 | banner SSH | Linux/Mac |
| 3389 | porta aberta | Windows PC |
| 62078 | porta aberta | iPhone/iPad |
| 5555 | banner ADB | Android |

---

## Notas

- O ArtNet Poll faz bind na porta `6454`. Se houver conflito (QLab, Resolume), o fallback automático usa porta efêmera — o broadcast ainda é enviado normalmente.
- Tasmota: extrai `FriendlyName` e `Module` do endpoint de status.
- Shelly: extrai `type` e `mac` do endpoint `/shelly`.
- ArtNet: parseia `ArtPollReply` (239 bytes) — extrai `ShortName`, `LongName`, `NumPorts` e universo.
