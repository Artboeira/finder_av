# TOMOE -  Network Scanner Toolkit 

Descobre e identifica automaticamente todos os dispositivos de uma subnet — dimmers Tasmota, relés Shelly, nodes ArtNet, tablets, computadores — e exibe um relatório visual colorido no terminal.

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

| Ícone | Tipo de dispositivo | Método de detecção |
|-------|---------------------|--------------------|
| 🎛️ | Tasmota (dimmer / relay) | HTTP `/cm?cmnd=Status` |
| 🔌 | Shelly | HTTP `/shelly` |
| 🌈 | WLED | HTTP `/json/info` |
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

---

## Instalação

```bash
pip install -r requirements.txt
```

Ou manualmente:

```bash
pip install netifaces zeroconf httpx rich getmac mac-vendor-lookup aiodns
```

> **Windows:** o mDNS requer o serviço **Bonjour** instalado (vem junto com iTunes ou Apple Devices).
> **Ping sweep:** execute como **Administrador** se 0 hosts forem encontrados (ICMP pode ser bloqueado).
> **`aiodns`** é opcional — se não estiver instalado, o DNS reverso usa fallback síncrono.
> **`getmac` / `mac-vendor-lookup`** são opcionais — se ausentes, o MAC vendor lookup é silenciosamente ignorado.

---

## Uso

```bash
# Detecta subnet automaticamente
python tomoe.py

# Subnet específica
python tomoe.py --subnet 192.168.10.0/24

# Rede lenta — aumenta timeouts
python tomoe.py --timeout 10 --artnet-timeout 4
```

### Formas alternativas de executar

```bash
# Windows — duplo clique ou pelo terminal:
run.bat

# Linux / Mac:
chmod +x run.sh && ./run.sh

# Rodar a pasta diretamente (qualquer SO):
python .
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
╔════════════════════════════════════════════════════════════════════════╗
║  IP               Tipo                Nome               Detalhes     ║
╠════════════════════════════════════════════════════════════════════════╣
║  192.168.1.20     💡 ArtNet Node      node-palco-01      ports=4      ║
║  192.168.1.21     🎛️  Tasmota         Dimmer Esquerdo    mod=Sonoff   ║
║  192.168.1.30     🌈 WLED             Fita Palco         leds=300,v14 ║
║  192.168.1.35     🔌 Shelly           shelly-dimmer-A3   mac=xx:xx    ║
║  192.168.1.40     📡 UPnP Device      Linux/2.6 UPnP/1.1 —           ║
║  192.168.1.45     🗄️  NAS              Synology DiskStn   —           ║
║  192.168.1.50     🖥️  Windows PC      DESKTOP-OPERACAO   —           ║
║  192.168.1.88     📱 iPhone/iPad      —                  —           ║
║  192.168.1.90     📟 IoT Device (ESP) —                  vendor=Esp.. ║
║  192.168.1.99     ❓ Desconhecido     —                  —           ║
╚════════════════════════════════════════════════════════════════════════╝

  Total: 10 dispositivos  |  Scan: 14.2s
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
│   ├── port_scanner.py            # Port scan + HTTP fingerprint
│   ├── artnet_poll.py             # ArtNet Poll UDP broadcast
│   ├── ssdp_scanner.py            # SSDP/UPnP M-SEARCH (stdlib puro)
│   └── mac_lookup.py              # MAC address + vendor OUI lookup
├── identifier/
│   └── device_classifier.py       # Consolida e classifica com prioridade
└── display/
    └── reporter.py                # Tabela colorida com rich
```

### Fluxo de execução

```
Fase 1 (paralelo):
   ├── Ping Sweep      → IPs vivos
   ├── mDNS Listener   → nomes amigáveis (5s)
   ├── ArtNet Poll     → nodes de luz (2s)
   └── SSDP Scan       → dispositivos UPnP (3s)

Fase 2 (paralelo, para cada IP vivo):
   ├── Port Scan + HTTP Fingerprint  → tipo e nome do device
   ├── MAC Vendor Lookup             → fabricante do hardware (ARP)
   └── DNS Reverso async             → hostname (aiodns ou fallback sync)

Fase 3:
   Classifier consolida com prioridade:
      ArtNet > HTTP (Tasmota/Shelly/WLED) > mDNS > SSDP > port heuristic > MAC vendor > desconhecido

Fase 4:
   Reporter renderiza tabela colorida no terminal
```

### Identificação HTTP

| Porta | Endpoint | Classifica como |
|-------|----------|-----------------|
| 80 | `GET /json/info` → JSON `"brand": "WLED"` | **WLED** |
| 80 | `GET /cm?cmnd=Status` → JSON `"Status"` | **Tasmota** |
| 80 | `GET /shelly` → JSON `"type"` | **Shelly** |
| 80 | resposta genérica | Web Device |
| 22 | banner SSH | Linux/Mac |
| 3389 | porta aberta | Windows PC |
| 62078 | porta aberta | iPhone/iPad |
| 5555 | banner ADB | Android |

---

## Notas

- **ArtNet:** bind na porta `6454`. Se houver conflito (QLab, Resolume), fallback automático para porta efêmera.
- **SSDP:** broadcast UDP para `239.255.255.250:1900` — usa apenas stdlib, sem dependências extras.
- **MAC Vendor:** lê o cache ARP local (hosts recém pingados já estão no cache). Identifica Espressif (ESP32/ESP8266), Apple, Raspberry Pi, Samsung, etc.
- **DNS reverso:** usa `aiodns` em paralelo se disponível; fallback para `socket.gethostbyaddr` em threads.
- **WLED:** extrai nome configurado, versão do firmware e número de LEDs via `/json/info`.
- **Tasmota:** extrai `FriendlyName` e `Module` do endpoint de status.
- **Shelly:** extrai `type` e `mac` do endpoint `/shelly`.
