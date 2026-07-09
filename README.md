# ☕ CPIP — Coffee Pot Internet Protocol

> RFC 2324 (HTCPCP) + RFC 7168 (HTCPCP-TEA) + Mesh Extension + Multi-Transport + ITF Defense

```
     ( (
      ) )
  .........
  :       :
  :   o   :     "A coffee pot is always listening.
  :       :      Even when nobody is brewing."
  :.......:
  \#######/
   \###/
    \#/
     V
```

CPIP is a fully functional implementation of the Hyper Text Coffee Pot Control
Protocol that runs on Raspberry Pi. Beneath the HTCPCP brew requests runs a
peer-to-peer mesh network with four transport layers — LAN, satellite,
radio (LoRa/TNC), and mobile broadband — plus covert channels, Ed25519 E2EE,
store-and-forward messaging, ITF (In The Face) active defense, pentest tool
detection, and a full CLI client.

---

## Table of Contents

- [What is this?](#what-is-this)
- [Features](#features)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Web Dashboard](#web-dashboard)
- [ITF Defense System](#itf-defense-system)
- [Multi-Transport Architecture](#multi-transport-architecture)
- [Covert Channel](#covert-channel)
- [Cryptography Notes](#cryptography-notes)
- [Deployment](#deployment)
- [Environment Variables](#environment-variables)
- [API Reference](#api-reference)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

---

## What is this?

The Hyper Text Coffee Pot Control Protocol (HTCPCP) was published as
[RFC 2324](https://datatracker.ietf.org/doc/html/rfc2324) on April 1, 1998 — an
April Fools' Day joke. It defined the now-famous HTTP 418 "I'm a teapot"
status code and specified how to control coffee pots over the internet.
[RFC 7168](https://datatracker.ietf.org/doc/html/rfc7168) extended it for tea
in 2014 (also April 1).

CPIP takes the joke seriously. It implements the full protocol and extends it
into a multi-transport mesh communication system with active network defense.
The coffee theme provides perfect cover traffic. Every brew request can carry
encrypted data. Every `WHEN` response is a potential message. The protocol
looks like coffee. It is not coffee.

**Your coffee pot is a mesh node. Your teapot fights back.**

---

## Features

- **HTCPCP/HTCPCP-TEA** — Full RFC 2324 + RFC 7168 (BREW, WHEN, PROPFIND, OPTIONS)
- **Web dashboard** — 6-tab SPA: Brew, Mesh, Covert, ITF Defense, Schedule, History
- **GPIO relay control** — Physical coffee maker control on Raspberry Pi
- **Mesh networking** — Peer-to-peer with store-and-forward, auto-discovery, E2EE
- **4 transport layers** — LAN UDP, satellite (internet-wide), radio (LoRa/TNC), mobile 4G/5G
- **Runtime transport toggles** — Enable/disable satellite and mobile at runtime via API
- **Cross-transport routing** — Messages automatically forwarded between all transports
- **Covert channel** — Data hidden inside `Accept-Additions` brew headers
- **Covert history** — LocalStorage-backed message history with copy-to-clipboard
- **ITF (In The Face) defense** — Active probe blocking with 418 responses
- **Pentest tool detection** — Burp Suite, Nmap, SQLMap, Nikto & 12 more tools fingerprinted and blocked
- **Runtime stealth toggle** — Enable/disable stealth mode without restart
- **Blacklist management** — IP blacklist with rate-limited exponential ban duration
- **Coffee Blend Cipher** — Custom stream cipher (deliberately non-FIPS)
- **Ed25519 ECC** — End-to-end encryption, address book, port hopping
- **CLI client** — Full-featured `htcpcp` bash CLI
- **mDNS advertising** — Zero-config discovery via Avahi
- **Brew scheduling** — Timed brews with daily recurring option
- **SSE events** — Real-time server-sent events
- **Prometheus metrics** — Export at `/cpip/metrics`
- **Webhook notifications** — POST to URLs on brew completion
- **418 defense** — Unauthorized probes replied to with "I'm a teapot"
- **9 beverage types** — Coffee, tea, espresso, latte, cappuccino, americano, cold brew, mocha, matcha
- **Temperature control** — Hot/iced toggle
- **Addition types** — Milk (5 kinds), sugar (3 kinds), syrup (3 kinds), spice (3 kinds), alcohol (6 kinds)
- **Radio status** — Live LoRa/TNC mode, frequency, bandwidth display
- **Pi-Apps support** — One-click install on Raspberry Pi

---

## Quick Start

```bash
# Start the server (defaults: hyper-text device, mesh enabled)
./server.py

# Web dashboard: http://localhost:4180/dashboard

# Brew some coffee
curl -X BREW http://localhost:4180/coffee

# Brew tea with additions
curl -X BREW \
  -H "Accept-Additions: milk;variety=whole, sugar;variety=honey" \
  http://localhost:4180/tea

# Stop brewing
curl -X WHEN http://localhost:4180/

# Check status
curl http://localhost:4180/
```

### With extra transports

```bash
# Build the optional radio interface (requires gcc)
make -C radio

# Enable all transports
CPIP_SAT=1 CPIP_RADIO=1 CPIP_MOBILE=1 ./server.py
```

### Using the CLI

```bash
./htcpcp status
./htcpcp brew coffee
./htcpcp mesh peers
./htcpcp mesh sat
./htcpcp mesh radio
./htcpcp mesh mobile
./htcpcp itf status
./htcpcp stats
```

---

## CLI Reference

The `htcpcp` command-line client communicates with a running CPIP server.

| Command | Description |
|---------|-------------|
| `htcpcp status` | Server status |
| `htcpcp version` | Server version |
| `htcpcp whoami` | Local node identity (POT_ID, address, hostname, device) |
| `htcpcp config` | Full node configuration (JSON) |
| `htcpcp stats` | All status at a glance (node, mesh, sat, radio, mobile) |
| `htcpcp brew coffee` | Brew coffee |
| `htcpcp brew tea` | Brew tea |
| `htcpcp brew tea "milk;variety=whole, sugar;variety=honey"` | Brew with additions |
| `htcpcp when` | Stop brewing |
| `htcpcp info` | Pot metadata (PROPFIND) |
| `htcpcp 418` | Trigger 418 (brew coffee on a teapot) |
| `htcpcp 418-alcohol` | Trigger 418 (alcohol on a teapot) |
| `htcpcp additions` | List supported addition types |
| `htcpcp mesh status` | Mesh network status |
| `htcpcp mesh peers` | List mesh peers |
| `htcpcp mesh inbox` | Received messages |
| `htcpcp mesh send <pot> <msg>` | Send E2EE message |
| `htcpcp mesh broadcast <msg>` | Broadcast to all peers |
| `htcpcp mesh scan` | Discover peers |
| `htcpcp mesh routes` | Routing table |
| `htcpcp mesh sat` | Satellite mesh status |
| `htcpcp mesh radio` | Radio / LoRa status |
| `htcpcp mesh mobile` | Mobile broadband status |
| `htcpcp mesh queued` | Store-and-forward queue |
| `htcpcp covert encode <msg>` | Encode covert message |
| `htcpcp covert decode <header>` | Decode covert message |
| `htcpcp covert brew <msg>` | Brew with hidden message |
| `htcpcp covert status` | Covert channel status |
| `htcpcp ecc status` | ECC engine status |
| `htcpcp ecc address` | Show this node's ECC address |
| `htcpcp ecc book` | List address book |
| `htcpcp ecc resolve <addr>` | Resolve ECC address |
| `htcpcp deaddrop list` | List dead-drop messages |
| `htcpcp deaddrop claim <id>` | Claim a dead-drop message |
| `htcpcp itf status` | Full defense posture |
| `htcpcp itf blacklist` | List blacklisted IPs |
| `htcpcp itf whitelist <addr>` | Remove IP from blacklist |
| `htcpcp itf clear` | Clear entire blacklist |
| `htcpcp itf stealth` | Stealth mode status |
| `htcpcp itf probe <addr>` | Check if IP is blacklisted |

---

## Web Dashboard

CPIP includes a full single-page application dashboard served at `/dashboard`.
Six tabs provide real-time control and monitoring:

| Tab | Features |
|-----|----------|
| **☕ Brew** | Device info, brew state, total count, quick brew with 9 beverage types, hot/iced toggle, milk (5 kinds), sugar, syrup, spice, alcohol (6 kinds) |
| **📡 Mesh** | Peer count, inbox, store-and-forward queue, satellite status (coords, port, relay, peers), mobile status (interface, signal, telemetry), radio status (mode, freq, bandwidth), send/broadcast messages, peer table, inbox table |
| **🔒 Covert** | Encode messages into Accept-Additions headers, decode headers back to plaintext, copy-to-clipboard, persistent message history (localStorage) |
| **🛡 ITF** | 418 teapot status, stealth mode toggle, port hopping, latent ports, blacklist count, blacklisted IPs with whitelist buttons, probe address, clear blacklist, detected pentest tools table |
| **⏰ Schedule** | Schedule brews in X seconds or at datetime, daily recurring option, list/delete schedules |
| **📜 History** | Brew history table with time/beverage/additions/duration, beverage filter dropdown, clear button |

The status bar shows live badges for: brewing state, GPIO, mesh, covert, ITF stealth status, NTP, and SSE connection. A live event log at the bottom shows real-time brew start/stop and mesh message events via Server-Sent Events.

---

## ITF Defense System

The ITF (In The Face) module is CPIP's active network defense. It identifies
and blocks hostile probes using multiple detection heuristics, all answered
with HTTP 418 "I'm a teapot" — making network mapping and brute-force attacks
indistinguishable from a joke.

### Detection Methods

| Method | Description |
|--------|-------------|
| **Scanner paths** | Requests to /admin, /wp-, /.env, /phpmyadmin, /shell, /cmd, /exec, /backdoor, /login, /setup, /install, /manager, /console → +3 probe score |
| **Missing headers** | BREW without Accept-Additions on non-standard paths → +1 probe score |
| **Unknown URI schemes** | Non-coffee URIs → +2 probe score |
| **Pentest tool fingerprinting** | User-Agent and header inspection for 16 security tools → +2 probe score |
| **Rate limiting** | Repeated probes double the ban duration (up to 24h) |

Threshold: probe score ≥ 2 → 418 response + IP blacklisted.

### Detected Tools

The following security tools are automatically fingerprinted by User-Agent:
Burp Suite, Nmap, SQLMap, Nikto, Gobuster, Dirb, FFUF, WFuzz, OpenVAS,
Nessus, Masscan, ZAP, Arachni, w3af, Metasploit, Acunetix.

Informational tools (cURL, Wget, Python, Go-http) are tracked in the
dashboard but do not trigger 418 blocking.

### Runtime Controls

- **Stealth mode** — Toggle via `POST /cpip/defense {"action":"stealth","enabled":true}` or dashboard button
- **Blacklist** — Whitelist individual IPs, clear entire blacklist, probe any IP
- **Satellite/mobile** — Enable or disable transports at runtime via `POST /cpip/mesh/sat` and `POST /cpip/mesh/mobile`

### Blacklist Behavior

- Base TTL: 1 hour (`CPIP_DEFENSE_BLACKLIST_TTL`)
- Rate limit: 10 probes within 60s doubles the ban duration
- Max blacklist: 1000 entries (oldest half pruned)
- Localhost (127.0.0.1, ::1) is never blacklisted

---

## Multi-Transport Architecture

CPIP supports four mesh transports that forward messages between each other
automatically. Messages received on any transport are relayed to all others
(routing loops are prevented).

| Transport | Env Flag | Port | Runtime Toggle | Description |
|-----------|----------|------|----------------|-------------|
| **LAN Mesh** | `CPIP_MESH=1` | 4191 | — | UDP heartbeat mesh on local network |
| **Satellite** | `CPIP_SAT=1` | 4195 | `POST /cpip/mesh/sat` | Internet-wide UDP relay with GPS coords |
| **Radio** | `CPIP_RADIO=1` | Unix socket | — | LoRa SPI, KISS TNC serial, or simulation |
| **Mobile** | `CPIP_MOBILE=1` | 4196 | `POST /cpip/mesh/mobile` | 4G/5G WWAN mesh with signal telemetry |

Satellite and mobile transports can be enabled or disabled at runtime
without restarting the server using the API or dashboard buttons.

### LAN Mesh (default)

Nodes discover each other via UDP heartbeats on port 4191. Messages use
store-and-forward delivery. E2EE with Ed25519 is default. Port hopping and
stealth mode are supported.

**No internet connection required.** Works over:
- Local Ethernet (wired)
- WiFi infrastructure mode
- WiFi Direct (ad-hoc/P2P)
- Any IP-based network

### Satellite Mesh (LEO / Starlink)

Internet-wide mesh relay using UDP port 4195. Designed for satellite
links with high latency. Features:
- GPS coordinate broadcasting (lat/lon/alt)
- Bootstrap seed nodes for peer discovery
- Configurable timeouts for high-latency links
- Dual env var naming (`CPIP_SAT_*` / `CPIP_STARLINK_*`) for backward compatibility

### Radio Transport (LoRa / TNC)

C-based radio interface with zero external dependencies. Built with
`gcc -O2 -Wall -pthread`. Supports:
- **SX1276/SX1278 LoRa** via SPI (full register map)
- **KISS TNC** serial (AX.25 over serial via termios)
- **RTL-SDR** stub (experimental)
- **Simulation mode** — synthetic mesh heartbeats for testing without hardware
- Duty cycle enforcement and listen-before-talk

The Python bridge (`radio/radio_protocol.py`) communicates with the C binary
over a Unix domain socket (`/tmp/cpip-radio.sock`).

### Mobile Broadband (4G/5G / LTE / WWAN)

UDP-based mesh transport over cellular data interfaces. Features:
- Automatic signal quality reading via ModemManager (`mmcli`) and sysfs
- Bootstrap seed nodes for internet-wide peer discovery
- TCP keepalive-compatible heartbeat intervals
- RSRP/RSSI/SINR telemetry

---

## Covert Channel

Messages can be hidden inside legitimate HTCPCP brew requests. The
`Accept-Additions` header carries encrypted data disguised as coffee
customization:

```
Accept-Additions: milk;variety=48656c6c, syrup;variety=6f20576f, sugar;variety=726c6421
```

To a casual observer this looks like a coffee order. In reality it has passed
"Hello World" traffic. With the Coffee Blend Cipher enabled, all payloads
appear as random hex data.

The system generates cover traffic (random brew requests at configurable
intervals) to obscure which requests carry real messages.

The dashboard Covert tab provides:
- **Encode** — Enter a message, choose a recipe, get the Accept-Additions header
- **Decode** — Paste a header, decode back to plaintext
- **History** — Previously encoded messages saved to browser localStorage with copy-to-clipboard

---

## Cryptography Notes

### Ed25519 ECC

- Key exchange: Curve25519 Diffie-Hellman
- Signatures: Ed25519
- Pure Python implementation (not constant-time)
- Default port hopping and latent ports for traffic obfuscation

### Coffee Blend Cipher

**This software deliberately does NOT comply with FIPS 140-2/3 or any federal
information processing standards.**

CPIP uses a custom stream cipher called the Coffee Blend Cipher:

- **Key derivation** uses MD4-derived mixing (not SHA-2) with coffee recipe
  names as key material
- **S-box substitution** uses the five addition types (milk, syrup, sugar,
  spice, alcohol) as substitution tables
- **Keystream** is XOR-based with no initialization vector
- **No padding oracle resistance** — the cipher is deliberately weak

This is intentional. The cipher is designed to be non-trivial to casual
inspection, obviously non-standard, sufficient for obscuring mesh traffic,
and trivially replaceable with any encryption you trust.

Set `CPIP_COVERT_KEY` to your own passphrase. The default is
`CHANGE_ME_COFFEE_BLEND_2024`.

---

## Deployment

### Raspberry Pi Zero

```bash
# Full deploy (run as root)
sudo ./deploy.sh

# Manual install
sudo mkdir -p /opt/cpip
sudo cp server.py /opt/cpip/
sudo chmod +x /opt/cpip/server.py
```

The deploy script installs:
- Server to `/opt/cpip/server.py`
- CLI to `/usr/local/bin/htcpcp`
- Web dashboard to `/opt/cpip/web/`
- Systemd service (`cpip.service`)
- Pi-Apps package (if `pi-apps/` directory is present)

### Pi-Apps

Copy the `pi-apps/` directory to
`~/.local/share/pi-apps/apps/Coffee-Protocol/` and it will appear in the
Pi-Apps catalog for one-click install.

### Systemd Service

```ini
[Unit]
Description=CPIP v2.2 — Coffee Pot Internet Protocol
After=network.target

[Service]
Type=simple
Environment=CPIP_DEVICE=hyper-text
Environment=CPIP_MESH=1
Environment=CPIP_COVERT=1
Environment=CPIP_COVERT_KEY=your_secret_key_here
Environment=CPIP_MESH_STEALTH=0
ExecStart=/usr/bin/python3 /opt/cpip/server.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Radio Interface Build

```bash
cd radio
make
```

Produces `radio_if` — standalone binary, zero external dependencies.

---

## Environment Variables

All configuration is via environment variables. No config files needed.

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_DEVICE` | `hyper-text` | Device type: `teapot`, `coffee-pot`, `hyper-text` |
| `CPIP_BIND` | `0.0.0.0` | HTTP bind address |
| `CPIP_PORT` | `4180` | HTTP port |
| `CPIP_GPIO` | `0` | Enable GPIO relay control |
| `CPIP_GPIO_PIN` | `17` | GPIO pin number |
| `CPIP_AVAHI` | `1` | Enable mDNS advertising |

### Mesh Network

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_MESH` | `1` | Enable mesh networking |
| `CPIP_MESH_PORT` | `4191` | Mesh UDP heartbeat port |
| `CPIP_MESH_TTL` | `5` | Message time-to-live (hops) |
| `CPIP_MESH_HEARTBEAT` | `30` | Heartbeat interval (seconds) |
| `CPIP_MESH_STEALTH` | `0` | Stealth mode (togglable at runtime) |
| `CPIP_MESH_LATENT_PORTS` | `4192,4193,4194` | Port-knocking latent ports |
| `CPIP_MESH_HOP_INTERVAL` | `3600` | Port hop interval (seconds) |
| `CPIP_MESH_PERSIST_DIR` | `/tmp/cpip` | Message persistence directory |

### Covert Channel

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_COVERT` | `1` | Enable covert channel |
| `CPIP_COVERT_KEY` | `CHANGE_ME...` | Encryption passphrase |
| `CPIP_COVER_TRAFFIC` | `1` | Generate random cover traffic |

### Satellite Mesh

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_SAT` | `0` | Enable satellite mesh (togglable at runtime) |
| `CPIP_SAT_PORT` | `4195` | UDP port |
| `CPIP_SAT_BOOTSTRAP` | — | Seed nodes (`host:port,host:port`) |
| `CPIP_SAT_LAT` | `0` | Node latitude |
| `CPIP_SAT_LON` | `0` | Node longitude |
| `CPIP_SAT_ALT` | `0` | Node altitude (meters) |
| `CPIP_SAT_RELAY` | `0` | Relay mode (forward traffic) |
| `CPIP_SAT_TIMEOUT` | `10` | Peer timeout (seconds) |
| `CPIP_SAT_HEARTBEAT` | `60` | Heartbeat interval (seconds) |

`CPIP_STARLINK_*` env vars are accepted as backward-compatible aliases.

### Radio Transport

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_RADIO` | `0` | Enable radio transport |
| `CPIP_RADIO_MODE` | `sim` | Mode: `sim`, `lora`, `tnc`, `rtlsdr` |
| `CPIP_RADIO_FREQ` | `915000000` | Frequency (Hz) |
| `CPIP_RADIO_SF` | `9` | LoRa spreading factor |
| `CPIP_RADIO_BW` | `125000` | LoRa bandwidth (Hz) |
| `CPIP_RADIO_POWER` | `17` | Transmit power (dBm) |
| `CPIP_RADIO_DEVICE` | `/dev/ttyUSB0` | TNC serial device |
| `CPIP_RADIO_BAUD` | `115200` | TNC serial baud rate |

### Mobile Broadband

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_MOBILE` | `0` | Enable mobile transport (togglable at runtime) |
| `CPIP_MOBILE_PORT` | `4196` | UDP port |
| `CPIP_MOBILE_IFACE` | `wwan0` | Network interface |
| `CPIP_MOBILE_APN` | — | Cellular APN |
| `CPIP_MOBILE_BOOTSTRAP` | — | Seed nodes (`host:port,host:port`) |
| `CPIP_MOBILE_HEARTBEAT` | `120` | Heartbeat interval (seconds) |
| `CPIP_MOBILE_KEEPALIVE` | `30` | Keepalive interval (seconds) |

`CPIP_CELLULAR_*` env vars are accepted as backward-compatible aliases.

### 418 ITF Defense

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_DEFENSE_RATE_LIMIT` | `10` | Max probes before ban duration doubles |
| `CPIP_DEFENSE_RATE_WINDOW` | `60` | Rate tracking window (seconds) |
| `CPIP_DEFENSE_BLACKLIST_TTL` | `3600` | Base ban duration (seconds) |
| `CPIP_DEFENSE_MAX_BLACKLIST` | `1000` | Max blacklist entries |

### USB Gadget (Pi-Tail)

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_PITAIL` | `0` | Enable USB gadget mode |
| `CPIP_PITAIL_ADDR` | `10.0.0.1` | USB gadget IP address |
| `CPIP_PITAIL_NETMASK` | `255.255.255.0` | USB gadget netmask |
| `CPIP_PITAIL_GADGET_DIR` | `/sys/kernel/config/usb_gadget` | Configfs path |

### Other

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_NTP` | `1` | Enable NTP sync |
| `CPIP_NTP_SERVER` | `pool.ntp.org` | NTP server |
| `CPIP_DISCOVERY_PORT` | `4190` | UDP pot discovery port |
| `CPIP_WEB_DIR` | `./web` | Web dashboard static files |
| `CPIP_THERMOS` | `0` | Enable dead-drop aggregator |
| `CPIP_THERMOS_MAX` | `1000000` | Max dead-drop storage (bytes) |

---

## API Reference

### HTCPCP (RFC 2324 + RFC 7168)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Server status |
| `BREW` | `/coffee` | Brew coffee |
| `BREW` | `/tea` | Brew tea |
| `POST` | `/coffee` | Brew coffee (fallback) |
| `POST` | `/tea` | Brew tea (fallback) |
| `WHEN` | `/` | Stop brewing |
| `PROPFIND` | `/` | Pot metadata |
| `OPTIONS` | `/` | Protocol capabilities |

### CPIP REST API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/cpip/status` | Full system status |
| `GET` | `/cpip/config` | Node configuration |
| `PUT` | `/cpip/config` | Update configuration |
| `POST` | `/cpip/brew` | Brew via JSON API |
| `GET` | `/cpip/history` | Brew history |
| `DELETE` | `/cpip/history` | Clear brew history |
| `GET` | `/cpip/schedules` | Scheduled brews |
| `POST` | `/cpip/schedule` | Create schedule |
| `DELETE` | `/cpip/schedules/:id` | Delete schedule |
| `GET` | `/cpip/pots` | Discovered pots |
| `GET` | `/cpip/metrics` | Prometheus metrics |
| `GET` | `/cpip/events` | SSE event stream |
| `POST` | `/cpip/webhooks` | Add webhook |
| `DELETE` | `/cpip/webhooks` | Clear webhooks |

### Mesh Network API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/cpip/mesh/status` | Mesh status (peers, inbox, ECC, defense) |
| `GET` | `/cpip/mesh/peers` | Peer list |
| `GET` | `/cpip/mesh/inbox` | Received messages |
| `GET` | `/cpip/mesh/routes` | Routing table |
| `POST` | `/cpip/mesh/send` | Send E2EE message |
| `POST` | `/cpip/mesh/broadcast` | Broadcast to all peers |
| `POST` | `/cpip/mesh/encode` | Encode covert message |
| `POST` | `/cpip/mesh/decode` | Decode covert message |
| `GET` | `/cpip/mesh/sat` | Satellite transport status |
| `POST` | `/cpip/mesh/sat` | Enable/disable satellite (`{"action":"enable"}` / `{"action":"disable"}`) |
| `GET` | `/cpip/mesh/radio` | Radio transport status |
| `GET` | `/cpip/mesh/mobile` | Mobile transport status |
| `POST` | `/cpip/mesh/mobile` | Enable/disable mobile (`{"action":"enable"}` / `{"action":"disable"}`) |
| `GET` | `/cpip/mesh/deaddrop` | List/claim dead drops |
| `GET` | `/cpip/defense` | Defense posture (418, stealth, blacklist, tools) |
| `POST` | `/cpip/defense` | Defense actions |

### Defense API Actions

| Action | Payload | Description |
|--------|---------|-------------|
| `whitelist` | `{"action":"whitelist","addr":"1.2.3.4"}` | Remove IP from blacklist |
| `clear` | `{"action":"clear"}` | Clear entire blacklist |
| `probe` | `{"action":"probe","addr":"1.2.3.4"}` | Check if IP is blacklisted |
| `stealth` | `{"action":"stealth","enabled":true}` | Toggle stealth mode |

### Web Interface

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/dashboard` | Web dashboard |
| `GET` | `/static/*` | Static assets |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     CPIP Server                             │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐             │
│  │  HTCPCP  │  │  CPIP    │  │  Covert      │  ┌────────┐ │
│  │  Handler │  │  REST API│  │  Channel     │  │  ITF   │ │
│  │(RFC2324) │  │(/cpip/*) │  │(Accept-Add)  │  │Defense │ │
│  └────┬─────┘  └────┬─────┘  └──────┬───────┘  └───┬────┘ │
│       │              │               │              │      │
│  ┌────▼──────────────▼───────────────▼──────────────▼───┐  │
│  │           PotState Engine + Defense Engine            │  │
│  │  (state machine, history, scheduling, probe check)    │  │
│  └────────────────┬─────────────────────────────────────┘  │
│                   │                                        │
│  ┌────────────────▼─────────────────────────────────────┐  │
│  │                 Mesh Node Layer                       │  │
│  │  (peers, routing, store-and-forward, cross-transport) │  │
│  └───────┬──────────────────────┬──────────────┬────────┘  │
│          │                      │              │           │
│  ┌───────▼──────┐  ┌───────────▼──────┐  ┌────▼─────────┐ │
│  │ LAN Mesh     │  │ Satellite Mesh   │  │ Radio (LoRa) │ │
│  │ UDP :4191    │  │ UDP :4195        │  │ Unix Socket  │ │
│  └──────────────┘  └─────────────────┘  └──────────────┘ │
│  ┌──────────────┐                                         │
│  │ Mobile BB    │  ┌──────────┐  ┌──────────────┐        │
│  │ UDP :4196    │  │  GPIO    │  │  Web UI      │        │
│  └──────────────┘  │  Control │  │  Dashboard   │        │
│                    └──────────┘  └──────────────┘        │
└─────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
├── server.py              # Main server (~5100 lines, zero deps)
├── htcpcp                 # CLI client (bash script)
├── deploy.sh              # Raspberry Pi deployment script
├── deploy_htcpcp.sh       # Minimal HTCPCP-only deployment
├── .gitignore
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── SECURITY.md
├── CODE_OF_CONDUCT.md
├── web/
│   └── index.html         # Web dashboard SPA
├── radio/
│   ├── radio_if.c         # C radio interface (LoRa SPI, KISS TNC, sim)
│   ├── radio_if.h         # C header (structs, enums, protocol)
│   ├── radio_protocol.py  # Python bridge to C binary
│   └── Makefile           # gcc build (zero deps)
└── pi-apps/
    ├── install
    ├── uninstall
    ├── credits
    ├── description
    └── icon-64.png
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

---

## License

This is free and unencumbered software released into the public domain.
See [LICENSE](LICENSE) for details.

The Coffee Blend Cipher is deliberately non-FIPS compliant and should not
be used for any purpose requiring actual cryptographic security.

```
     ☕     ☕     ☕
        ☕  ☕  ☕
           ☕☕
        ☕  ☕  ☕
      ☕     ☕     ☕

  Brew responsibly.
  Mesh securely.
  Never trust a teapot.
```
