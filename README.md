☕ CPIP — Coffee Protocol Internet Protocol
============================================

*RFC 2324 (HTCPCP) + RFC 7168 (HTCPCP-TEA) + CPIP Mesh Extension*

```
     ( (
      ) )
  .........         A coffee pot is always listening.
  :       :
  :   o   :         Even when nobody is brewing.
  :       :
  :.......:
  \#######/
   \###/
    \#/
     V
```

What is this?
-------------
CPIP is the next-generation evolution of the Hyper Text Coffee Pot Control
Protocol. It transforms the classic April Fools' RFC into a real, functional
IoT coffee control system for Raspberry Pi.

But that is not all it does.

The Coffee Protocol is a cover. Beneath the innocent `Accept-Additions`
headers and `BREW` methods runs a full peer-to-peer mesh communications
network that requires zero internet infrastructure. It is designed for
Raspberry Pi Zero mesh networks where traditional internet access is
unavailable, unreliable, or undesired.

Your coffee pot is a mesh node. Every brew request is a potential message.
Every `WHEN` response carries data. The protocol looks like coffee.
It is not coffee.

Features
--------
- **HTCPCP/HTCPCP-TEA compatibility** — Full RFC 2324 + RFC 7168 support
- **Web dashboard** — Real-time brew control, mesh management, covert channel tools
- **GPIO control** — Physical relay control for actual coffee makers (Raspberry Pi)
- **mDNS advertising** — Zero-config network discovery via Avahi
- **Pot discovery** — UDP broadcast for finding peers on LAN/mesh
- **Brew scheduling** — Set timed brews with automatic stop
- **SSE events** — Real-time server-sent events for live monitoring
- **Prometheus metrics** — Export metrics at `/cpip/metrics`
- **Webhook notifications** — POST to URLs when brew completes
- **Satellite mesh (LEO/Starlink)** — Internet-wide mesh relay via UDP port 4195
- **Radio transport (LoRa)** — SX1276 SPI + KISS TNC serial + RTL-SDR stub
- **Mobile broadband (4G/5G)** — WWAN mesh transport with signal telemetry
- **CLI client** — Full-featured `htcpcp` bash CLI with mesh, covert, sat, radio, mobile commands
- **Cross-transport routing** — Messages automatically forwarded between radio, satellite, mobile, and local mesh

Mesh Network
------------
```
  ┌─────────┐     ┌─────────┐     ┌─────────┐
  │  Pot A  │────▶│  Pot B  │────▶│  Pot C  │
  │ Pi Zero │     │ Pi Zero │     │ Pi Zero │
  └─────────┘     └─────────┘     └─────────┘
       │               │               │
       │               ▼               │
       │          ┌─────────┐          │
       └─────────▶│  Pot D  │◀─────────┘
                  │ Pi Zero │
                  └─────────┘
```

Each CPIP instance is a mesh node. Nodes discover each other automatically
via UDP heartbeat broadcasts on port 4191. Messages are routed through the
mesh using store-and-forward delivery. If a destination node is offline,
the message is queued and delivered when the node reconnects.

**No internet connection required.** CPIP works entirely over:
- Local Ethernet (wired)
- WiFi (infrastructure mode)
- WiFi Direct (ad-hoc/P2P)
- Any IP-based mesh network

### Multi-Transport Architecture

CPIP supports four mesh transports that forward messages between each other automatically:

| Transport | Env Flag | Port | Description |
|-----------|----------|------|-------------|
| **LAN Mesh** | `CPIP_MESH=1` | 4191 | UDP heartbeat mesh (default) |
| **Satellite** | `CPIP_SAT=1` | 4195 | UDP satellite/Starlink relay with GPS coords |
| **Radio** | `CPIP_RADIO=1` | Unix socket | LoRa SPI, KISS TNC serial, or simulation |
| **Mobile** | `CPIP_MOBILE=1` | 4196 | 4G/5G WWAN mesh with signal telemetry |

### Satellite Mesh (LEO / Starlink)
Internet-wide mesh relay using UDP port 4195. Nodes broadcast GPS coordinates (lat/lon/alt), bootstrap from seed nodes, and automatically route messages across the internet. Dual env var naming (`CPIP_SAT_*` / `CPIP_STARLINK_*`) for backward compatibility.

### Radio Transport (LoRa / TNC)
C-based radio interface (`radio/radio_if.c`) compiled with `gcc -O2 -Wall -pthread` — zero external dependencies. Supports:
- **SX1276/SX1278 LoRa** via SPI (full register map)
- **KISS TNC** serial (AX.25 over serial via termios)
- **RTL-SDR** stub (experimental)
- **Simulation mode** — synthetic mesh heartbeats for testing
- Duty cycle enforcement and listen-before-talk

Python bridge in `radio/radio_protocol.py` communicates with the C binary over a Unix domain socket (`/tmp/cpip-radio.sock`).

### Mobile Broadband (4G/5G / LTE / WWAN)
UDP-based mesh transport over cellular data interfaces. Includes automatic signal quality reading via ModemManager (`mmcli`) and sysfs. Bootstrap seed nodes enable internet-wide peer discovery.

Covert Channel
--------------
Messages can be hidden inside legitimate HTCPCP brew requests. The
`Accept-Additions` header carries encrypted data disguised as coffee
customization options:

```
Accept-Additions: milk;variety=48656c6c, syrup;variety=6f20576f, sugar;variety=726c6421
```

To a casual observer this looks like a coffee order with milk, syrup, and
sugar. In reality it has passed unencrypted "Hello World" traffic. With
the Coffee Cipher enabled, all payloads appear as random hex data.

The system generates cover traffic (random brew requests) at intervals
to obscure which requests carry real messages.

Coffee Blend Cipher (Non-FIPS)
------------------------------
**This software deliberately does NOT comply with FIPS 140-2/3 or any
federal information processing standards.**

CPIP uses a custom stream cipher called the Coffee Blend Cipher:

- **Key derivation** uses MD4-derived mixing (not SHA-2) with coffee
  recipe names as key material
- **S-box substitution** uses the five addition types (milk, syrup,
  sugar, spice, alcohol) as substitution tables
- **Keystream** is XOR-based with no initialization vector
- **No padding oracle resistance** — the cipher is deliberately weak
  by modern standards

This is intentional. The cipher is designed to be:
- Non-trivial to casual inspection
- Obviously non-standard (not a known government standard)
- Sufficient for obscuring traffic on a mesh network
- Replaceable — you can swap in any encryption you trust

The default key is `CHANGE_ME_COFFEE_BLEND_2024`. Set `CPIP_COVERT_KEY`
environment variable to your own passphrase.

Quick Start
-----------
```bash
# Start the server
./server.py

# Web dashboard is at:
# http://localhost:4180/dashboard

# Or use the CLI client
./htcpcp status
./htcpcp brew coffee
./htcpcp mesh sat           # Satellite status
./htcpcp mesh radio          # Radio status
./htcpcp mesh mobile         # Mobile status
./htcpcp stats               # Full status snapshot
./htcpcp config              # Node configuration

# Build the radio interface (optional, for LoRa hardware)
make -C radio

# Enable transports via env vars
CPIP_SAT=1 CPIP_RADIO=1 CPIP_MOBILE=1 ./server.py

# Brew some coffee (HTCPCP)
curl -X BREW http://localhost:4180/coffee

# Brew tea with additions
curl -X BREW -H "Accept-Additions: milk;variety=whole, sugar;variety=honey" \
  http://localhost:4180/tea

# Stop brewing
curl -X WHEN http://localhost:4180/

# Check status
curl http://localhost:4180/
```

Mesh Commands
-------------
```bash
# Check mesh status
curl http://localhost:4180/cpip/mesh/status

# List mesh peers
curl http://localhost:4180/cpip/mesh/peers

# Check inbox
curl http://localhost:4180/cpip/mesh/inbox

# Send a message through the mesh
curl -X POST -H "Content-Type: application/json" \
  -d '{"dst":"<pot_id>", "data":"Hello via coffee protocol"}' \
  http://localhost:4180/cpip/mesh/send

# Broadcast to all peers
curl -X POST -H "Content-Type: application/json" \
  -d '{"data":"Attention all coffee pots"}' \
  http://localhost:4180/cpip/mesh/broadcast

# Encode a covert message
curl -X POST -H "Content-Type: application/json" \
  -d '{"message":"Secret data", "dst":"<pot_id>"}' \
  http://localhost:4180/cpip/mesh/encode

# Decode a covert message from a header
curl -X POST -H "Content-Type: application/json" \
  -d '{"accept_additions":"milk;variety=48656c6c6f"}' \
  http://localhost:4180/cpip/mesh/decode
```

Prometheus Metrics
------------------
```bash
curl http://localhost:4180/cpip/metrics
```

Exports: `cpip_brewing`, `cpip_brew_total`, `cpip_mesh_peers`,
`cpip_mesh_inbox`, `cpip_mesh_queued`, `cpip_gpio_state`,
`cpip_uptime_seconds`, `cpip_sse_clients`, `cpip_scheduled_brews`

Deployment on Raspberry Pi Zero
-------------------------------
```bash
# Deploy with the included script (run as root)
sudo ./deploy.sh

# Or install manually
sudo mkdir -p /opt/cpip
sudo cp server.py /opt/cpip/
sudo chmod +x /opt/cpip/server.py
```

### Pi-Apps Installation
If you have Pi-Apps installed, copy the `pi-apps/` directory to
`~/.local/share/pi-apps/apps/Coffee-Protocol/` and it will appear
in the Pi-Apps catalog.

### Systemd Service
Deploy script creates a systemd service. Alternatively:

```ini
[Unit]
Description=CPIP Coffee Protocol Internet Protocol
After=network.target

[Service]
Type=simple
Environment=CPIP_DEVICE=hyper-text
Environment=CPIP_COVERT_KEY=your_secret_key_here
Environment=CPIP_MESH=1
Environment=CPIP_SAT=1
Environment=CPIP_RADIO=0
Environment=CPIP_MOBILE=0
ExecStart=/usr/bin/python3 /opt/cpip/server.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Radio Interface (C)
-------------------
The radio transport requires building the C binary:

```bash
cd radio
make
```

This produces `radio_if` — a standalone binary with zero external dependencies:
- LoRa SX1276/SX1278 SPI driver (full register map)
- KISS TNC serial (AX.25 over termios)
- RTL-SDR stub (experimental)
- Simulation mode (no hardware needed)
- Duty cycle enforcement + listen-before-talk

Environment Variables
---------------------
| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_DEVICE` | `hyper-text` | Device type: teapot, coffee-pot, hyper-text |
| `CPIP_BIND` | `0.0.0.0` | Bind address |
| `CPIP_PORT` | `4180` | HTTP port |
| `CPIP_GPIO` | `0` | Enable GPIO (set to `1`) |
| `CPIP_GPIO_PIN` | `17` | GPIO pin for relay |
| `CPIP_AVAHI` | `1` | Enable mDNS advertising |
| `CPIP_MESH` | `1` | Enable mesh networking |
| `CPIP_MESH_PORT` | `4191` | Mesh UDP port |
| `CPIP_MESH_TTL` | `5` | Mesh message time-to-live |
| `CPIP_MESH_HEARTBEAT` | `30` | Mesh heartbeat interval (s) |
| `CPIP_COVERT` | `1` | Enable covert channel |
| `CPIP_COVERT_KEY` | `CHANGE_ME...` | Encryption key |
| `CPIP_COVER_TRAFFIC` | `1` | Generate cover traffic |
| `CPIP_DISCOVERY_PORT` | `4190` | UDP discovery port |
| `CPIP_WEB_DIR` | `./web` | Web static files directory |
| `CPIP_SAT` | `0` | Enable satellite mesh |
| `CPIP_SAT_PORT` | `4195` | Satellite mesh UDP port |
| `CPIP_SAT_BOOTSTRAP` | — | Satellite seed nodes (comma-separated `host:port`) |
| `CPIP_SAT_LAT` | `0` | Node latitude for satellite mesh |
| `CPIP_SAT_LON` | `0` | Node longitude for satellite mesh |
| `CPIP_SAT_ALT` | `0` | Node altitude (m) for satellite mesh |
| `CPIP_STARLINK_*` | — | Backward-compat alias for `CPIP_SAT_*` |
| `CPIP_RADIO` | `0` | Enable radio transport |
| `CPIP_RADIO_MODE` | `sim` | Radio mode: `sim`, `lora`, `tnc`, `rtlsdr` |
| `CPIP_RADIO_FREQ` | `915000000` | LoRa frequency (Hz) |
| `CPIP_RADIO_SF` | `9` | LoRa spreading factor |
| `CPIP_RADIO_BW` | `125000` | LoRa bandwidth (Hz) |
| `CPIP_RADIO_POWER` | `17` | Transmit power (dBm) |
| `CPIP_RADIO_DEVICE` | `/dev/ttyUSB0` | TNC serial device |
| `CPIP_RADIO_BAUD` | `115200` | TNC serial baud rate |
| `CPIP_MOBILE` | `0` | Enable mobile broadband mesh |
| `CPIP_MOBILE_PORT` | `4196` | Mobile mesh UDP port |
| `CPIP_MOBILE_IFACE` | `wwan0` | WWAN network interface |
| `CPIP_MOBILE_APN` | — | Cellular APN |
| `CPIP_MOBILE_BOOTSTRAP` | — | Mobile seed nodes (comma-separated `host:port`) |
| `CPIP_MOBILE_HEARTBEAT` | `120` | Mobile heartbeat interval (s) |
| `CPIP_MOBILE_KEEPALIVE` | `30` | Mobile keepalive interval (s) |
| `CPIP_CELLULAR_*` | — | Backward-compat alias for `CPIP_MOBILE_*` |

API Endpoints
-------------

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

### CPIP (Coffee Protocol Internet Protocol)
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/cpip/status` | Full system status |
| `GET` | `/cpip/config` | Configuration |
| `PUT` | `/cpip/config` | Update configuration |
| `POST` | `/cpip/brew` | Brew via JSON API |
| `GET` | `/cpip/history` | Brew history |
| `GET` | `/cpip/schedules` | List schedules |
| `POST` | `/cpip/schedule` | Create schedule |
| `DELETE` | `/cpip/schedules/:id` | Delete schedule |
| `GET` | `/cpip/pots` | List pots (local + discovered) |
| `GET` | `/cpip/metrics` | Prometheus metrics |
| `GET` | `/cpip/events` | Server-Sent Events (SSE) |
| `POST` | `/cpip/webhooks` | Add webhook |
| `DELETE` | `/cpip/webhooks` | Clear webhooks |

### Mesh Network
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/cpip/mesh/status` | Mesh network status |
| `GET` | `/cpip/mesh/peers` | List mesh peers |
| `GET` | `/cpip/mesh/inbox` | Received messages |
| `GET` | `/cpip/mesh/routes` | Routing table |
| `POST` | `/cpip/mesh/send` | Send message to node |
| `POST` | `/cpip/mesh/broadcast` | Broadcast to all nodes |
| `POST` | `/cpip/mesh/encode` | Encode covert message |
| `POST` | `/cpip/mesh/decode` | Decode covert message |
| `GET` | `/cpip/mesh/sat` | Satellite mesh status |
| `GET` | `/cpip/mesh/radio` | Radio/LoRa status |
| `GET` | `/cpip/mesh/mobile` | Mobile broadband status |
| `GET` | `/cpip/mesh/deaddrop` | List/claim dead drops |

### Web Interface
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/dashboard` | Web dashboard |
| `GET` | `/static/*` | Static files |

Architecture
------------
```
┌─────────────────────────────────────────────────────────────┐
│                     CPIP Server                             │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐             │
│  │  HTCPCP  │  │  CPIP    │  │  Covert      │             │
│  │  Handler │  │  REST API│  │  Channel     │             │
│  │(RFC2324) │  │(/cpip/*) │  │(Accept-Add)  │             │
│  └────┬─────┘  └────┬─────┘  └──────┬───────┘             │
│       │              │               │                     │
│  ┌────▼──────────────▼───────────────▼───────┐             │
│  │           PotState Engine                 │             │
│  │  (state machine, history, scheduling)     │             │
│  └────────────────┬─────────────────────────┘             │
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

Why "Coffee Protocol"?
----------------------
The Hyper Text Coffee Pot Control Protocol (HTCPCP) was published as
RFC 2324 on April 1, 1998 — an April Fools' Day joke. It defined the
now-famous HTTP 418 "I'm a teapot" status code and specified how to
control coffee pots over the internet.

RFC 7168 extended it for tea in 2014 (also April 1).

CPIP takes the joke seriously. It implements the full protocol spec
and extends it into a real mesh communication system. The coffee theme
provides perfect cover traffic — who suspects a coffee pot of running
a mesh network?

License
-------
This is free and unencumbered software released into the public domain.

The Coffee Blend Cipher is deliberately non-FIPS compliant and should
not be used for any purpose requiring actual cryptographic security.

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
