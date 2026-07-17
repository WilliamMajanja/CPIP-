# ☕ CPIP — Coffee Pot Internet Protocol

> RFC 2324 (HTCPCP) + RFC 7168 (HTCPCP-TEA) + Mesh + Multi-Transport + ITF Defense + FIPS-Compliant Crypto + 1nf1D3L Post-Quantum KEM

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

CPIP v3 is a fully functional implementation of the Hyper Text Coffee Pot Control
Protocol that runs on Raspberry Pi. Beneath the HTCPCP brew requests runs a
peer-to-peer mesh network with four transport layers — LAN, satellite,
radio (LoRa/TNC), and mobile broadband — plus covert channels, ECDH P-256 E2EE,
ECDH+RSA-KEM hybrid key exchange, store-and-forward messaging, ITF (In The
Face) active defense, pentest tool detection, incident response with automated
mitigation, and a full CLI client.

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
- [Cryptography](#cryptography)
- [TLS/SSL (HTTPS)](#tlsssl-https)
- [Deployment](#deployment)
- [Kubernetes](#kubernetes)
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

**Your coffee pot is a mesh node. Your teapot fights back. v3 — all fangs out.**

---

## Features

- **HTCPCP/HTCPCP-TEA** — Full RFC 2324 + RFC 7168 (BREW, WHEN, PROPFIND, OPTIONS)
- **Web dashboard** — Refined 6-tab SPA: Brew, Mesh, Covert, ITF Defense, Schedule, History with streamlined UX/UI
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
- **CoffeeCipher v3 (AES-256-GCM)** — FIPS 197 authenticated encryption with HKDF-SHA256 key derivation
- **RSA-KEM-2048** — FIPS 186-4 / SP 800-56B key encapsulation with OAEP
- **HybridKEM** — ECDH P-256 + RSA-KEM hybrid key exchange
- **1nf1D3L's Kyber KEM** — Non-FIPS ML-KEM-768 variant (η=3, custom domain tags, NTT perturbation, coffee recipe binding) via `b4dm4n-cw` CLI
- **Hybrid PQ+Classical** — ECDH P-256 + 1nf1D3L Kyber hybrid key exchange
- **SHA-256 domain-separated hashing** — tamper-evident audit chain
- **ECDSA/ECDH P-256** — FIPS 186-4 end-to-end encryption, address book, port hopping
- **Incident response** — auto-detection, severity alerts, auto-mitigation
- **Signal awareness** — bandwidth estimation, jamming detection, link quality
- **Emergency mode** — instant key rotation, peer notification, secure wipe
- **Network diagnostics** — TCP/UDP ping, port scan, DNS, traceroute, interfaces
- **HTTP security** — rate limiting, request size limits, security headers
- **TLS/SSL (HTTPS)** — Built-in HTTPS with auto-generated self-signed certs, custom cert support, HTTP→HTTPS redirect
- **Kubernetes self-hosting** — Production-ready K8s manifests with ConfigMap, Secret, Ingress, NetworkPolicy
- **Encrypted persistence** — data at rest encrypted with HMAC integrity
- **CLI client** — Full-featured `cpip` bash CLI
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
# Start the server (defaults: hyper-text device, mesh enabled, HTTPS auto-cert)
CPIP_SSL=1 CPIP_SSL_AUTO=1 ./server.py

# Web dashboard: https://localhost:4180/dashboard

# Brew some coffee
curl -X BREW https://localhost:4180/coffee

# Brew tea with additions
curl -X BREW \
  -H "Accept-Additions: milk;variety=whole, sugar;variety=honey" \
  https://localhost:4180/tea

# Stop brewing
curl -X WHEN https://localhost:4180/

# Check status
curl https://localhost:4180/

# Or run without SSL (HTTP only)
./server.py
# Dashboard: http://localhost:4180/dashboard
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
./cpip status
./cpip brew coffee
./cpip mesh peers
./cpip mesh sat
./cpip mesh radio
./cpip mesh mobile
./cpip itf status
./cpip stats
```

---

## CLI Reference

The `cpip` command-line client communicates with a running CPIP server.

| Command | Description |
|---------|-------------|
| `cpip status` | Server status |
| `cpip version` | Server version |
| `cpip whoami` | Local node identity (POT_ID, address, hostname, device) |
| `cpip config` | Full node configuration (JSON) |
| `cpip stats` | All status at a glance (node, mesh, sat, radio, mobile) |
| `cpip brew coffee` | Brew coffee |
| `cpip brew tea` | Brew tea |
| `cpip brew tea "milk;variety=whole, sugar;variety=honey"` | Brew with additions |
| `cpip when` | Stop brewing |
| `cpip info` | Pot metadata (PROPFIND) |
| `cpip 418` | Trigger 418 (brew coffee on a teapot) |
| `cpip 418-alcohol` | Trigger 418 (alcohol on a teapot) |
| `cpip additions` | List supported addition types |
| `cpip mesh status` | Mesh network status |
| `cpip mesh peers` | List mesh peers |
| `cpip mesh inbox` | Received messages |
| `cpip mesh send <pot> <msg>` | Send E2EE message |
| `cpip mesh broadcast <msg>` | Broadcast to all peers |
| `cpip mesh scan` | Discover peers |
| `cpip mesh routes` | Routing table |
| `cpip mesh sat` | Satellite mesh status |
| `cpip mesh radio` | Radio / LoRa status |
| `cpip mesh mobile` | Mobile broadband status |
| `cpip mesh queued` | Store-and-forward queue |
| `cpip covert encode <msg>` | Encode covert message |
| `cpip covert decode <header>` | Decode covert message |
| `cpip covert brew <msg>` | Brew with hidden message |
| `cpip covert status` | Covert channel status |
| `cpip ecc status` | ECC engine status |
| `cpip ecc address` | Show this node's ECC address |
| `cpip ecc book` | List address book |
| `cpip ecc resolve <addr>` | Resolve ECC address |
| `cpip deaddrop list` | List dead-drop messages |
| `cpip deaddrop claim <id>` | Claim a dead-drop message |
| `cpip itf status` | Full defense posture |
| `cpip itf blacklist` | List blacklisted IPs |
| `cpip itf whitelist <addr>` | Remove IP from blacklist |
| `cpip itf clear` | Clear entire blacklist |
| `cpip itf stealth` | Stealth mode status |
| `cpip itf probe <addr>` | Check if IP is blacklisted |

---

## Web Dashboard

CPIP v3 includes a refined single-page application dashboard served at `/dashboard`.
Six tabs provide real-time control and monitoring with a streamlined, professional UI:

| Tab | Features |
|-----|----------|
| **☕ Brew** | Device info, brew state, total count, quick brew with 9 beverage types, hot/iced toggle, milk (5 kinds), sugar, syrup, spice, alcohol (6 kinds) |
| **📡 Mesh** | Peer count, inbox, store-and-forward queue, satellite status (coords, port, relay, peers), mobile status (interface, signal, telemetry), radio status (mode, freq, bandwidth), send/broadcast messages, peer table, inbox table |
| **🔒 Covert** | Encode messages into Accept-Additions headers, decode headers back to plaintext, copy-to-clipboard, persistent message history (localStorage) |
| **🛡 ITF** | 418 teapot status, stealth mode toggle, port hopping, latent ports, blacklist count, blacklisted IPs with whitelist buttons, probe address, clear blacklist, detected pentest tools table |
| **⏰ Schedule** | Schedule brews in X seconds or at datetime, daily recurring option, list/delete schedules |
| **📜 History** | Brew history table with time/beverage/additions/duration, beverage filter dropdown, clear button |

The status bar shows live badges with dot indicators for: brewing state, GPIO, mesh, covert, ITF stealth, NTP, and SSE connection. A live event log at the bottom shows real-time brew start/stop and mesh message events via Server-Sent Events.

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
store-and-forward delivery. E2EE with ECDH P-256 is default. Port hopping and
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
- **RTL-SDR receive** (requires librtlsdr, build with `make RTL=1`)
- **Simulation mode** — requires explicit `--sim` flag; LoRa mode requires real hardware
- Default mode is `lora` (not `sim`)
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

## Cryptography

All cryptographic primitives in CPIP v3 use FIPS-compliant algorithms via the
`cryptography` library, which provides constant-time implementations. The
`secrets` module replaces `random` for all security-relevant operations.
Post-quantum KEM is available via the `b4dm4n-cw` CLI (Non-FIPS).

### CoffeeCipher v3 (AES-256-GCM)

- **Cipher**: AES-256-GCM (FIPS 197) with 12-byte nonce and 16-byte authentication tag
- **Key derivation**: HKDF-SHA256 with domain-separated info strings
- **Format**: `nonce(12B) || ciphertext || GCM-tag(16B)`
- **Backward-compatible**: Reads v1 and v2 Coffee Blend Cipher messages transparently

### ECDSA/ECDH P-256

- **Key exchange**: ECDH over NIST P-256 (FIPS 186-4) via `cryptography` library
- **Signatures**: ECDSA with P-256 (FIPS 186-4) via `cryptography` library
- **Constant-time**: Uses `cryptography` library's constant-time implementations
- **Working ECDH and signatures**

### RSA-KEM-2048

- **Key encapsulation**: RSA-KEM with 2048-bit keys (FIPS 186-4 / SP 800-56B)
- **Padding**: OAEP with SHA-256 label
- **Key derivation**: HKDF-SHA256 from RSA-KEM shared secret

### HybridKEM (Classical)

- **ECDH P-256 + RSA-KEM-2048** combined key exchange
- **Key derivation**: HKDF-SHA256 from combined ECDH + RSA-KEM shared secrets
- **Hybrid guarantee**: Secure if EITHER classical component holds

### 1nf1D3L's Kyber KEM (Post-Quantum, Non-FIPS)

Available via the `b4dm4n-cw` CLI (`inf1del_kyber.py`):

- **Variant**: Non-FIPS ML-KEM-768 with 1nf1D3L modifications
- **Parameters**: n=256, k=3, q=3329, η₁=3, η₂=3, du=10, dv=4
- **Domain tag**: "1NF1D3L-KYBER-V1" on all hash/KDF inputs
- **Wider noise**: η=3 (vs FIPS η=2) — more entropy, stronger concrete security
- **NTT twiddle perturbation**: Per-session random twiddle factors for side-channel resistance
- **Coffee recipe binding**: Recipe string (espresso, cappuccino, latte, mocha, americano) mixed into KDF
- **Key confirmation**: Re-encapsulation check (implicit rejection via KDF with z)
- **Sizes**: PK=1184B, SK=2400B, CT=1120B, SS=32B
- **CLI**: `b4dm4n-cw {keygen,encaps,decaps,bench,info}`

### Hybrid PQ+Classical (Defense in Depth)

- **ECDH P-256 + 1nf1D3L Kyber** combined key exchange
- **Key derivation**: HKDF-SHA3-256 from combined ECDH + Kyber shared secrets
- **Hybrid guarantee**: Secure if EITHER component holds
- **Sizes**: PK≈1251B, SK≈2432B, CT≈1187B, SS=32B
- **CLI**: `b4dm4n-cw {hybrid-keygen,hybrid-encaps,hybrid-decaps}`

### HMAC-SHA256

- Mesh heartbeat authentication
- Message integrity verification

### SHA-256 / SHA3-256

- Domain-separated hashing for audit chain and identity
- SHA3-256 for Kyber KDF/H

### Encrypted Persistence

- v3 format with AES-256-GCM encryption and HMAC integrity verification
- v1/v2 backward-compatible load
- Data at rest encrypted with HMAC integrity

**Note**: Classical primitives (AES-256-GCM, ECDSA/ECDH P-256, RSA-KEM-2048, HKDF-SHA256, HMAC-SHA256) are FIPS-compliant.
**1nf1D3L's Kyber is NOT FIPS 203 validated** — it is a Non-FIPS ML-KEM-768 variant with wider noise (η=3), custom domain tags, NTT perturbation, and coffee recipe binding. Use for coffee protocols, red teaming, research, and survival.

---

## TLS/SSL (HTTPS)

CPIP v3 includes built-in HTTPS support with three modes:

### Auto Self-Signed Certificates

```bash
# Enable HTTPS with auto-generated self-signed cert
CPIP_SSL=1 CPIP_SSL_AUTO=1 ./server.py
```

On first startup, CPIP generates a self-signed certificate in `.ssl/cert.pem` and `.ssl/key.pem` using `openssl`. If `openssl` is unavailable, it falls back to the Python `cryptography` library, and finally to a minimal stub.

### Custom Certificates

```bash
# Use your own certificate
CPIP_SSL=1 CPIP_SSL_CERT=/path/to/cert.pem CPIP_SSL_KEY=/path/to/key.pem ./server.py
```

### HTTP→HTTPS Redirect

```bash
# Redirect HTTP (port 4181) to HTTPS (port 4180)
CPIP_SSL=1 CPIP_SSL_AUTO=1 CPIP_HTTP_REDIRECT=1 CPIP_HTTP_REDIRECT_PORT=4181 ./server.py
```

When enabled, all HTTP requests on the redirect port receive a `301 Moved Permanently` to the equivalent HTTPS URL.

### Security Headers

When SSL is active, CPIP adds:
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `Upgrade-Insecure-Requests: 1`

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_SSL` | `0` | Enable HTTPS (TLS) |
| `CPIP_SSL_CERT` | — | Path to TLS certificate PEM file |
| `CPIP_SSL_KEY` | — | Path to TLS private key PEM file |
| `CPIP_SSL_AUTO` | `0` | Auto-generate self-signed cert on first run |
| `CPIP_SSL_CERT_DIR` | `.ssl` | Directory for auto-generated certs |
| `CPIP_HTTP_REDIRECT` | `0` | Enable HTTP→HTTPS redirect |
| `CPIP_HTTP_REDIRECT_PORT` | `4181` | Port for HTTP redirect server |

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
- CLI to `/usr/local/bin/cpip`
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
Description=CPIP v3.0 — Coffee Pot Internet Protocol
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

## Kubernetes

CPIP v3 includes production-ready Kubernetes manifests for self-hosting.

### Quick Deploy

```bash
# Clone and deploy
git clone https://github.com/WilliamMajanska/CPIP-.git
cd CPIP-
kubectl apply -f k8s/

# Check status
kubectl get pods -n cpip
kubectl logs -n cpip deployment/cpip
```

### Architecture

The K8s deployment includes:

| Resource | Description |
|----------|-------------|
| **Namespace** | `cpip` — isolated environment |
| **ConfigMap** | Environment variables (device, ports, mesh, SSL) |
| **Secret** | Sensitive keys (`CPIP_COVERT_KEY`) |
| **Deployment** | Single replica with health/readiness/startup probes |
| **Service** | ClusterIP exposing HTTP (4180), mesh UDP (4191/4195/4196) |
| **Ingress** | nginx Ingress with TLS passthrough for `cpip.local` |
| **NetworkPolicy** | Restrict ingress/egress to CPIP ports only |
| **PVC** | 1Gi persistent volume for mesh data |

### Configuration

Edit the ConfigMap for environment variables:

```bash
kubectl edit configmap cpip-config -n cpip
```

Key settings:
- `CPIP_SSL=1` / `CPIP_SSL_AUTO=1` — HTTPS with auto certs
- `CPIP_MESH=1` — Enable mesh networking
- `CPIP_SAT=1` — Enable satellite transport
- `CPIP_COVERT_KEY` — Set in the Secret, not ConfigMap

### Docker Build

```bash
docker build -t cpip:3.0.0 .
docker run -p 4180:4180 -p 4181:4181 -p 4191:4191/udp \
  -e CPIP_SSL=1 -e CPIP_SSL_AUTO=1 -e CPIP_HTTP_REDIRECT=1 \
  cpip:3.0.0
```

### Access

```bash
# Port forward for local testing
kubectl port-forward -n cpip deployment/cpip 4180:4180

# Open dashboard
open https://localhost:4180/dashboard
```

### Production Ingress

For external access with a real domain and Let's Encrypt:

```yaml
# Add cert-manager annotation to the Ingress:
annotations:
  cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
    - hosts:
        - cpip.yourdomain.com
      secretName: cpip-tls-prod
```

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
| `CPIP_RADIO_MODE` | `lora` | Mode: `sim`, `lora`, `tnc`, `rtlsdr` |
| `CPIP_RADIO_FREQ` | `915000000` | Frequency (Hz) |
| `CPIP_RADIO_SF` | `9` | LoRa spreading factor |
| `CPIP_RADIO_BW` | `125000` | LoRa bandwidth (Hz) |
| `CPIP_RADIO_POWER` | `17` | Transmit power (dBm) |
| `CPIP_RADIO_DEVICE` | `/dev/spidev0.0` | TNC serial device |
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

### TLS/SSL

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_SSL` | `0` | Enable HTTPS (TLS) |
| `CPIP_SSL_CERT` | — | Path to TLS certificate PEM file |
| `CPIP_SSL_KEY` | — | Path to TLS private key PEM file |
| `CPIP_SSL_AUTO` | `0` | Auto-generate self-signed cert on first run |
| `CPIP_SSL_CERT_DIR` | `.ssl` | Directory for auto-generated certs |
| `CPIP_HTTP_REDIRECT` | `0` | Enable HTTP→HTTPS redirect |
| `CPIP_HTTP_REDIRECT_PORT` | `4181` | Port for HTTP redirect server |

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

### Crypto & Security API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/cpip/crypto` | Crypto status |
| `POST` | `/cpip/crypto` | Key rotation |
| `GET` | `/cpip/incident` | Incident alerts and audit chain |
| `POST` | `/cpip/incident` | Create alert |
| `GET` | `/cpip/signal` | Signal awareness (bandwidth, link quality, jamming) |
| `POST` | `/cpip/emergency` | Emergency actions (`activate`, `rotate_keys`, `wipe`, `deactivate`) |
| `GET` | `/cpip/diagnostics/ping` | TCP/UDP ping |
| `GET` | `/cpip/diagnostics/ports` | Port scan |
| `GET` | `/cpip/diagnostics/dns` | DNS resolution |
| `GET` | `/cpip/diagnostics/traceroute` | Traceroute |
| `GET` | `/cpip/diagnostics/interfaces` | Network interfaces |

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
┌──────────────────────────────────────────────────────────────────┐
│                       CPIP Server                                │
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐  ┌────────────┐   │
│  │  HTCPCP  │  │  CPIP    │  │  Covert      │  │    ITF     │   │
│  │  Handler │  │  REST API│  │  Channel     │  │  Defense   │   │
│  │(RFC2324) │  │(/cpip/*) │  │(Accept-Add)  │  │            │   │
│  └────┬─────┘  └────┬─────┘  └──────┬───────┘  └─────┬──────┘   │
│       │              │               │                │          │
│  ┌────▼──────────────▼───────────────▼────────────────▼──────┐  │
│  │           PotState Engine + Defense Engine                │  │
│  │  (state machine, history, scheduling, probe check)        │  │
│  └────────────────┬───────────────────────────────────────────┘  │
│                   │                                              │
│  ┌────────────────▼─────────────────────────────────────┐      │
│  │               Mesh Node Layer                         │      │
│  │  (peers, routing, store-and-forward, cross-transport) │      │
│  └───────┬──────────────────────┬──────────────┬─────────┘      │
│          │                      │              │                │
│  ┌───────▼──────┐  ┌───────────▼──────┐  ┌────▼─────────┐    │
│  │ LAN Mesh     │  │ Satellite Mesh   │  │ Radio (LoRa) │    │
│  │ UDP :4191    │  │ UDP :4195        │  │ Unix Socket  │    │
│  └──────────────┘  └─────────────────┘  └──────────────┘    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │
│  │ Mobile BB    │  │    GPIO      │  │   Web UI     │        │
│  │ UDP :4196    │  │  Control     │  │  Dashboard   │        │
│  └──────────────┘  └──────────────┘  └──────────────┘        │
│  ┌──────────────────┐  ┌──────────────────┐                   │
│  │  Crypto Engine   │  │ Incident Response │                   │
│  │ (CoffeeCipher v3,│  │ (auto-detect,     │                   │
│  │  RSA-KEM, Hybrid)│  │  alert, mitigate)│                   │
│  └──────────────────┘  └──────────────────┘                   │
└──────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
├── server.py              # Main server (~6700 lines, zero deps, v3.0)
├── cpip                 # CLI client (bash script)
├── deploy.sh              # Raspberry Pi deployment script
├── deploy_cpip.sh       # Minimal HTCPCP-only deployment
├── Dockerfile             # Docker image (Alpine, SSL-enabled)
├── .gitignore
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── SECURITY.md
├── CODE_OF_CONDUCT.md
├── web/
│   └── index.html         # Web dashboard SPA (v3)
├── k8s/
│   ├── deployment.yaml    # Kubernetes manifests (Deployment, Service, Ingress, etc.)
│   └── kustomization.yaml # Kustomize configuration
├── radio/
│   ├── radio_if.c         # C radio interface (LoRa SPI, KISS TNC, RTL-SDR receive, sim)
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

The CoffeeCipher v3 uses FIPS-compliant cryptographic primitives
(AES-256-GCM, ECDSA/ECDH P-256, RSA-KEM-2048, HKDF-SHA256, HMAC-SHA256).

```
     ☕     ☕     ☕
        ☕  ☕  ☕
           ☕☕
        ☕  ☕  ☕
      ☕     ☕     ☕

  Brew responsibly.
  Mesh securely.
  Never trust a teapot.
  v3 — all fangs out.
```
