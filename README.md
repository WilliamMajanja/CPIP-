# CPIP — Coffee Pot Internet Protocol

[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](LICENSE)
[![Python 3.x](https://img.shields.io/badge/python-3.x-blue.svg)](https://python.org)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux%20%7C%20Raspberry%20Pi-blue.svg)](deploy.sh)
[![Version](https://img.shields.io/badge/version-4.0.2-blue.svg)]()
[![RFC 2324](https://img.shields.io/badge/RFC-2324-green.svg)](https://datatracker.ietf.org/doc/html/rfc2324)
[![RFC 7168](https://img.shields.io/badge/RFC-7168-green.svg)](https://datatracker.ietf.org/doc/html/rfc7168)
[![Mesh](https://img.shields.io/badge/mesh-LAN%20%7C%20Satellite%20%7C%20Radio%20%7C%20Mobile-blueviolet.svg)]()
[![ITF Defense](https://img.shields.io/badge/ITF-defense-orange.svg)]()
[![Covert Channel](https://img.shields.io/badge/covert-channel-lightgrey.svg)]()
[![Crypto](https://img.shields.io/badge/crypto-AES--256--GCM%20%7C%20ECDH%20%7C%20Kyber-success.svg)]()
[![K8s](https://img.shields.io/badge/Kubernetes-ready-326CE5.svg)]()
[![GPIO](https://img.shields.io/badge/GPIO-Raspberry%20Pi-green.svg)]()
[![FIPS](https://img.shields.io/badge/FIPS-197%20%7C%20186--4%20%7C%20180--4-blue.svg)]()
[![HSM](https://img.shields.io/badge/HSM-PKCS%2311-orange.svg)]()
[![Anti-ISP](https://img.shields.io/badge/Anti--ISP-STUN%20%7C%20UPnP%20%7C%20DNS%20Tunnel%20%7C%20WSS%20%7C%20DoH-red.svg)]()
[![Anti-Stingray](https://img.shields.io/badge/Anti--Stingray-IMSI%20Catcher%20Detection-red.svg)]()
[![Anti-Surveillance](https://img.shields.io/badge/Anti--Surveillance-DPI%20%7C%20Obfuscation%20%7C%20Metadata%20Strip-red.svg)]()
[![Net Neutrality](https://img.shields.io/badge/Net%20Neutrality-BW%20Monitor%20%7C%20Masquerade%20%7C%20Fragmentation-red.svg)]()
[![TUI](https://img.shields.io/badge/TUI-OpenTUI-brightgreen.svg)]()
[![b4dm4n-cw](https://img.shields.io/badge/b4dm4n--cw-Cipher%20Workbench-yellowgreen.svg)]()

Implementation of RFC 2324 (HTCPCP) and RFC 7168 (HTCPCP-TEA) with mesh networking, multi-transport routing, cryptographic defense, and active network defense.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Web Dashboard](#web-dashboard)
- [ITF Defense System](#itf-defense-system)
- [Multi-Transport Architecture](#multi-transport-architecture)
- [Covert Channel](#covert-channel)
- [Cryptography](#cryptography)
- [TLS/SSL](#tlsssl)
- [Deployment](#deployment)
- [Kubernetes](#kubernetes)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

## Overview

The Hyper Text Coffee Pot Control Protocol (HTCPCP) was published as RFC 2324 on April 1, 1998, defining the HTTP 418 "I'm a teapot" status code and specifying how to control coffee pots over the internet. RFC 7168 extended it for tea in 2014.

CPIP implements the full HTCPCP specification and extends it into a multi-transport mesh communication system with active network defense. The protocol operates over four transport layers — LAN, satellite, radio (LoRa/TNC), and mobile broadband — with end-to-end encryption, store-and-forward messaging, and covert channels. All HTCPCP brew requests and responses double as cover traffic for encrypted mesh messages.

## Features

- **HTCPCP/HTCPCP-TEA** — RFC 2324 and RFC 7168 (BREW, WHEN, PROPFIND, OPTIONS)
- **Web dashboard** — Single-page application with tabs for Brew, Mesh, Covert, ITF Defense, Scheduling, and History
- **Mesh networking** — Peer-to-peer with store-and-forward, auto-discovery, and E2EE
- **Multi-transport routing** — LAN UDP, satellite (internet-wide), radio (LoRa/TNC), mobile 4G/5G with automatic message forwarding between transports
- **Runtime transport toggles** — Enable/disable satellite and mobile transports via API without restart
- **Runtime defense policy toggles** — Independent enable/disable of every Anti-ISP, Anti-Stingray, Anti-Surveillance, and Net-Neutrality vector via API or dashboard
- **Covert channel** — Data embedded in Accept-Additions brew headers with LocalStorage-backed message history
- **ITF (In The Face) defense** — Active probe blocking with HTTP 418 responses
- **Pentest tool detection** — Fingerprinting of Burp Suite, Nmap, SQLMap, Nikto, and 12 additional security tools
- **IP blacklist management** — Rate-limited exponential ban duration
- **CoffeeCipher v3 (AES-256-GCM)** — FIPS 197 authenticated encryption with HKDF-SHA256 key derivation
- **RSA-KEM-2048** — FIPS 186-4 / SP 800-56B key encapsulation with OAEP
- **HybridKEM** — ECDH P-256 + RSA-KEM hybrid key exchange
- **Post-quantum KEM** — 1nf1D3L's Kyber ML-KEM-768 variant via b4dm4n-cw CLI (non-FIPS)
- **Hybrid PQ+Classical** — ECDH P-256 + Kyber hybrid key exchange
- **SHA-256 domain-separated hashing** — Tamper-evident audit chain
- **ECDSA/ECDH P-256** — FIPS 186-4 end-to-end encryption, address book, port hopping
- **Incident response** — Auto-detection, severity alerts, auto-mitigation
- **Signal awareness** — Bandwidth estimation, jamming detection, link quality monitoring
- **Emergency mode** — Instant key rotation, peer notification, secure wipe
- **GPIO relay control** — Physical coffee maker control on Raspberry Pi
- **HTTP security** — Rate limiting, request size limits, security headers
- **TLS/SSL** — Built-in HTTPS with auto-generated self-signed certificates, custom certificate support, and HTTP-to-HTTPS redirect
- **Kubernetes support** — Production-ready manifests with ConfigMap, Secret, Ingress, and NetworkPolicy
- **Encrypted persistence** — Data at rest encrypted with HMAC integrity verification
- **CLI client** — Full-featured bash CLI
- **mDNS advertising** — Zero-config discovery via Avahi
- **Brew scheduling** — Timed brews with daily recurring option
- **SSE events** — Real-time server-sent events
- **Prometheus metrics** — Export at `/cpip/metrics`
- **9 beverage types** — Coffee, tea, espresso, latte, cappuccino, americano, cold brew, mocha, matcha
- **Addition types** — Milk (5 kinds), sugar (3 kinds), syrup (3 kinds), spice (3 kinds), alcohol (6 kinds)
- **Pi-Apps support** — One-click install on Raspberry Pi

## Quick Start

```bash
# Start the server (hyper-text device, mesh enabled, HTTPS with auto-generated cert)
CPIP_SSL=1 CPIP_SSL_AUTO=1 ./server.py

# Web dashboard: https://localhost:4180/dashboard

# Brew coffee
curl -X BREW https://localhost:4180/coffee

# Brew tea with additions
curl -X BREW \
  -H "Accept-Additions: milk;variety=whole, sugar;variety=honey" \
  https://localhost:4180/tea

# Stop brewing
curl -X WHEN https://localhost:4180/

# Check status
curl https://localhost:4180/

# Run without SSL (HTTP only)
./server.py
```

### With additional transports

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
| `cpip tui [host] [port]`                | Launch Terminal UI (OpenTUI)        |
| `cpip itf status` | Full defense posture |
| `cpip itf blacklist` | List blacklisted IPs |
| `cpip itf whitelist <addr>` | Remove IP from blacklist |
| `cpip itf clear` | Clear entire blacklist |
| `cpip itf stealth` | Stealth mode status |
| `cpip itf probe <addr>` | Check if IP is blacklisted |

## Web Dashboard

CPIP includes a single-page application dashboard served at `/dashboard` with fourteen tabs providing real-time control and monitoring:

| Tab | Features |
|-----|----------|
| **Brew** | Device info, brew state, total count, quick brew with 9 beverage types, hot/iced toggle, milk (5 kinds), sugar, syrup, spice, alcohol (6 kinds) |
| **Mesh** | Peer count, inbox, store-and-forward queue, satellite status (coordinates, port, relay, peers), mobile status (interface, signal, telemetry), radio status (mode, frequency, bandwidth), send/broadcast messages, peer table, inbox table |
| **Covert** | Encode messages into Accept-Additions headers, decode headers to plaintext, copy-to-clipboard, persistent message history (localStorage) |
| **ITF** | 418 teapot status, stealth mode toggle, port hopping, latent ports, blacklist count, blacklisted IPs with whitelist buttons, probe address, clear blacklist, detected pentest tools table |
| **Crypto** | Crypto engine status, key material, KEM/encryption info, rotation controls |
| **IR** | Incident response: severity alerts, audit chain, auto-mitigation state |
| **Signal** | Signal awareness: bandwidth estimate, link quality, jamming detection |
| **Diag** | Network diagnostics: ping, port scan, DNS, traceroute, interfaces |
| **Anti-ISP** | Live toggle cards for STUN, UPnP, relay, DNS tunnel, WSS, DoH transports with per-vector switches |
| **Anti-Stingray** | Live toggle cards for master, cell/RG/signal/known-signature scans with rescan button |
| **Anti-Surveillance** | Live toggle cards for DPI evasion, traffic obfuscation, metadata strip, exploit-kit and process-injection detection with scan button |
| **Net Neutrality** | Live toggle cards for bandwidth monitor, protocol masquerade, fragmentation, throttle detect, jitter injection |
| **Schedule** | Schedule brews in X seconds or at datetime, daily recurring option, list/delete schedules |
| **History** | Brew history table with time/beverage/additions/duration, beverage filter dropdown, clear button |

The defense groups (Anti-ISP, Anti-Stingray, Anti-Surveillance, Net Neutrality) each have dedicated tabs with per-vector toggles reachable via API or dashboard.

The status bar displays live badges for brewing state, GPIO, mesh, covert, ITF stealth, NTP, and SSE connection status. A live event log shows real-time brew and mesh message events via Server-Sent Events.

## ITF Defense System

The ITF (In The Face) module implements active network defense by identifying and blocking hostile probes using multiple detection heuristics. Blocked probes receive HTTP 418 "I'm a teapot" responses.

### Detection Methods

| Method | Description |
|--------|-------------|
| Scanner paths | Requests to /admin, /wp-, /.env, /phpmyadmin, /shell, /cmd, /exec, /backdoor, /login, /setup, /install, /manager, /console (+3 probe score) |
| Missing headers | BREW without Accept-Additions on non-standard paths (+1 probe score) |
| Unknown URI schemes | Non-coffee URIs (+2 probe score) |
| Pentest tool fingerprinting | User-Agent and header inspection for 16 security tools (+2 probe score) |
| Rate limiting | Repeated probes double the ban duration (up to 24 hours) |

Threshold: probe score >= 2 results in 418 response and IP blacklisting.

### Detected Tools

The following tools are detected by User-Agent fingerprinting: Burp Suite, Nmap, SQLMap, Nikto, Gobuster, Dirb, FFUF, WFuzz, OpenVAS, Nessus, Masscan, ZAP, Arachni, w3af, Metasploit, Acunetix.

Informational tools (cURL, Wget, Python, Go-http) are tracked in the dashboard but do not trigger blocking.

### Runtime Controls

- **Stealth mode** — Toggle via `POST /cpip/defense {"action":"stealth","enabled":true}` or dashboard button
- **Blacklist** — Whitelist individual IPs, clear entire blacklist, probe any IP
- **Transport toggles** — Enable or disable satellite/mobile at runtime via API

### Blacklist Behavior

- Base TTL: 1 hour (`CPIP_DEFENSE_BLACKLIST_TTL`)
- Rate limit: 10 probes within 60 seconds doubles the ban duration
- Maximum entries: 1000 (oldest half pruned on overflow)
- Localhost (127.0.0.1, ::1) is never blacklisted

## Multi-Transport Architecture

CPIP supports four mesh transports with automatic message forwarding between all transports (routing loops are prevented).

| Transport | Env Flag | Port | Runtime Toggle | Description |
|-----------|----------|------|----------------|-------------|
| LAN Mesh | `CPIP_MESH=1` | 4191 | None | UDP heartbeat mesh on local network |
| Satellite | `CPIP_SAT=1` | 4195 | `POST /cpip/mesh/sat` | Internet-wide UDP relay with GPS coordinates |
| Radio | `CPIP_RADIO=1` | Unix socket | None | LoRa SPI, KISS TNC serial, or simulation |
| Mobile | `CPIP_MOBILE=1` | 4196 | `POST /cpip/mesh/mobile` | 4G/5G WWAN mesh with signal telemetry |

Satellite and mobile transports can be enabled or disabled at runtime without restarting the server.

### LAN Mesh

Nodes discover each other via UDP heartbeats on port 4191. Messages use store-and-forward delivery with ECDH P-256 E2EE by default. Port hopping and stealth mode are supported. No internet connection required — works over Ethernet, WiFi, WiFi Direct, or any IP-based network.

### Satellite Mesh

Internet-wide mesh relay using UDP port 4195, designed for satellite links with high latency. Features GPS coordinate broadcasting (lat/lon/alt), bootstrap seed nodes for peer discovery, and configurable timeouts for high-latency links. Dual env var naming (`CPIP_SAT_*` / `CPIP_STARLINK_*`) for backward compatibility.

### Radio Transport (LoRa / TNC)

C-based radio interface with zero external dependencies. Built with `gcc -O2 -Wall -pthread`. Supports:
- **SX1276/SX1278 LoRa** via SPI (full register map)
- **KISS TNC** serial (AX.25 over serial via termios)
- **RTL-SDR receive** (requires librtlsdr, build with `make RTL=1`)
- **Simulation mode** — requires explicit `--sim` flag; LoRa mode requires real hardware
- Default mode is `lora` (not `sim`)
- Duty cycle enforcement and listen-before-talk

The Python bridge (`radio/radio_protocol.py`) communicates with the C binary over a Unix domain socket (`/tmp/cpip-radio.sock`).

### Mobile Broadband (4G/5G / LTE / WWAN)

UDP-based mesh transport over cellular data interfaces. Features include automatic signal quality reading via ModemManager (`mmcli`) and sysfs, bootstrap seed nodes for peer discovery, TCP keepalive-compatible heartbeat intervals, and RSRP/RSSI/SINR telemetry.

## Covert Channel

Messages can be embedded inside legitimate HTCPCP brew requests. The `Accept-Additions` header carries data disguised as coffee customization:

```
Accept-Additions: milk;variety=48656c6c, syrup;variety=6f20576f, sugar;variety=726c6421
```

The system generates cover traffic (random brew requests at configurable intervals) to obscure which requests carry real messages. The dashboard Covert tab provides encode, decode, and persistent history functionality.

## Cryptography

All cryptographic primitives use FIPS-compliant algorithms via the `cryptography` library, which provides constant-time implementations. The `secrets` module replaces `random` for all security-relevant operations. Post-quantum KEM is available via the `b4dm4n-cw` CLI (non-FIPS).

### CoffeeCipher v3 (AES-256-GCM)

- Cipher: AES-256-GCM (FIPS 197) with 12-byte nonce and 16-byte authentication tag
- Key derivation: HKDF-SHA256 with domain-separated info strings
- Format: `nonce(12B) || ciphertext || GCM-tag(16B)`
- Backward-compatible: reads v1 and v2 messages transparently

### ECDSA/ECDH P-256

- Key exchange: ECDH over NIST P-256 (FIPS 186-4)
- Signatures: ECDSA with P-256 (FIPS 186-4)
- Constant-time implementations via `cryptography` library

### RSA-KEM-2048

- Key encapsulation: RSA-KEM with 2048-bit keys (FIPS 186-4 / SP 800-56B)
- Padding: OAEP with SHA-256 label
- Key derivation: HKDF-SHA256 from RSA-KEM shared secret

### HybridKEM (Classical)

- ECDH P-256 + RSA-KEM-2048 combined key exchange
- Key derivation: HKDF-SHA256 from combined ECDH + RSA-KEM shared secrets
- Secure if either classical component holds

### 1nf1D3L's Kyber KEM (Post-Quantum, Non-FIPS)

Available via the `b4dm4n-cw` CLI (`inf1del_kyber.py`):

- Variant: Non-FIPS ML-KEM-768 with 1nf1D3L modifications
- Parameters: n=256, k=3, q=3329, eta1=3, eta2=3, du=10, dv=4
- Domain tag: "1NF1D3L-KYBER-V1" on all hash/KDF inputs
- Wider noise: eta=3 (vs FIPS eta=2) for enhanced concrete security
- NTT twiddle perturbation: Per-session random twiddle factors for side-channel resistance
- Coffee recipe binding: Recipe string mixed into KDF
- Key confirmation: Re-encapsulation check (implicit rejection via KDF with z)
- Sizes: PK=1184B, SK=2400B, CT=1120B, SS=32B
- CLI: `b4dm4n-cw {keygen,encaps,decaps,bench,info,tui}`

### Hybrid PQ+Classical

- ECDH P-256 + 1nf1D3L Kyber combined key exchange
- Key derivation: HKDF-SHA3-256 from combined ECDH + Kyber shared secrets
- Secure if either component holds
- Sizes: PK~1251B, SK~2432B, CT~1187B, SS=32B
- CLI: `b4dm4n-cw {hybrid-keygen,hybrid-encaps,hybrid-decaps,tui}`

### HMAC-SHA256

Mesh heartbeat authentication and message integrity verification.

### SHA-256 / SHA3-256

Domain-separated hashing for audit chain and identity; SHA3-256 for Kyber KDF/H.

### Encrypted Persistence

v4 format with AES-256-GCM encryption and HMAC integrity verification. v1/v2 backward-compatible load.

Classical primitives (AES-256-GCM, ECDSA/ECDH P-256, RSA-KEM-2048, HKDF-SHA256, HMAC-SHA256) are FIPS-compliant. 1nf1D3L's Kyber is not FIPS 203 validated — it is a non-FIPS ML-KEM-768 variant intended for research and experimental use.

## TLS/SSL

CPIP includes built-in HTTPS support with three modes.

### Auto Self-Signed Certificates

```bash
CPIP_SSL=1 CPIP_SSL_AUTO=1 ./server.py
```

On first startup, CPIP generates a self-signed certificate in `.ssl/cert.pem` and `.ssl/key.pem` using OpenSSL. If OpenSSL is unavailable, it falls back to the Python `cryptography` library, and finally to a minimal stub.

### Custom Certificates

```bash
CPIP_SSL=1 CPIP_SSL_CERT=/path/to/cert.pem CPIP_SSL_KEY=/path/to/key.pem ./server.py
```

### HTTP-to-HTTPS Redirect

```bash
CPIP_SSL=1 CPIP_SSL_AUTO=1 CPIP_HTTP_REDIRECT=1 CPIP_HTTP_REDIRECT_PORT=4181 ./server.py
```

When enabled, all HTTP requests on the redirect port receive a 301 Moved Permanently to the equivalent HTTPS URL.

### Security Headers

When SSL is active, CPIP adds Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, Content-Security-Policy, and Upgrade-Insecure-Requests headers.

## Deployment

### Raspberry Pi

```bash
# Full deployment (run as root)
sudo ./deploy.sh

# Manual installation
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

Copy the `pi-apps/` directory to `~/.local/share/pi-apps/apps/Coffee-Protocol/` for one-click install in the Pi-Apps catalog.

### Systemd Service

```ini
[Unit]
Description=CPIP v4.0.2 — Coffee Pot Internet Protocol
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

Produces `radio_if` — a standalone binary with zero external dependencies.

## Kubernetes

CPIP includes production-ready Kubernetes manifests for self-hosting.

### Quick Deploy

```bash
git clone https://github.com/WilliamMajanska/CPIP-.git
cd CPIP-
kubectl apply -f k8s/
```

### Architecture

| Resource | Description |
|----------|-------------|
| **Namespace** | `cpip` — isolated environment |
| **ConfigMap** | Environment variables (device, ports, mesh, SSL) |
| **Secret** | Sensitive keys (CPIP_COVERT_KEY) |
| **Deployment** | Single replica with health/readiness/startup probes |
| **Service** | ClusterIP exposing HTTP (4180), mesh UDP (4191/4195/4196) |
| **Ingress** | nginx Ingress with TLS passthrough |
| **NetworkPolicy** | Restrict ingress/egress to CPIP ports only |
| **PVC** | 1Gi persistent volume for mesh data |

### Configuration

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
docker build -t cpip:4.0.2 .
docker run -p 4180:4180 -p 4181:4181 -p 4191:4191/udp \
  -e CPIP_SSL=1 -e CPIP_SSL_AUTO=1 -e CPIP_HTTP_REDIRECT=1 \
  cpip:4.0.2
```

### Access

```bash
# Port forward for local testing
kubectl port-forward -n cpip deployment/cpip 4180:4180
```

### Production Ingress

For external access with a real domain and Let's Encrypt:

```yaml
annotations:
  cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
    - hosts:
        - cpip.yourdomain.com
      secretName: cpip-tls-prod
```

## Configuration

All configuration is via environment variables. No configuration files are required.

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
| `CPIP_SAT_BOOTSTRAP` | None | Seed nodes (`host:port,host:port`) |
| `CPIP_SAT_LAT` | `0` | Node latitude |
| `CPIP_SAT_LON` | `0` | Node longitude |
| `CPIP_SAT_ALT` | `0` | Node altitude (meters) |
| `CPIP_SAT_RELAY` | `0` | Relay mode (forward traffic) |
| `CPIP_SAT_TIMEOUT` | `10` | Peer timeout (seconds) |
| `CPIP_SAT_HEARTBEAT` | `60` | Heartbeat interval (seconds) |



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
| `CPIP_MOBILE_APN` | None | Cellular APN |
| `CPIP_MOBILE_BOOTSTRAP` | None | Seed nodes (`host:port,host:port`) |
| `CPIP_MOBILE_HEARTBEAT` | `120` | Heartbeat interval (seconds) |
| `CPIP_MOBILE_KEEPALIVE` | `30` | Keepalive interval (seconds) |



### ITF Defense

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_DEFENSE_RATE_LIMIT` | `10` | Max probes before ban duration doubles |
| `CPIP_DEFENSE_RATE_WINDOW` | `60` | Rate tracking window (seconds) |
| `CPIP_DEFENSE_BLACKLIST_TTL` | `3600` | Base ban duration (seconds) |
| `CPIP_DEFENSE_MAX_BLACKLIST` | `1000` | Max blacklist entries |

### Anti-ISP Policy

All Anti-ISP transports default to **on** and are individually togglable at runtime via `POST /cpip/anti-isp` or `PUT /cpip/config`.

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_ANTI_ISP` | `1` | Master enable for Anti-ISP transports |
| `CPIP_STUN` | `1` | STUN NAT hole-punching |
| `CPIP_STUN_SERVERS` | (built-in) | Comma-separated STUN servers |
| `CPIP_STUN_REFRESH` | `300` | STUN refresh interval (seconds) |
| `CPIP_UPNP` | `1` | UPnP port mapping |
| `CPIP_UPNP_LEASE` | `3600` | UPnP lease duration (seconds) |
| `CPIP_DNS_TUNNEL` | `1` | DNS tunnel covert transport |
| `CPIP_DNS_TUNNEL_DOMAIN` | None | Tunnel domain |
| `CPIP_DNS_TUNNEL_SUBDOMAIN` | `cpip` | Tunnel subdomain label |
| `CPIP_DNS_CHUNK_SIZE` | `63` | DNS tunnel chunk size (bytes) |
| `CPIP_WSS` | `1` | WebSocket (WSS) relay tunnel |
| `CPIP_WSS_RELAYS` | (built-in) | Comma-separated WSS relays |
| `CPIP_WSS_TIMEOUT` | `10` | WSS relay timeout (seconds) |
| `CPIP_RELAY` | `1` | Mesh relay pool |
| `CPIP_RELAY_SERVERS` | (built-in) | Comma-separated relay servers |
| `CPIP_RELAY_TIMEOUT` | `5` | Relay timeout (seconds) |
| `CPIP_DOH` | `1` | DNS-over-HTTPS (oblivious) |

### Anti-Stingray Policy

All detection vectors default to **on** and are individually togglable at runtime via `POST /cpip/anti-stingray` or `PUT /cpip/config`. Set any variable to `0` to disable a vector at startup.

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_ANTI_STINGRAY` | `1` | Master enable for Stingray detection |
| `CPIP_STINGRAY_SCAN` | `30` | Scan interval (seconds) |
| `CPIP_STINGRAY_SIGNAL_DB` | `50` | Signal-anomaly delta threshold (dB) |
| `CPIP_STINGRAY_KNOWN_MCC_MNC` | `310260,310030,...` | Known-good MCC/MNC allowlist |
| `CPIP_STINGRAY_PORTS` | `443,80,53,8080` | Ports watched for IMSI-catcher signatures |
| `CPIP_STINGRAY_CELL` | `1` | Cellular MCC/MNC/LAC scan |
| `CPIP_STINGRAY_RF` | `1` | RF spectrum anomaly scan |
| `CPIP_STINGRAY_SIG` | `1` | Signal-strength anomaly scan |
| `CPIP_STINGRAY_KNOWN` | `1` | Known-signature (IMSI-catcher DB) scan |

### Anti-Surveillance Policy

All defenses default to **on** and are individually togglable at runtime via `POST /cpip/anti-surveillance` or `PUT /cpip/config`.

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_ANTI_SURVEILLANCE` | `1` | Master enable for counter-surveillance |
| `CPIP_DPI_EVASION` | `1` | DPI evasion (traffic shaping) |
| `CPIP_DPI_EVASION_MODE` | `aggressive` | DPI evasion mode |
| `CPIP_TRAFFIC_OBFUSC` | `1` | Traffic obfuscation (pad/garble) |
| `CPIP_METADATA_STRIP` | `1` | Header/metadata stripping |
| `CPIP_TLS_FP_ROTATE` | `3600` | TLS fingerprint rotation (seconds) |
| `CPIP_EXPLOITKIT_DETECT` | `1` | 0-click exploit-kit detection |
| `CPIP_PROC_INJECT_DETECT` | `1` | Process-injection / hooking detection |

### Net-Neutrality Policy

All countermeasures default to **on** and are individually togglable at runtime via `POST /cpip/net-neutrality` or `PUT /cpip/config`.

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_NET_NEUTRALITY` | `1` | Master enable for net-neutrality defense |
| `CPIP_NN_BW_MONITOR` | `1` | Bandwidth sampling/monitoring |
| `CPIP_NN_PROTO_MASK` | `1` | Protocol masquerade (disguise as web traffic) |
| `CPIP_NN_MASK_AS` | `standard_web` | Masquerade protocol label |
| `CPIP_NN_FRAG_EVASION` | `1` | Packet fragmentation for DPI evasion |
| `CPIP_NN_THROTTLE_DETECT` | `1` | Throttling detection |
| `CPIP_NN_JITTER` | `1` | Jitter (timing-noise) injection |
| `CPIP_NN_COVER_MIN` | `256` | Cover-traffic minimum size (bytes) |
| `CPIP_NN_COVER_MAX` | `1024` | Cover-traffic maximum size (bytes) |

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
| `CPIP_THERMOS_MAX` | `1000000` | Maximum dead-drop storage (bytes) |

### TLS/SSL

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_SSL` | `0` | Enable HTTPS (TLS) |
| `CPIP_SSL_CERT` | None | Path to TLS certificate PEM file |
| `CPIP_SSL_KEY` | None | Path to TLS private key PEM file |
| `CPIP_SSL_AUTO` | `0` | Auto-generate self-signed certificate on first run |
| `CPIP_SSL_CERT_DIR` | `.ssl` | Directory for auto-generated certificates |
| `CPIP_HTTP_REDIRECT` | `0` | Enable HTTP-to-HTTPS redirect |
| `CPIP_HTTP_REDIRECT_PORT` | `4181` | Port for HTTP redirect server |

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
| `POST` | `/cpip/mesh/sat` | Enable/disable satellite |
| `GET` | `/cpip/mesh/radio` | Radio transport status |
| `GET` | `/cpip/mesh/mobile` | Mobile transport status |
| `POST` | `/cpip/mesh/mobile` | Enable/disable mobile |
| `GET` | `/cpip/mesh/deaddrop` | List/claim dead drops |
| `GET` | `/cpip/defense` | Defense posture (418, stealth, blacklist, tools) |
| `POST` | `/cpip/defense` | Defense actions |

### Crypto and Security API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/cpip/crypto` | Crypto status |
| `POST` | `/cpip/crypto` | Key rotation |
| `GET` | `/cpip/incident` | Incident alerts and audit chain |
| `POST` | `/cpip/incident` | Create alert |
| `GET` | `/cpip/signal` | Signal awareness (bandwidth, link quality, jamming) |
| `POST` | `/cpip/emergency` | Emergency actions (activate, rotate_keys, wipe, deactivate) |
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

### Defense Policy API (Runtime Toggles)

Every defense vector is independently togglable at runtime without restart. The `feature` field accepts the per-vector names listed in the environment variable tables (e.g., `stun`, `upnp`, `cell_scan`, `dpi_evasion`, `fragmentation`).

| Method | Path | Payload | Description |
|--------|------|---------|-------------|
| `POST` | `/cpip/anti-isp` | `{"action":"toggle","feature":"stun","enabled":false}` | Toggle Anti-ISP transport |
| `POST` | `/cpip/anti-isp` | `{"action":"refresh"}` | Force refresh all transports |
| `POST` | `/cpip/anti-isp` | `{"action":"hole_punch","ip":...,"port":...}` | Punch a NAT hole |
| `POST` | `/cpip/anti-stingray` | `{"action":"toggle","feature":"cell_scan","enabled":false}` | Toggle detection vector |
| `POST` | `/cpip/anti-stingray` | `{"action":"rescan"}` | Force immediate rescan |
| `POST` | `/cpip/anti-surveillance` | `{"action":"toggle","feature":"dpi_evasion","enabled":false}` | Toggle defense vector |
| `POST` | `/cpip/anti-surveillance` | `{"action":"scan"}` | Force immediate scan |
| `POST` | `/cpip/net-neutrality` | `{"action":"toggle","feature":"fragmentation","enabled":false}` | Toggle countermeasure |
| `GET` | `/cpip/config` | None | Returns live `policies` block (all four groups) |
| `PUT` | `/cpip/config` | `{"policies":{"anti_isp":{"stun":false}}}` | Bulk-update policies at runtime |

Unknown `feature` names return HTTP 400. Toggling the master switch on any defense group starts or stops the background scan/reaction loop.

### Web Interface

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/dashboard` | Web dashboard |
| `GET` | `/static/*` | Static assets |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CPIP Server                                │
│                                                                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  HTCPCP  │  │  CPIP    │  │  Covert      │  │    ITF       │  │
│  │  Handler │  │  REST API│  │  Channel     │  │  Defense     │  │
│  │(RFC 2324)│  │(/cpip/*) │  │(Accept-Add)  │  │              │  │
│  └────┬─────┘  └────┬─────┘  └──────┬───────┘  └──────┬───────┘  │
│       │              │               │                  │         │
│  ┌────▼──────────────▼───────────────▼──────────────────▼──────┐  │
│  │             PotState Engine + Defense Engine                │  │
│  │    (state machine, history, scheduling, probe check)        │  │
│  └────────────────┬───────────────────────────────────────────┘  │
│                   │                                              │
│  ┌────────────────▼──────────────────────────────────────┐      │
│  │                Mesh Node Layer                         │      │
│  │   (peers, routing, store-and-forward, cross-transport) │      │
│  └───────┬──────────────────────┬──────────────┬─────────┘      │
│          │                      │              │                │
│  ┌───────▼──────┐  ┌───────────▼──────┐  ┌────▼─────────┐    │
│  │  LAN Mesh    │  │ Satellite Mesh   │  │ Radio (LoRa) │    │
│  │  UDP :4191   │  │ UDP :4195        │  │ Unix Socket  │    │
│  └──────────────┘  └─────────────────┘  └──────────────┘    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │  Mobile BB   │  │    GPIO      │  │   Web UI     │       │
│  │  UDP :4196   │  │  Control     │  │  Dashboard   │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
│  ┌──────────────────┐  ┌──────────────────┐                  │
│  │  Crypto Engine   │  │ Incident Response│                  │
│  │ (AES-256-GCM,    │  │ (auto-detect,    │                  │
│  │  RSA-KEM, Hybrid)│  │  alert, mitigate)│                  │
│  └──────────────────┘  └──────────────────┘                  │
└─────────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
├── server.py              # Main server (Python)
├── cpip                   # CLI client (bash)
├── deploy.sh              # Raspberry Pi deployment script
├── deploy_cpip.sh         # Minimal HTCPCP-only deployment
├── Dockerfile             # Docker image (Alpine, SSL-enabled)
├── web/
│   └── index.html         # Web dashboard SPA
├── k8s/
│   ├── deployment.yaml    # Kubernetes manifests
│   └── kustomization.yaml # Kustomize configuration
├── radio/
│   ├── radio_if.c         # C radio interface (LoRa SPI, KISS TNC, RTL-SDR, sim)
│   ├── radio_if.h         # C header
│   ├── radio_protocol.py  # Python bridge to C binary
│   └── Makefile           # Build (zero external dependencies)
└── pi-apps/
    ├── install
    ├── uninstall
    ├── credits
    ├── description
    └── icon-64.png
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

This is free and unencumbered software released into the public domain. See [LICENSE](LICENSE) for details.

The CoffeeCipher v3 uses FIPS-compliant cryptographic primitives (AES-256-GCM, ECDSA/ECDH P-256, RSA-KEM-2048, HKDF-SHA256, HMAC-SHA256).
