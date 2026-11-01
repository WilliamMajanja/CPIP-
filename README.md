# CPIP — Coffee Pot Internet Protocol

[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://python.org)
[![Platform: Linux | Raspberry Pi](https://img.shields.io/badge/platform-Linux%20%7C%20Raspberry%20Pi-green.svg)](deploy-pi.sh)
[![Version](https://img.shields.io/badge/version-7.0.0-blue.svg)](https://github.com/WilliamMajanja/CPIP-/releases/tag/v7.0.0)
[![CI](https://img.shields.io/github/actions/workflow/status/WilliamMajanja/CPIP-/ci.yml?branch=master)](https://github.com/WilliamMajanja/CPIP-/actions)

> *"I'm a teapot."* — RFC 2324, April 1st, 1998

CPIP is a production-grade implementation of the Hyper Text Coffee Pot Control Protocol (HTCPCP) extending RFC 2324 and RFC 7168 (HTCPCP-TEA) into a resilient, encrypted, multi-transport mesh communication system with active counter-surveillance capabilities.

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [CLI Tools](#cli-tools)
- [Web Dashboard](#web-dashboard)
- [Cryptography](#cryptography)
- [Multi-Transport Mesh](#multi-transport-mesh)
- [Defense Systems](#defense-systems)
- [Deployment](#deployment)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Development](#development)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

## Overview

What began as an April Fools' joke has evolved into a fully-featured covert communication platform. CPIP combines:
- **Standards Compliance**: Full HTCPCP/HTCPCP-TEA implementation (BREW, GET, PROPFIND, WHEN, OPTIONS)
- **Resilient Mesh**: Store-and-forward networking across LAN, satellite, radio (LoRa/TNC), and mobile networks
- **End-to-End Encryption**: Hybrid classical + post-quantum cryptography
- **Active Defense**: Counter-surveillance against ISP throttling, Stingray IMSI catchers, DPI, and traffic analysis
- **Covert Channels**: Steganographic messaging hidden within coffee protocol traffic

## Key Features

### Core Protocol
- **HTCPCP Compliance** — BREW coffee/tea, WHEN pot is ready, PROPFIND capabilities, OPTIONS methods
- **418 I'm a Teapot** — Authentic RFC 2324 error responses
- **Coffee Pot Control** — GPIO integration for physical Raspberry Pi coffee maker control

### Networking & Mesh
- **Multi-Transport Routing** — Automatic failover across UDP/LAN, satellite, LoRa radio, 4G/5G
- **Store-and-Forward** — Messages queue when peers offline, delivered on reconnection
- **Peer Discovery** — mDNS/SSDP and manual peer configuration
- **Port Hopping** — Dynamic port rotation for evasion
- **Bonding** — Aggregate bandwidth across multiple links simultaneously

### Cryptography & Security
- **CoffeeCipher v5** — AES-256-GCM with HKDF-SHA256, authenticated encryption
- **Hybrid KEM** — ECDH P-256 + post-quantum KEM (Kyber/ML-KEM compatible)
- **Digital Signatures** — ECDSA P-256 (FIPS 186-4)
- **Perfect Forward Secrecy** — Ephemeral keys for each session
- **Post-Quantum Ready** — ML-KEM support with experimental custom variants

### Counter-Surveillance
- **Anti-ISP** — Traffic shaping evasion, DNS-over-HTTPS, WebSocket tunneling, fragmentation
- **Anti-Stingray** — IMSI catcher detection, cell tower anomaly monitoring
- **Anti-DPI** — Protocol obfuscation, padding, timing jitter, cover traffic
- **Anti-Palantir** — Traffic analysis resistance, mix-net style routing, chaff generation
- **ITF Defense** — Automated blocking of security scanners (Burp, Nmap, SQLMap, Nikto, 16+ tools)
- **Net Neutrality Tools** — Bandwidth monitoring and throttling detection

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Web UI     │────▶│   Server.py   │────▶│  Mesh Router │
│  Dashboard   │     │  (HTTP/HTTPS) │     │ Multi-Transport│
└─────────────┘     └──────────────┘     └─────────────┘
                            │                      │
                    ┌───────┴────────┐    ┌───────┴────────┐
                    │  Crypto Layer  │    │ Defense System  │
                    │ CoffeeCipher v5│    │ ITF + Anti-*    │
                    └────────────────┘    └────────────────┘
```

## Quick Start

### Prerequisites
- Python 3.10-3.13
- Linux/macOS/Windows (Linux recommended for full features)
- Optional: Raspberry Pi with GPIO for coffee pot control
- Optional: LoRa radio, cellular modem

### Installation

```bash
# Clone repository
git clone https://github.com/WilliamMajanja/CPIP-.git
cd CPIP-

# Install dependencies
pip install -r requirements.txt
# or
pip install cryptography

# Generate self-signed certificates (optional, auto-generated)
./mkcert

# Run server
python server.py
```

### Access
- **Web Dashboard**: https://localhost:4180 or http://localhost:4180
- **Default Port**: 4180 (HTTP), 4181 (HTTPS)

## Usage

### Start Server
```bash
# Basic start
python server.py

# With all features enabled
CPIP_DEFENSE_ENABLED=1 CPIP_MESH_ENABLED=1 CPIP_BONDING=1 python server.py

# Raspberry Pi with GPIO
CPIP_GPIO=1 python server.py
```

### CLI Tools

**b4dm4n_cw.py** - Cipher Workbench (Zero external deps except optional Pillow)
```bash
# Key generation
python b4dm4n_cw.py keygen -o mykey

# Encryption/Decryption
python b4dm4n_cw.py encrypt -k mykey.pk file.txt -o file.enc
python b4dm4n_cw.py decrypt -k mykey.sk file.enc -o file.txt

# Post-quantum KEM
python b4dm4n_cw.py keygen -a inf1del-kyber -o pqkey
python b4dm4n_cw.py encaps -p pqkey.pk -o ct.bin
python b4dm4n_cw.py decaps -k pqkey.sk -c ct.bin

# Image to ASCII (new in v7.0.0)
python b4dm4n_cw.py ascii image.png -w 80 -o art.txt

# Benchmarks
python b4dm4n_cw.py bench -a inf1del-kyber -n 100
```

**cpip** - Main CLI tool
```bash
# Check status
./cpip status

# Brew coffee (HTCPCP)
./cpip brew --additions milk

# Mesh messaging
./cpip mesh send peer_id "Hello"
./cpip mesh peers
```

## Web Dashboard

Access the dashboard at `http://localhost:4180` for:
- **Brew** — HTCPCP requests with additions (milk, sugar, syrup, etc.)
- **Mesh** — Peer management, messaging, routing table
- **Covert** — Hidden message channel via Accept-Additions headers
- **ITF Defense** — Threat monitoring, IP blacklist, blocked attacks
- **Bonding** — Multi-link aggregation statistics
- **Palantir** — Counter-surveillance controls and metrics
- **History** — Request/response audit trail

## Cryptography

| Primitive | Purpose | Standard |
|-----------|---------|----------|
| AES-256-GCM | Authenticated encryption | FIPS 197 |
| HKDF-SHA256 | Key derivation | RFC 5869 |
| HMAC-SHA256 | Message authentication | FIPS 198-1 |
| ECDSA P-256 | Digital signatures | FIPS 186-4 |
| ECDH P-256 | Key exchange | NIST SP 800-56A |
| ML-KEM/Custom KEM | Post-quantum key encapsulation | NIST PQC (experimental) |
| SHA-256/SHA3-256 | Hashing | FIPS 180-4 |

## Multi-Transport Mesh

| Transport | Range | Use Case | Status |
|-----------|-------|----------|--------|
| **LAN/UDP** | Local network | Primary, high-speed | Stable |
| **Satellite** | Global | Bypass ISP blocks/censorship | Configurable |
| **Radio (LoRa)** | 1-15km | Off-grid, mesh relays | Experimental |
| **Radio (TNC)** | Varies | Amateur radio networks | Experimental |
| **Mobile (4G/5G)** | Cellular | Fallback, mobility | Configurable |

## Defense Systems

### ITF (In The Face) Defense
Automatically detects and blocks:
- Port scanners (Nmap, Masscan)
- Web vulnerability scanners (Burp, OWASP ZAP, Nikto, SQLMap)
- Exploitation frameworks (Metasploit, Hydra)
- Directory brute-forcers (Gobuster, Dirbuster, FFUF)
- Custom user-agent and behavioral fingerprinting

Response: HTTP 418 I'm a Teapot with minimal information disclosure.

### Active Counter-Surveillance
- **Traffic Padding**: Random padding to normalize packet sizes
- **Timing Obfuscation**: Jitter injection to break timing analysis
- **Cover Traffic**: Legitimate HTCPCP requests mask encrypted data
- **Chaff Generation**: Decoy traffic to confuse traffic analysis
- **Metadata Stripping**: Remove identifying headers
- **Link Hopping**: Rotate transports to evade monitoring

## Deployment

### Docker
```bash
docker build -t cpip:7.0.0 .
docker run -p 4180:4180 -p 4181:4181 cpip:7.0.0
```

### Docker Compose
```bash
docker-compose up -d
```

### Kubernetes
```bash
kubectl apply -k k8s/
```

### Raspberry Pi (systemd)
```bash
sudo ./deploy-pi.sh
sudo systemctl enable --now cpip
```

## Configuration

Key environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_PORT` | 4180 | HTTP port |
| `CPIP_HTTPS_PORT` | 4181 | HTTPS port |
| `CPIP_DEFENSE_ENABLED` | 1 | Enable ITF defense |
| `CPIP_MESH_ENABLED` | 1 | Enable mesh networking |
| `CPIP_BONDING` | 1 | Enable multi-link bonding |
| `CPIP_PALANTIR` | 0 | Enable anti-Palantir features |
| `CPIP_SATELLITE` | 0 | Enable satellite transport |
| `CPIP_MOBILE` | 0 | Enable mobile transport |
| `CPIP_GPIO` | 0 | Enable GPIO coffee pot control |
| `CPIP_ML_KEM_BACKEND` | stdlib | KEM backend (stdlib/pqcrypto) |

See [README.md](README.md) for complete configuration reference.

## API Reference

### HTCPCP Endpoints
- `BREW /` — Brew coffee/tea with optional additions
- `GET /` — Status check
- `PROPFIND /` — Capabilities discovery
- `WHEN /` — Ask when pot ready
- `OPTIONS /` — List supported methods

### REST API
- `GET /api/status` — Server status
- `GET /api/mesh/peers` — Mesh peers
# ...
