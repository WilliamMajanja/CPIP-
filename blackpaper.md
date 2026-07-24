# Blackpaper: The Coffee Protocol (CPIP)
### A Multi-Transport Mesh with Hybrid Post-Quantum Cryptography and Active Network Defense

**Version 5.1.0** · **Date: July 2026** · **Status: Public Domain (Unlicense)**

---

## Abstract

CPIP (Coffee Pot Internet Protocol) is an implementation of the Hyper Text Coffee Pot Control Protocol (HTCPCP), originally specified as an April Fools' RFC (RFC 2324, 1998) and extended for tea in RFC 7168. This blackpaper describes how CPIP transforms that joke protocol into a production-grade, multi-transport mesh communication system with end-to-end encryption, hybrid post-quantum key exchange, store-and-forward messaging, covert channels, and active network defense. We document the protocol design, cryptographic architecture (CoffeeCipher v5 / AES-256-GCM, ECDSA/ECDH P-256, and a hybrid ECDH + 1nf1D3L Kyber ML-KEM-768 KEM), the four-transport routing fabric (LAN, satellite, radio, mobile), the ITF defense engine, and the integration surface with Minima blockchain nodes in the PiNet-OS edge stack. The system is intentionally FIPS-aligned for its classical primitives while keeping a non-FIPS post-quantum component for research and forward security.

---

## 1. Introduction

### 1.1 Motivation

RFC 2324 defined the HTTP 418 "I'm a teapot" status code and a control vocabulary for coffee pots over HTTP. While humorous, the protocol is syntactically valid HTTP/1.1 and provides a plausible cover for arbitrary control-plane traffic. CPIP exploits this dual nature: every brew request and response is a legitimate HTCPCP transaction *and* a potential carrier for encrypted mesh payloads. The result is a protocol stack that is both a faithful implementation of a joke RFC and a serious communication system for hostile and degraded network environments — edge deployments, wilderness radio links, censorship circumvention, and contested spectrum.

### 1.2 Design Goals

1. **RFC fidelity** — Full HTCPCP / HTCPCP-TEA semantics (BREW, WHEN, PROPFIND, OPTIONS), the 418 semantics, addition vocabularies, and the international coffee-URI scheme family.
2. **Plausible cover traffic** — All mesh and covert traffic is shaped as ordinary brew/tea transactions, defeating naive traffic classification.
3. **Multi-transport resilience** — A single logical mesh spans LAN UDP, satellite/internet UDP, LoRa/TNC radio, and 4G/5G WWAN, with automatic cross-transport forwarding and routing-loop prevention.
4. **Hybrid post-quantum security** — Classical ECDH P-256 is composed with a non-FIPS Kyber ML-KEM-768 variant; the combination is secure if *either* component holds.
5. **FIPS alignment where it counts** — AES-256-GCM, ECDSA/ECDH P-256, HKDF-SHA256, and HMAC-SHA256 are FIPS-197/186-4/180-4 compliant; the PQ component is explicitly non-FIPS and labelled as such.
6. **Active defense** — Probe identification, pentest-tool fingerprinting, rate-limited blacklisting, and stealth/port-hopping, all runtime-togglable without restart.
7. **Operability** — Single-file Python stdlib server, bash CLI, TUI, embedded web dashboard, Kubernetes manifests, systemd deployment, and one-click Pi-Apps install.

### 1.3 Non-Goals

- CPIP does not implement RSA-KEM; the hybrid KEM is strictly ECDH + Kyber.
- CPIP's Kyber is not FIPS 203 validated. It is a research variant (η=3) and is not claimed to be certified.
- CPIP does not seek IETF standardization; it consumes an existing RFC for cover.

---

## 2. Threat Model

CPIP assumes an adversary capable of:

- **Passive network observation** — DPI, traffic logging, metadata collection.
- **Active probing** — sending crafted HTCPCP/HTTP requests to enumerate and fingerprint the service.
- **Selective interference** — throttling, jamming, DNS poisoning, port blocking, and IMSI-catcher deployment against mobile transports.
- **Cryptanalytic advancement** — including future quantum adversaries against recorded traffic ("harvest now, decrypt later").

CPIP does **not** assume:

- Physical tamper resistance of end nodes (keys are software-held unless an HSM/PKCS#11 module is configured).
- A trustworthy DNS hierarchy (DoH, DNS tunneling, and `.pot` name resolution are provided as alternatives).
- A cooperative ISP (Anti-ISP transports: STUN, UPnP, relay pool, WSS, DoH).

---

## 3. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CPIP Server                                 │
│                                                                     │
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
│  │  ECDH+Kyber)     │  │  alert, mitigate)│                  │
│  └──────────────────┘  └──────────────────┘                  │
└─────────────────────────────────────────────────────────────────────┘
```

The server is a single Python file using only the standard library (`http.server`) plus the `cryptography` package. The CLI (`cpip`) is a bash script; the TUI (`cpip_tui.py`) uses OpenTUI. The radio interface is a C binary (`radio_if.c`) with zero external dependencies, bridged to Python over a Unix domain socket.

---

## 4. Protocol Layer: HTCPCP

### 4.1 RFC 2324 Semantics

| Method | Path | Effect |
|--------|------|--------|
| `BREW` | `/coffee`, `/tea` | Begin brewing; body may carry Accept-Additions |
| `WHEN` | `/` | Stop brewing |
| `PROPFIND` | `/` | Pot metadata |
| `OPTIONS` | `/` | Capabilities advertisement |
| `GET` | `/health` `/ready` | Liveness / readiness probes |

A `BREW` against a beverage unsupported by the device yields HTTP 418 "I'm a teapot". The `hyper-text` device brews both coffee and tea; `teapot` brews only tea; `coffee-pot` brews only coffee. This is the canonical 418 trigger and is reused as a defensive signal against probes (see §8).

### 4.2 Coffee-URI Internationalization

CPIP recognises 29 international `coffee://` URI schemes across multiple languages. Any `{scheme}://host/pot-N?additions` URI is accepted as a brew request, expanding the cover-traffic surface beyond ASCII English.

### 4.3 Additions Vocabulary

Accept-Additions carry typed coffee customization:

| Type | Varieties |
|------|-----------|
| milk (6) | cream, half-and-half, whole, part-skim, skim, non-dairy |
| syrup (5) | vanilla, caramel, almond, hazelnut, chocolate |
| sugar (5) | white, brown, raw, honey, artificial |
| spice (4) | cinnamon, cardamom, nutmeg, clove |
| alcohol (5) | whisky, rum, kahlua, aquavit, brandy |

The covert channel (§7) hides data inside these addition strings.

---

## 5. Cryptographic Architecture

### 5.1 CoffeeCipher v5 — AES-256-GCM with HKDF-SHA256

- **Cipher**: AES-256-GCM (FIPS 197), 12-byte random nonce, 16-byte authentication tag.
- **Wire format**: `nonce(12B) || ciphertext || GCM-tag(16B)`.
- **Key derivation**: HKDF-SHA256 (SP 800-56C) with domain-separated `info` strings of the form `cpip-cipher-v5:<recipe>`.
- **Recipe binding**: A "coffee recipe" string (espresso, latte, cappuccino, americano, cold-brew, mocha, matcha, or a custom label such as `minima`) is mixed into the KDF. Different recipes produce cryptographically independent keys from the same base key material, giving cheap domain separation per deployment.
- **Backward compatibility**: v1 and v2 ciphertexts are read transparently; v5 is the write format.

Constant-time primitives are supplied by the `cryptography` library. The `secrets` module replaces `random` for all security-relevant randomness.

### 5.2 ECDSA / ECDH over NIST P-256 (FIPS 186-4)

Used for:

- **Mesh E2EE** — ECDH P-256 key agreement between peers.
- **Node identity** — ECDSA P-256 signatures over pot identity claims.
- **Address book** — P-256 public-key fingerprints serve as mesh addresses.
- **Port hopping** — signed port-hop announcements.

### 5.3 HybridKEM — ECDH P-256 + 1nf1D3L Kyber

CPIP's hybrid key encapsulation mechanism combines a classical ECDH P-256 exchange with a post-quantum Kyber KEM. The two shared secrets are concatenated and fed to HKDF-SHA256 with domain tag `cpip-hybrid-kem-kyber-v1`.

- **Security property**: The composite is secure if *either* the classical ECDH component *or* the PQ Kyber component resists the adversary. This hedges against both a sudden classical break and a future quantum adversary, while not trusting the non-FIPS PQ component alone.
- **Sizes**: PK ≈ 1251 B, SK ≈ 2432 B, CT ≈ 1187 B, SS = 32 B.
- **Implementation**: `server.HybridKEM` in `server.py`.

### 5.4 1nf1D3L Kyber KEM (Non-FIPS, Research Variant)

A modified ML-KEM-768 provided as the `b4dm4n-cw` CLI (`inf1del_kyber.py`):

- **Parameters**: n=256, k=3, q=3329, η₁=3, η₂=3, dᵤ=10, dᵥ=4.
- **Domain tag**: `1NF1D3L-KYBER-V1` on every hash/KDF input.
- **Wider noise**: η=3 (vs FIPS η=2) for enhanced concrete security at the cost of larger errors.
- **NTT twiddle perturbation**: Per-session random twiddle factors for side-channel resistance.
- **Key confirmation**: Re-encapsulation check; decapsulation failures are caught and fed to a KDF with a rejection value `z` (implicit rejection).
- **Sizes**: PK=1184 B, SK=2400 B, CT=1120 B, SS=32 B.
- **CLI**: `./b4dm4n_cw.py {keygen,encaps,decaps,...}`; hybrid selected via `-a hybrid` (alias for `hybrid-ecdh-kyber`).

This variant is **not** FIPS 203 validated and is intended for research and experimental use. It is explicitly labelled as non-FIPS in all status outputs.

### 5.5 Supporting Primitives

| Primitive | Use |
|-----------|-----|
| HMAC-SHA256 / HMAC-SHA3-256 | Mesh heartbeat auth, message integrity, RPC token auth |
| SHA-256 (domain-separated) | Tamper-evident audit chain, node identity |
| SHA3-256 | Kyber KDF / H |
| HKDF-SHA256 | All key derivation |

### 5.6 FIPS Self-Tests

When `CPIP_FIPS=1`, the server runs power-on Known Answer Tests for AES-256-GCM, HMAC-SHA256, HKDF, ECDSA sign/verify, and ECDH key agreement. Startup aborts on any failure. This provides FIPS 140-2/3-style assurance for the classical surface.

### 5.7 Encrypted Persistence

Data at rest uses a v4 format: AES-256-GCM encryption with HMAC integrity verification. v1/v2 formats are loadable for backward compatibility. Persistence lives under `CPIP_MESH_PERSIST_DIR` (default `/tmp/cpip`).

---

## 6. Multi-Transport Mesh

CPIP runs one logical mesh over four physical transports, with automatic cross-transport forwarding and loop prevention via TTL and visited-node tracking.

| Transport | Env | Port | Runtime Toggle | Notes |
|-----------|-----|------|----------------|-------|
| LAN | `CPIP_MESH=1` | 4191 | — | UDP heartbeats, local subnet, zero-internet |
| Satellite | `CPIP_SAT=1` | 4195 | `POST /cpip/mesh/sat` | Internet-wide UDP relay; GPS coords; high-latency timeouts |
| Radio | `CPIP_RADIO=1` | Unix socket | — | LoRa SPI / KISS TNC / RTL-SDR / sim |
| Mobile | `CPIP_MOBILE=1` | 4196 | `POST /cpip/mesh/mobile` | 4G/5G WWAN; RSRP/RSSI/SINR telemetry |

### 6.1 LAN Mesh

UDP heartbeats on 4191 with ECDH P-256 E2EE by default. Supports port hopping (`CPIP_MESH_LATENT_PORTS=4192,4193,4194`) and stealth mode. Works over Ethernet, WiFi, WiFi Direct, or any IP fabric.

### 6.2 Satellite Mesh

Internet-wide UDP relay on 4195 for high-latency links. Advertises GPS coordinates (lat/lon/alt), supports bootstrap seed nodes, and accepts configurable timeouts. Dual env naming (`CPIP_SAT_*` / `CPIP_STARLINK_*`) for backward compatibility.

### 6.3 Radio Transport

A C binary (`radio/radio_if.c`) built with `gcc -O2 -Wall -pthread` and zero external dependencies. Supports:

- **SX1276/SX1278 LoRa** via SPI (full register map).
- **KISS TNC** serial (AX.25 over termios).
- **RTL-SDR receive** (optional, `make RTL=1`, requires librtlsdr).
- **Simulation** requires explicit `--sim`; LoRa mode requires real hardware.

Duty-cycle enforcement and listen-before-talk are implemented in the C layer. The Python bridge (`radio/radio_protocol.py`) communicates over `/tmp/cpip-radio.sock`.

### 6.4 Mobile Broadband

UDP mesh over cellular interfaces. Reads signal quality via ModemManager (`mmcli`) and sysfs; exposes RSRP/RSSI/SINR telemetry. Bootstrap seed nodes for discovery; TCP-keepalive-compatible heartbeat intervals.

### 6.5 Store-and-Forward

Messages are queued per-recipient and delivered when the recipient appears on *any* transport. The queue is encrypted at rest and survives restarts. Routing loops are prevented by TTL (`CPIP_MESH_TTL=5`) and a visited-set carried per message.

---

## 7. Covert Channel

Messages are embedded inside legitimate `Accept-Additions` headers, disguised as coffee customization:

```
Accept-Additions: milk;variety=48656c6c, syrup;variety=6f20576f, sugar;variety=726c6421
```

- **Encoding**: Plaintext → hex chunking into addition varieties; recipe labels (`recipe_<chunk>`) carry the active recipe string for domain separation.
- **ECC mode**: When a destination public key is known, an ECDH-derived one-time key encrypts the payload (AES-256-GCM) before embedding.
- **Cover traffic**: Random brew requests at configurable intervals obscure which requests carry real messages.
- **History**: The dashboard Covert tab persists message history in `localStorage`.

Because the carrier is RFC-2324-conformant HTCPCP traffic, the channel survives DPI that classifies by protocol name — there is nothing to classify except a coffee pot.

---

## 8. ITF Defense System

"ITF" (In The Face) implements active network defense. Hostile probes receive HTTP 418 responses and are blacklisted.

### 8.1 Detection Methods

| Method | Probe score |
|--------|-------------|
| Scanner paths (`/admin`, `/wp-`, `/.env`, `/phpmyadmin`, `/shell`, `/cmd`, `/exec`, `/backdoor`, `/login`, `/setup`, `/install`, `/manager`, `/config`, `/console`) | +3 |
| Missing headers (BREW without Accept-Additions on non-standard paths) | +1 |
| Unknown URI schemes (non-coffee URIs) | +2 |
| Pentest tool fingerprinting (16 tools) | +2 |
| **Threshold** | **≥ 2** → 418 + blacklist |

### 8.2 Detected Tools

Burp Suite, Nmap, SQLMap, Nikto, Gobuster, Dirb, FFUF, WFuzz, OpenVAS, Nessus, Masscan, ZAP, Arachni, w3af, Metasploit, Acunetix (16). Informational tools (cURL, Wget, Python, Go-http) are tracked but not blocked.

### 8.3 Blacklist Behaviour

- Base TTL: 3600 s (`CPIP_DEFENSE_BLACKLIST_TTL`).
- Rate limit: 10 probes / 60 s doubles the ban (capped at 86400 s).
- Max entries: 1000; oldest half pruned on overflow.
- Localhost (127.0.0.1, ::1, localhost) is never blacklisted.

### 8.4 Runtime Controls

All defense vectors — across Anti-ISP, Anti-Stingray, Anti-Surveillance, and Net-Neutrality groups — are independently togglable at runtime via `POST /cpip/<group>` or `PUT /cpip/config` without restart. Toggling a group master switch starts/stops the background scan loop.

---

## 9. Anti-ISP, Anti-Stingray, Anti-Surveillance, Net-Neutrality

Each group is a collection of independently togglable vectors. All default to **on**.

### 9.1 Anti-ISP

| Vector | Purpose |
|--------|---------|
| STUN (`CPIP_STUN`) | NAT hole-punching |
| UPnP (`CPIP_UPNP`) | Port mapping |
| DNS tunnel (`CPIP_DNS_TUNNEL`) | Covert transport over DNS |
| WSS relay (`CPIP_WSS`) | WebSocket relay tunnel |
| Relay pool (`CPIP_RELAY`) | Mesh relay servers |
| DoH (`CPIP_DOH`) | Oblivious DNS over HTTPS |

### 9.2 Anti-Stingray

Cellular MCC/MNC/LAC scan, RF spectrum anomaly scan, signal-strength anomaly scan, and known-signature (IMSI-catcher DB) scan. Configurable scan interval and signal-anomaly delta threshold.

### 9.3 Anti-Surveillance

DPI evasion (traffic shaping), traffic obfuscation (pad/garble), metadata stripping, TLS fingerprint rotation, 0-click exploit-kit detection, and process-injection / hooking detection.

### 9.4 Net-Neutrality

Bandwidth sampling/monitoring, protocol masquerade (disguise as standard web traffic), packet fragmentation for DPI evasion, throttling detection, and jitter (timing-noise) injection.

---

## 10. Incident Response and Signal Awareness

### 10.1 Incident Response

Auto-detection of anomalies with severity classification (info/warning/critical), a tamper-evident SHA-256 audit chain, and auto-mitigation state. Alerts are creatable via `POST /cpip/incident`.

### 10.2 Signal Awareness

Continuous bandwidth estimation, link quality monitoring, and jamming detection feed into the routing layer. Degraded transports are deprioritized; the mesh falls back across transports automatically.

### 10.3 Emergency Mode

`POST /cpip/emergency` supports `activate`, `rotate_keys`, `wipe`, `deactivate`. Activation rotates all keys, notifies peers, forces stealth mode, and engages mitigations. Secure wipe zeroes keys and clears inboxes and stores.

---

## 11. Identity, Trust, Naming

### 11.1 Web of Trust

Identities are ECDSA P-256 keypairs. Peers vouch for each other at trust levels (2 = marginal, 3 = full). The trust graph is queryable via `GET /cpip/identity/trust-graph`. Trust signatures are exposed at `GET /cpip/identity/trust-sigs`.

### 11.2 `.pot` DNS

A self-sovereign naming layer maps human-readable `<name>.pot` to pot IDs, registered via `POST /cpip/dns/register`. Stale entries are expired via `POST /cpip/dns/cleanup`. This sidesteps the legacy DNS hierarchy entirely.

### 11.3 Groups and Sync

E2EE group chats (create/join/leave/send/history) and offline-sync channels (channels/pending/clocks/send/deliver/request) provide multi-party and delay-tolerant messaging on top of the same mesh.

---

## 12. Deployment

### 12.1 Standalone

```bash
./server.py                        # SSL + auto-cert + redirect ON by default
CPIP_SAT=1 CPIP_RADIO=1 CPIP_MOBILE=1 ./server.py   # all transports
```

### 12.2 Raspberry Pi

`sudo ./deploy.sh` installs the server to `/opt/cpip`, the CLI to `/usr/local/bin/cpip`, a systemd unit (`cpip.service`), and a Pi-Apps package when `pi-apps/` is present. GPIO relay control is available on Pi hardware (`CPIP_GPIO=1`).

### 12.3 Kubernetes

Bundled manifests (`k8s/deployment.yaml`) provide Namespace, ConfigMap, Secret, Deployment with health/readiness/startup probes, ClusterIP Service (HTTP 4180, mesh UDP 4191/4195/4196), nginx Ingress with TLS passthrough, NetworkPolicy, and a 1 Gi PVC. Image tag: `cpip:5.0.0`.

### 12.4 Docker

```bash
docker build -t cpip:5.0.0 .
docker run -p 4180:4180 -p 4181:4181 -p 4191:4191/udp \
  -e CPIP_SSL=1 -e CPIP_SSL_AUTO=1 -e CPIP_HTTP_REDIRECT=1 \
  cpip:5.0.0
```

### 12.5 TLS/SSL

Three modes: auto self-signed (OpenSSL, falling back to `cryptography`, then a stub), custom certificates (`CPIP_SSL_CERT` / `CPIP_SSL_KEY`), and HTTP-to-HTTPS redirect on a separate port (4181). Security headers (HSTS, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, CSP, Upgrade-Insecure-Requests) are emitted when SSL is active.

---

## 13. Minima / PiNet-OS Integration

CPIP v5.1.0 serves as the primary cryptographic security provider for Minima blockchain nodes in the PiNet-OS edge computing stack.

| Integration surface | CPIP capability |
|---------------------|-----------------|
| Data at rest | CoffeeCipher v5 (AES-256-GCM + HKDF-SHA256) |
| Node identity | ECDSA P-256 challenge-response authentication |
| RPC authentication | HMAC-SHA256 time-bounded tokens (replaces Basic Auth) |
| Key encapsulation | HybridKEM — ECDH P-256 + 1nf1D3L Kyber |
| Message signatures | ECDSA P-256 |
| API defense | ITF Defense (probe blocking, pentest detection, blacklisting) |
| FIPS assurance | Power-on self-tests (AES-GCM, HMAC, HKDF, ECDSA, ECDH) |

Deployment: CPIP runs as a sidecar container (`cpip:5.0.0`, port 4180) in the Minima k3s DaemonSet and as a dedicated `cpip.service` systemd unit.

PQ complementarity: Minima uses WOTS+ (FIPS 205, 128-bit PQ) for consensus signatures; CPIP adds Kyber (non-FIPS ML-KEM-768) for transport encryption. The two approaches are complementary — WOTS+ for consensus, Kyber for key exchange.

---

## 14. Configuration Summary

All configuration is via environment variables; no config files are required. Notable knobs (full table in README §Configuration):

| Variable | Default | Purpose |
|----------|---------|---------|
| `CPIP_DEVICE` | `hyper-text` | teapot / coffee-pot / hyper-text |
| `CPIP_PORT` | 4180 | HTTP port |
| `CPIP_MESH` | 1 | Enable LAN mesh |
| `CPIP_SAT` / `CPIP_STARLINK` | 0 | Enable satellite mesh (dual-naming for backcompat) |
| `CPIP_RADIO` | 0 | Enable radio transport |
| `CPIP_MOBILE` | 0 | Enable mobile transport |
| `CPIP_COVERT_KEY` | (auto) | Encryption passphrase; auto-generated if unset |
| `CPIP_RECIPE` | `espresso` | Default KDF recipe (Minima uses `minima`) |
| `CPIP_RPC_AUTH` | 1 | Require HMAC-SHA256 tokens on mutating endpoints |
| `CPIP_DEFENSE_ENABLED` | 1 | Master gate for ITF defense |
| `CPIP_FIPS` | 0 | Require power-on self-tests to pass |
| `CPIP_SSL` / `CPIP_SSL_AUTO` / `CPIP_HTTP_REDIRECT` | 1 | TLS + redirect defaults on |

---

## 15. Security Considerations

- **Non-FIPS PQ component**: 1nf1D3L Kyber is not FIPS 203 validated. It is a research variant (η=3) and must not be relied upon as a certified primitive. The hybrid construction limits the blast radius of any weakness in this component, provided the classical ECDH half holds.
- **Cover traffic is heuristic, not cryptographic**: DPI evasion depends on adversary behaviour; a determined classifier with traffic models may still distinguish covert-carrying brews. CPIP raises the cost, it does not make detection impossible.
- **Software key storage**: Without an HSM (`CPIP_HSM_MODULE`), keys live in process memory. Emergency `wipe` zeroes what it can but cannot guarantee erasure from swap or core dumps.
- **Probe scoring is heuristic**: Threshold tuning (`CPIP_DEFENSE_RATE_LIMIT`, `CPIP_DEFENSE_BLACKLIST_TTL`) trades false-positive rate against coverage. Localhost is always exempt to avoid lockout.
- **Side-channel scope**: Classical primitives are constant-time via `cryptography`. The PQ Kyber variant adds per-session NTT twiddle perturbation as a partial side-channel countermeasure; full side-channel hardening is out of scope.
- **CLKF hardening (v5.1.0+)**: Diagnostic endpoints block SSRF to RFC 1918/loopback/link-local/metadata ranges. Port scans capped at 20 ports. All mutating `/cpip/*` endpoints require HMAC auth by default (`CPIP_RPC_AUTH=1`). `deploy.sh` configures iptables with INPUT DROP policy and explicit allowlists. The default `CHANGE_ME_COFFEE_BLEND_2024` COVERT_KEY is rejected and auto-generated.

---

## 16. Future Work

- **PQ signature integration** — complement Kyber KEM with a PQ signature (e.g., a WOTS+ or Dilithium variant) for node identity, enabling a fully PQ-secure identity layer alongside Minima's WOTS+ consensus.
- **Hybrid certificate chains** — X.509 with classical + PQ signatures.
- **Formal cover-traffic analysis** — quantify detectability against trained classifiers and shape traffic accordingly.
- **FIPS 203 transition path** — a swappable Kyber implementation to allow moving to a FIPS-validated ML-KEM without protocol change.
- **Radio hardware certification** — regulatory-band-aware LoRa configuration for deployment legality across regions.

---

## 17. Conclusion

CPIP takes an April Fools' RFC and returns it as a serious, deployable, multi-transport mesh with hybrid post-quantum security and active defense. The joke is the cover; the cover is the protocol. By staying syntactically faithful to HTCPCP, CPIP gains a cover-traffic advantage that more obviously-military protocols cannot claim, while its hybrid ECDH + Kyber KEM, FIPS-aligned classical surface, and runtime-togglable defense posture make it suitable for edge, wilderness, and contested-environment deployment. The system is public-domain, single-file, and operable from a Raspberry Pi to a Kubernetes cluster.

---

## Appendix A — References

- RFC 2324 — Hyper Text Coffee Pot Control Protocol (HTCPCP)
- RFC 7168 — The Hyper Text Coffee Pot Control Protocol for Tea Efflux (HTCPCP-TEA)
- FIPS 197 — Advanced Encryption Standard (AES)
- FIPS 186-4 — Digital Signature Standard (ECDSA/ECDH P-256)
- FIPS 180-4 — Secure Hash Standard (SHA-256)
- SP 800-56C — HKDF (HMAC-based Key Derivation)
- SP 800-38D — Galois/Counter Mode (AES-GCM)
- FIPS 203 — Module-Lattice-Based Key-Encapsulation (ML-KEM, reference only; CPIP's Kyber is non-FIPS)
- FIPS 205 — Stateless Hash-Based Digital Signature (WOTS+ context, Minima consensus)

## Appendix B — Project Layout

```
server.py              Main server (Python stdlib http.server, ~11k lines)
cpip                   CLI client (bash)
cpip.1                 CLI man page (roff)
cpip_tui.py            Terminal UI (OpenTUI, 12 pages)
b4dm4n_cw.py           Cipher Workbench CLI v2.0
inf1del_kyber.py       1nf1D3L Kyber ML-KEM-768 (numpy-accelerated)
pyproject.toml         Package metadata (name: cpip, v5.1.0)
Dockerfile / docker-compose.yml
deploy.sh / deploy-pi.sh / cluster.sh
test_crypto.py / test_cpip.py
test_key.{pk,sk} / test_ct / test_hybrid.{hp,hs} / test_hybrid_ct
k8s/                   deployment.yaml, kustomization.yaml
radio/                 radio_if.c, radio_if.h, radio_protocol.py, Makefile
pi-apps/               install, uninstall, credits, description, icon-64.png
.github/workflows/ci.yml  CI matrix (Python 3.10–3.13 + Docker)
```

## Appendix C — License

This is free and unencumbered software released into the public domain. See `LICENSE` for details. The classical cryptographic primitives (AES-256-GCM, ECDSA/ECDH P-256, HKDF-SHA256, HMAC-SHA256) are FIPS-compliant. The hybrid KEM combines ECDH P-256 with 1nf1D3L's Kyber (non-FIPS ML-KEM-768).