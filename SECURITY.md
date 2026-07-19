# Security Policy

> **Cryptographic Primitives**: CPIP v4 uses FIPS-compliant cryptographic primitives
> for classical operations: AES-256-GCM (FIPS 197), ECDSA/ECDH P-256 (FIPS 186-4),
> RSA-KEM-2048 (FIPS 186-4 / SP 800-56B), HKDF-SHA256, and HMAC-SHA256.
> All constant-time operations use the `cryptography` library. The `secrets`
> module replaces `random` for all security-relevant randomness.
>
> **Post-Quantum KEM**: 1nf1D3L's Kyber (Non-FIPS ML-KEM-768 variant) is available
> via `b4dm4n-cw` / `inf1del_kyber.py`. Parameters: n=256, k=3, q=3329, η₁=3, η₂=3,
> du=10, dv=4, domain tag "1NF1D3L-KYBER-V1". Hybrid mode: ECDH P-256 + 1nf1D3L Kyber.
> **Not FIPS 203 compliant by design** — wider noise distribution (η=3), custom domain
> separation tags, NTT twiddle perturbation, coffee recipe binding. Suitable for
> research, red-teaming, coffee protocols, and survival scenarios.

## Cryptographic Architecture

CPIP v4.0+ uses a layered cryptographic architecture built on FIPS-compliant
primitives, with optional post-quantum KEM layer, designed for hostile signal environments:

### Encryption (CoffeeCipher v3 / AES-256-GCM)
- **Cipher**: AES-256-GCM (FIPS 197) with 12-byte nonce and 16-byte authentication tag
- **Key derivation**: HKDF-SHA256 with domain-separated info strings
- **Nonce**: 12-byte random nonce per encryption (prevents identical-plaintext attacks)
- **Authentication**: GCM authentication tag on every ciphertext (detects tampering)
- **Format**: `nonce (12B) || ciphertext || GCM-tag (16B)`

### CoffeeCipher v3 Format
- **Structure**: `nonce(12B) || ciphertext || GCM-tag(16B)`
- **Nonce**: Fresh random 12-byte nonce generated per encryption via `secrets` module
- **Key derivation**: HKDF-SHA256 with domain-separated info strings
- **Authentication**: GCM tag appended to ciphertext for integrity verification
- **Decryption**: GCM tag verified before decryption; tampered ciphertext is rejected
- **Backward compatibility**: Reads v1 and v2 Coffee Blend Cipher messages transparently

### End-to-End Encryption (E2EE)
- **Classical hybrid**: ECDH P-256 (FIPS 186-4) + RSA-KEM-2048 hybrid KEM
- **Post-quantum hybrid**: ECDH P-256 (FIPS 186-4) + 1nf1D3L Kyber (Non-FIPS ML-KEM-768 variant)
- **Key derivation**: HKDF-SHA256 from combined shared secrets
- **Hybrid guarantee**: Secure if EITHER classical OR PQ component holds

### 1nf1D3L's Kyber (Non-FIPS Post-Quantum KEM)
- **Variant**: ML-KEM-768 with 1nf1D3L modifications (η=3, custom domain tags, NTT perturbation)
- **Parameters**: n=256, k=3, q=3329, η₁=3, η₂=3, du=10, dv=4
- **Domain separation**: "1NF1D3L-KYBER-V1" on all hash/KDF inputs
- **NTT twiddle perturbation**: Per-session random twiddle factors for side-channel resistance
- **Coffee recipe binding**: Recipe string (espresso, cappuccino, etc.) mixed into KDF
- **Key confirmation**: Re-encapsulation check (implicit rejection via KDF with z)
- **Sizes**: PK=1184B, SK=2400B, CT=1120B, SS=32B
- **Hybrid (ECDH+Kyber)**: PK≈1251B, SK≈2432B, CT≈1187B, SS=32B

### RSA-KEM-2048 (Key Encapsulation)

The RSA-KEM implementation in CPIP uses FIPS-compliant primitives:

- **Key generation**: 2048-bit RSA keys (FIPS 186-4)
- **Encapsulation**: RSA-KEM with OAEP padding (SP 800-56B)
- **Key derivation**: HKDF-SHA256 from RSA-KEM shared secret
- **Security basis**: RSA-OAEP with SHA-256 — FIPS 186-4 / SP 800-56B compliant

### Signatures
- **Classical**: ECDSA P-256 (FIPS 186-4) via `cryptography` library — constant-time
- **Key exchange**: ECDH P-256 (FIPS 186-4) via `cryptography` library — constant-time
- **Mesh message authentication**: HMAC-SHA256 domain-separated tags

### Hash Functions
- **Primary**: SHA-256 (key derivation, identity, HMAC)
- **Node identity**: SHA-256 (replaces MD5)
- **Audit log**: SHA-256 with tamper-evident chaining

### Message Security
- **Timestamp validation**: Mesh messages rejected if >300 seconds old (replay protection)
- **HMAC authentication**: Heartbeat and control messages HMAC-signed
- **Cover traffic**: Randomized padding to defeat traffic analysis

### Data at Rest
- **Persistence**: Encrypted with CoffeeCipher v3 (AES-256-GCM) + HMAC integrity verification
- **Key material**: Derived from node secret with HKDF domain separation
- **Plaintext**: Purged from message store after re-encryption
- **Format**: v3 encrypted persistence format; v1/v2 data loads with backward-compatible
  migration path (v1/v2 is transparently upgraded on next write)

## Network Security

- **TLS/SSL**: Built-in HTTPS support with auto-generated self-signed certificates or custom certs. HTTP→HTTPS redirect available.
- **HSTS**: `Strict-Transport-Security: max-age=31536000; includeSubDomains` header when SSL is active
- **HTTP rate limiting**: 100 requests per 60 seconds per IP address
- **Request size limit**: 64 KB maximum request body
- **Security headers**:
  - `Content-Security-Policy` (CSP)
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `X-XSS-Protection: 1; mode=block`
  - `Referrer-Policy: no-referrer`
- **CORS**: Configurable per-deployment; not permissive by default

## Signal Awareness

- **Bandwidth estimation**: Continuous measurement of available link bandwidth
- **Per-peer link quality**: Each peer connection tracked with quality metrics
- **Jamming detection**: Anomalous signal patterns trigger alerts and auto-mitigation

## Defense Policy & Runtime Controls

CPIP exposes four independently configurable defense policy groups. Every vector
within a group defaults to **enabled** and can be toggled at runtime **without a
restart** — useful for threat-responsive hardening (e.g. disable a transport that
is being fingerprinted, or stop a scan loop under active jamming).

| Policy group | Endpoint | Vectors |
|--------------|----------|---------|
| **Anti-ISP** | `POST /cpip/anti-isp` | STUN hole-punch, UPnP mapping, mesh relay, DNS tunnel, WSS relay, DoH |
| **Anti-Stingray** | `POST /cpip/anti-stingray` | master switch, cellular MCC/MNC scan, RF anomaly scan, signal-anomaly scan, known-signature scan |
| **Anti-Surveillance** | `POST /cpip/anti-surveillance` | master switch, DPI evasion, traffic obfuscation, metadata strip, exploit-kit detection, process-injection detection |
| **Net-Neutrality** | `POST /cpip/net-neutrality` | master switch, bandwidth monitor, protocol masquerade, fragmentation, throttle detect, jitter injection |

**Runtime toggle controls**

- `POST /cpip/anti-isp` with `{"action":"toggle","feature":"stun","enabled":false}`
- `POST /cpip/anti-stingray` with `{"action":"toggle","feature":"cell_scan","enabled":false}`
- `POST /cpip/anti-surveillance` with `{"action":"toggle","feature":"dpi_evasion","enabled":false}`
- `POST /cpip/net-neutrality` with `{"action":"toggle","feature":"fragmentation","enabled":false}`
- `POST /cpip/anti-stingray {"action":"rescan"}` / `POST /cpip/anti-surveillance {"action":"scan"}` force an immediate pass
- `GET /cpip/config` returns the live `policies` block for all four groups
- `PUT /cpip/config` with `{"policies":{...}}` bulk-updates policies at runtime

Unknown feature names return HTTP `400`. Toggling `enabled` / `master` on the
Anti-Stingray, Anti-Surveillance, or Net-Neutrality groups starts or stops the
background scan/reaction loop.

**Operational guidance**

- Disabling a vector weakens a specific defense; only disable what is unnecessary
  for your deployment (e.g. `known_signatures` on a non-cellular link).
- The master `enabled` flag for each group gates all sub-vectors; turning the
  master off stops background loops and halts associated processing.
- Runtime changes are **not** persisted across restarts — set the corresponding
  `CPIP_*` environment variable (see README "Environment Variables") for a
  permanent policy. Authorize `/cpip/config` and the `*/toggle` endpoints behind
  your own network controls; they are unauthenticated by default.

## Threat Model

CPIP is designed for operation in hostile signal environments:

| Threat | Mitigation |
|--------|-----------|
| Passive eavesdropping | E2EE with AES-256-GCM + HMAC authentication |
| Message tampering | HMAC-SHA256 / GCM authentication tags |
| Replay attacks | Timestamp validation (300s window) |
| Traffic analysis | Random padding + cover traffic |
| Identity spoofing | ECDSA P-256 signatures + HMAC mesh auth |
| Key compromise | Emergency key rotation + secure wipe |
| Network scanning | 418 I'm a Teapot defense + port knocking |
| Jamming detection | Signal awareness + incident response |
| Insider threat | Encrypted persistence + audit chain |

## What CPIP Is For

- Raspberry Pi mesh networks in contested or degraded signal spaces
- Emergency communications where internet infrastructure is unavailable
- Covert mesh communications under casual inspection
- Post-disaster / field operations communications
- Systems administration multi-tool for hostile network environments

## What CPIP Is NOT Designed For

- FIPS 140-2/3 validation (uses FIPS-compliant algorithms but is not itself a validated module)
- Protecting classified/sensitive information requiring formal certification
- Environments requiring hardware security modules (HSMs)

## Incident Response

CPIP includes an automated incident response system with severity-based alerts:

- **Alert system**: Automated alerts classified by severity level (low, medium, high, critical)
- **Signal anomaly detection**: Detects jamming, signal loss, and flooding
- **Auto-mitigation actions**:
  - **Stealth mode**: Automatically activated on jamming detection (high-severity signal anomalies)
  - **Blacklisting**: Automatic IP blacklisting on brute-force attempts
- **Emergency mode**: Key rotation, peer notification, stealth activation
- **Audit trail**: Tamper-evident SHA-256 chained audit log
- **Secure wipe**: Overwrites key material in memory

## Emergency Mode

Emergency mode provides instant response to active threats:

- **Key rotation**: Immediate rotation of all cryptographic keys
- **Stealth activation**: Instant transition to covert operation mode
- **Peer notification**: Alerts connected peers to enter emergency state
- **Secure memory wipe**: Overwrites all in-memory key material before release

### Emergency Procedures (API)

1. **Key rotation**: `POST /cpip/emergency {"action": "rotate_keys"}`
2. **Emergency activate**: `POST /cpip/emergency {"action": "activate", "reason": "..."}`
3. **Secure wipe**: `POST /cpip/emergency {"action": "wipe"}`
4. **Deactivate**: `POST /cpip/emergency {"action": "deactivate"}`

## Network Diagnostics

CPIP includes built-in network diagnostic tools:

- **TCP/UDP ping**: Connectivity testing to arbitrary hosts/ports
- **Port scanning**: Remote port enumeration for network assessment
- **DNS resolution**: Forward and reverse DNS lookups
- **Traceroute**: Network path discovery
- **Interface listing**: Local network interface enumeration

## Reporting a Vulnerability

1. **Do not** open a public GitHub issue for critical vulnerabilities
2. Open a standard issue for non-critical bugs
3. For serious issues, contact the repository owner directly via GitHub

## Responsible Use

- The covert channel key **default is now empty** (no insecure default); it must be
  explicitly set via the `CPIP_COVERT_KEY` environment variable before use
- Radio transport defaults to `lora` — simulation mode requires the explicit `--sim` flag
- Use emergency key rotation if a key may have been compromised
- Monitor incident response alerts for signs of hostile activity
- Understand that classical cryptographic operations use FIPS-compliant primitives
  via the `cryptography` library (constant-time ECDSA/ECDH P-256, AES-256-GCM,
  RSA-KEM-2048)
- **1nf1D3L's Kyber is NOT FIPS 203 validated** — it is a Non-FIPS ML-KEM-768 variant
  with wider noise (η=3), custom domain tags, and NTT perturbation. Use for research,
  red-teaming, coffee protocols, and survival — not for FIPS-required deployments.