# Security Policy

## Cryptographic Architecture

CPIP v2.2+ uses a layered cryptographic architecture designed for hostile
signal environments:

### Encryption (Coffee Blend Cipher v2)
- **Key derivation**: HKDF-SHA256 with domain-separated info strings (replaces MD5)
- **Stream cipher**: SHA-256 counter mode with S-box substitution layer
- **IV/Nonce**: Random 16-byte IV per encryption (prevents identical-plaintext attacks)
- **Authentication**: HMAC-SHA256 authentication tag on every ciphertext (detects tampering)
- **Format**: `IV (16B) || ciphertext || HMAC-SHA256 (32B)`

### CoffeeCipher v2 Format
- **Structure**: `IV(16B) || ciphertext || HMAC-SHA256(32B)`
- **IV**: Fresh random 16-byte IV generated per encryption
- **Key derivation**: HKDF-SHA256 with domain-separated info strings
- **Authentication**: HMAC-SHA256 tag appended to ciphertext for integrity verification
- **Decryption**: HMAC verified before decryption; tampered ciphertext is rejected

### End-to-End Encryption (E2EE)
- **Key agreement**: ECDH (Ed25519) + ML-KEM hybrid KEM
- **Key derivation**: HKDF-SHA256 from combined ECDH + ML-KEM shared secrets
- **Post-quantum security**: ML-KEM provides PQ key agreement via SHA-3-based construction
- **Hybrid guarantee**: Secure if EITHER classical OR post-quantum component holds

### ML-KEM (Post-Quantum Key Encapsulation)

The ML-KEM implementation in CPIP is **not** a true FIPS 203 lattice-based Kyber
implementation. It is a SHA-3-based Fujisaki-Okamoto KEM construction that
provides post-quantum security through hash-based primitives:

- **Public key derivation**: SHA-3-256 hash of the seed (not lattice key generation)
- **Ciphertext**: One-time-pad XOR construction (seed XOR'd with SHA-3-derived pad)
- **IND-CCA2 security**: Fujisaki-Okamoto re-encryption check validates ciphertext integrity
- **Security basis**: Relies on SHA-3 preimage/collision resistance, not lattice hardness
- **Result**: A hash-based PQ KEM — not real Kyber, but honest in its construction

### Signatures
- **Classical**: Ed25519 (Curve25519) — pure Python implementation
  - The `_recover_x` sign bit bug has been **fixed**; ECDH and signatures now work
    correctly end-to-end
  - Still **NOT constant-time** — timing side-channels remain
- **Post-quantum**: ML-KEM encapsulation provides PQ key agreement
- **Mesh message authentication**: HMAC-SHA256 domain-separated tags

### Hash Functions
- **Primary**: SHA-256 (key derivation, identity, HMAC)
- **Secondary**: SHA-3-256 (domain-separated hashing, audit chain)
- **Node identity**: SHA-256 (replaces MD5)
- **Audit log**: SHA-3-256 with tamper-evident chaining

### Message Security
- **Timestamp validation**: Mesh messages rejected if >300 seconds old (replay protection)
- **HMAC authentication**: Heartbeat and control messages HMAC-signed
- **Cover traffic**: Randomized padding to defeat traffic analysis

### Data at Rest
- **Persistence**: Encrypted with CoffeeCipher v2 + HMAC integrity verification
- **Key material**: Derived from node secret with HKDF domain separation
- **Plaintext**: Purged from message store after re-encryption
- **Format**: v2 encrypted persistence format; v1 data loads with backward-compatible
  migration path (v1 is transparently upgraded on next write)

## Network Security

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

## Threat Model

CPIP is designed for operation in hostile signal environments:

| Threat | Mitigation |
|--------|-----------|
| Quantum computing (Shor's) | ML-KEM hybrid KEM (SHA-3-based) |
| Passive eavesdropping | E2EE with HMAC authentication |
| Message tampering | HMAC-SHA256 authentication tags |
| Replay attacks | Timestamp validation (300s window) |
| Traffic analysis | Random padding + cover traffic |
| Identity spoofing | Ed25519 signatures + HMAC mesh auth |
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

- FIPS 140-2/3 compliance (custom cipher construction: SHA-256 + HKDF with HMAC
  authentication — much stronger than the previous MD4-derived stream cipher, but
  still not FIPS-validated)
- Protecting classified/sensitive information requiring compliance
- Production environments requiring constant-time implementations
- The Ed25519 implementation is NOT constant-time (timing side-channels exist)

## Incident Response

CPIP includes an automated incident response system with severity-based alerts:

- **Alert system**: Automated alerts classified by severity level (low, medium, high, critical)
- **Signal anomaly detection**: Detects jamming, signal loss, and flooding
- **Auto-mitigation actions**:
  - **Stealth mode**: Automatically activated on jamming detection (high-severity signal anomalies)
  - **Blacklisting**: Automatic IP blacklisting on brute-force attempts
- **Emergency mode**: Key rotation, peer notification, stealth activation
- **Audit trail**: Tamper-evident SHA-3-256 chained audit log
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
- Understand that the Ed25519 implementation has timing side-channels