# RFC-0003: PQC-SUCI — Quantum-Resistant Subscriber Identity

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `server.py` (Crypto), `providers/kem.py` |
| Related | RFC-0019 |
| Version Target | v6.0.0 |

## Abstract

Replace ECIES (P-256/X25519) with Kyber-768/1024 for CPIP node identity
concealment, preventing harvest-now-decrypt-later attacks on subscriber
identities.

## Motivation

The current CPIP identity exchange uses ECDH P-256 (secp256r1), which is
vulnerable to quantum cryptanalysis via Shor's algorithm. An adversary who
records encrypted identity exchanges today can decrypt them retroactively
once a sufficiently large quantum computer exists. PQC-SUCI migrates to
Kyber (ML-KEM), the NIST-selected KEM standard, for forward-secure identity
concealment.

## Design

- Hybrid identity exchange: ECDH + Kyber-768 (mode 1), Kyber-only (mode 2)
- CPIP_SUPI → CPIP_SUCI: encrypt node identity with Kyber public key of
  the home node (or mesh bootstrap node)
- Only home-node Kyber private key can decrypt → identity never in cleartext
- Ephemeral Kyber key per registration → unlinkable
- Backward compat: ECDH-only mode for pre-v6 peers
- Integration with existing CoffeeCipher/KEM registry in `server.py`

## API Changes

```
GET  /cpip/crypto/pqc-status    — PQ cipher suite info
POST /cpip/crypto/pqc-keys      — generate/rotate PQ keys
POST /cpip/crypto/pqc-handshake — test PQ handshake with peer
```

## CLI Changes

```
cpip crypto pqc-status
cpip crypto pqc-keys
cpip crypto pqc-rotate
cpip crypto pqc-handshake <peer>
```

## Env Variables

```
CPIP_PQC_IDENTITY=0|1|hybrid    (default: hybrid)
CPIP_PQC_KEM=kyber768|kyber1024|hqc192
```

## Security Considerations

- Kyber-1024 targets NIST security level 5 (highest)
- Hybrid mode (ECDH + Kyber) protects against cryptanalytic breakthroughs
  in both classical and quantum cryptanalysis
- PQ key sizes are larger (Kyber PK=1184B, SK=2400B, CT=1088B for ML-KEM-768)

## Limitations

- Requires `pqcrypto >= 0.6.0` with Kyber/ML-KEM support
- Larger key exchange messages increase mesh handshake size
- Not all peers may support PQ — fallback to ECDH required
