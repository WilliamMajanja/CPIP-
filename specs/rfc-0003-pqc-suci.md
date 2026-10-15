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
CPIP_PQC_KEM=ml_kem_512|ml_kem_768|ml_kem_1024|1nf1d3l_kem_2048|1nf1d3l_kem_4096 (default: ml_kem_768)
CPIP_ML_KEM_BACKEND=auto|stdlib|numpy|pqcrypto (stdlib has no third-party KEM dependency)
```

## Security Considerations

- Standardized FIPS 203 ML-KEM-1024 targets NIST level 5; do not assign that level to the custom 1nf1D3L implementation.
- Hybrid mode (ECDH + Kyber) protects against cryptanalytic breakthroughs
  in both classical and quantum cryptanalysis
- Standard parameter-size options are 512/768/1024. Experimental custom 1nf1D3L ranks 2048/4096 use separate algorithm IDs and are not security-level claims.
- The bundled implementation is non-FIPS and not wire-compatible with FIPS 203 ciphertexts.

## Limitations

- The standard-library backend has no third-party KEM dependency; the accelerated backend requires NumPy, and the optional standardized backend requires `pqcrypto`.
- Larger key exchange messages increase mesh handshake size
- Not all peers may support PQ — fallback to ECDH required
