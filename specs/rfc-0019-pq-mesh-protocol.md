# RFC-0019: Post-Quantum Mesh Protocol (PQMP)

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/mesh.py`, `server.py` |
| Related | RFC-0003 |
| Version Target | v6.0.0 |

## Abstract

Full PQC for all mesh communication: Kyber-1024 KEM + Falcon-1024/Dilithium-5
signatures for per-message handshake and ratcheting.

## Design

- Handshake: X25519 + Kyber-1024 hybrid ephemeral key exchange
- Signatures: Dilithium-5 for node identity attestation
- Ratchet: double-ratchet using Kyber encapsulation per message
- PQ message format: { kyber_ct, falcon_sig, ciphertext, nonce }
- Backward compat: negotiate PQC vs ECDH; older peers get ECDH fallback

## CLI

```
cpip crypto pq-mesh status
cpip crypto pq-mesh enforce [on|off]
cpip crypto pq-mesh handshake <peer>
```

## Env

```
CPIP_PQ_MESH=0|1|enforce
CPIP_PQ_MESH_KEM=kyber1024
CPIP_PQ_MESH_SIG=dilithium5|falcon1024
```
