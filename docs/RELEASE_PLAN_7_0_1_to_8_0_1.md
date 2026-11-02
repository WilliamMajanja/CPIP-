# CPIP Release Plan: v7.0.1 → v8.0.1

**Status:** Planning  
**Author:** CPIP Core Team  
**Last Updated:** 2026-11-02  

## Philosophy
- **Pragmatic over perfect:** Ship small, testable increments
- **Security-first:** Leverage custom KEMs (1nf1d3l extended ranks) and SLH-DSA safely
- **Zero-dependency friendly:** Prefer stdlib; optional deps clearly marked
- **Backward compatible:** Don't break existing mesh/HTCPCP behavior
- **Methodical:** Each patch has tests, docs, and rollback path

## Current State
- **Version:** 7.0.0
- **Custom Crypto:** Inf1delKyber (512/768/1024/2048/4096), Inf1delSLH (all 12 SLH-DSA variants), hybrid KEM support
- **Backends:** inf1del (NumPy), stdlib (pure_mlkem), pqcrypto (optional)
- **Mesh:** Basic E2EE, multi-transport, store-and-forward
- **Defense:** ITF, anti-surveillance vectors

---

## Release Timeline

### v7.0.1 - "Harden" (Patch) - Immediate
- CodeQL hardening, secure file perms, logging redaction

### v7.0.2 - "Polish" (Patch) - +1-2 days
- CLI improvements, JSON output, better errors

### v7.0.3 - "Bundle" (Patch) - +2-3 days
- kem_bundle.py, bundle commands in b4dm4n_cw

### v7.1.0 - "Sign" (Minor) - +3-5 days
- SLH-DSA provider integration, dual-signing

### v7.1.1 - "Airgap" (Patch) - +5-6 days
- qr_airgap.py, airgap encode/decode

### v7.2.0 - "Ratchet" (Minor) - +6-9 days
- pq_ratchet.py foundation (opt-in)

### v7.2.1 - "HardenRatchet" (Patch) - +9-10 days
- Ratchet hardening

### v7.3.0 - "Identity" (Minor) - +10-12 days
- slh_identity.py, dual-signed identities

### v7.3.1 - "Attest" (Patch) - +12-13 days
- Attestation format

### v7.4.0 - "Gossip" (Minor) - +13-15 days
- Opt-in threat gossip

### v7.4.1 - "Evidence" (Patch) - +15-16 days
- Evidence chain enhancements

### v7.5.0 - "Forge" (Minor) - +16-18 days
- kem_forge.py, unified API

### v7.5.1 - "Tune" (Patch) - +18-19 days
- Performance tuning

### v7.6.0 - "QuantumMesh" (Minor) - +19-22 days
- PQ ratchet mesh adapter (opt-in)

### v7.6.1 - "Guard" (Patch) - +22-23 days
- Security review

### v7.7.0 - "Interop" (Minor) - +23-25 days
- Interop improvements

### v7.7.1 - "Docs" (Patch) - +25-26 days
- Documentation pass

### v7.8.0 - "Fortify" (Minor) - +26-28 days
- Advanced hardening

### v7.8.1 - "Polish" (Patch) - +28-29 days
- Polish

### v7.9.0 - "Omega" (Minor) - +29-31 days
- Feature complete

### v7.9.1 - "RC" (Patch) - +31-32 days
- Release candidate

### v8.0.0 - "FORTRESS" (Major) - +32-35 days
- Major release

### v8.0.1 - "Stabilize" (Patch) - +35-36 days
- Post-release

## Implementation Guidelines
- Zero deps by default, extras optional
- Domain separation for all crypto
- Never log secrets; redact outputs
- Secure permissions (0600) for private keys
- Opt-in for experimental/risky features
- Backward compatible
- Tests required for new features

## Quick Wins
1. kem-list in b4dm4n_cw
2. kem_bundle.py + bundle commands
3. SLH-DSA CLI polish
4. qr_airgap.py text-mode
5. Unified KEM API

## Notes
- Extended-rank KEMs (2048/4096) experimental with warnings
- PQ ratchet/gossip off by default
- RF transmission never auto-enabled
