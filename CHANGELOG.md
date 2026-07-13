# Changelog

All notable changes to CPIP are documented here.

## [3.0.0] — 2026-07-13

### Added
- **ML-KEM-768 (Kyber768) post-quantum key exchange** — real lattice-based KEM verified correct (200+ round-trips), suitable for in-situ encrypted mesh communications
- **Side-channel hardening** — constant-time ciphertext comparison (`hmac.compare_digest`) in Fujisaki-Okamoto decapsulation, arithmetic masking in compression
- **`kyber.py`** — complete pure-Python ML-KEM-768 implementation: NTT, CBD, Fujisaki-Okamoto CCA transform, AES-256-CTR, combined encrypt/decrypt
- **E2EE using Kyber768 + AES-256-CTR** — primary encryption path for mesh messages (Ed25519 ECDH fallback)
- **GitHub issue templates** — bug report, feature request, security vulnerability
- **GitHub PR template** — includes crypto verification checklist
- **FUNDING.yml** — Buy Me A Coffee link
- **`.github/SECURITY.md`** — directs to main SECURITY.md
- **KEM tests** — keygen, encaps/decaps, 50-round stress test, wrong-key, encrypt/decrypt, constant-time verification

### Changed
- **SECURITY.md** — rewritten: KEM verified correct, side-channel hardening documented, responsible use updated
- **README.md** — added 5 GitHub badges, "Why post-quantum?" section, updated crypto notes, version bumped
- **CONTRIBUTING.md** — side-channel hardening PRs now welcome
- **`kyber.py` docstring** — updated from "no side-channel protections" to "side-channel hardened"
- **`server.py`** — module docstring updated, Kyber import now runs KEM self-test at startup
- **`deploy.sh`** — crypto banner updated ("side-channel hardened pure Python")
- **`htcpcp` CLI** — version bumped to v2.3, ML-KEM-768 branding
- **`htcpcp.1` man page** — updated BUGS section
- **`pi-apps/description`** — updated to mention post-quantum encrypted comms
- **`Dockerfile`** — added `kyber.py` to COPY, version bumped to 3.0.0
- **CI workflow** — added `kyber.py` syntax check and KEM round-trip test step

### Fixed
- **`_sample_ntt_poly`** — XOF called once per polynomial with correct row/column indices; 3-byte pair parsing per FIPS 203
- **`_bit_unpack`** — bounds check prevents IndexError when unpacking compressed data
- **NTT/invNTT** — correct zeta table computation (`pow(17, bitrev_7(k), Q)`), pair-wise multiplication with `_ZETA_PAIRS`, `128^{-1}` scale factor
- **CBD** — Hamming-weight counting (`a += bit`) instead of binary OR
- **Encapsulation/decapsulation** — compress `u` in time domain (invNTT before compress, NTT after decompress)
- **Message decoding** — uses `Compress(m_poly[i], 1)` per FIPS 203 instead of threshold comparison
- **Matrix transpose** — `A_hat[j][i]` in both encaps and decaps (A^T, not A)
- **`sk_bytes()`** — returns correct 2368 instead of 2400
- **Radio C warning** — `cfg->spi_device && cfg->spi_device[0]` → `cfg->spi_device[0]`

### Breaking
- Version bumped from 2.x to 3.0.0 (new KEM is a fundamental protocol change)
- Secret key format changed (Kyber768 secret key now 2368 bytes)
- Ciphertext format changed (ML-KEM-768: 1088 bytes)