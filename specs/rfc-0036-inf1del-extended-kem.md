# RFC-0036: Experimental 1nf1D3L Extended-Rank KEMs

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `inf1del_kyber.py`, `pure_mlkem.py`, `server.py`, `providers/kem.py`, `b4dm4n_cw.py` |
| Related | RFC-0003, RFC-0019, RFC-0027, RFF-0002 |
| Version Target | v7.0.0 |

## Abstract

Specify the project-local experimental 1nf1D3L-2048 and 1nf1D3L-4096 KEM parameter sets and expose them through both bundled backends. Their names are project identifiers, not NIST ML-KEM security levels or claims of 2048-/4096-bit security.

## Parameter Sets

Both variants use `n=256`, `q=3329`, `eta1=3`, `eta2=2`, the `1NF1D3L-KYBER-V1` domain tag, and the existing 32-byte ciphertext suffix. The wider module ranks are experimental and require independent cryptanalysis before security claims are made.

| Identifier | k | du | dv | Public key | Secret key | Ciphertext | Shared secret |
|------------|---:|---:|---:|---:|---:|---:|---:|
| `1nf1d3l_kem_2048` | 8 | 12 | 5 | 3104 B | 6240 B | 3264 B | 32 B |
| `1nf1d3l_kem_4096` | 16 | 13 | 5 | 6176 B | 12384 B | 6848 B | 32 B |

## Design

- Keep standardized identifiers `ml_kem_512`, `ml_kem_768`, and `ml_kem_1024` unchanged.
- Use the explicit `1nf1d3l_kem_2048` and `1nf1d3l_kem_4096` names in APIs, provider registry, CLI, and serialized negotiation.
- Support the same parameter sets in the NumPy-accelerated implementation and the standard-library-only implementation.
- `CPIP_ML_KEM_BACKEND=stdlib` forces the dependency-free backend; `auto` may choose an installed accelerated backend and falls back to stdlib. `pqcrypto` is not a backend for the extended sizes.
- Any hybrid exchange carries an algorithm identifier and rejects unknown or mismatched identifiers; it must not silently negotiate a different size.

## API and CLI Changes

- `GET /cpip/crypto/pqc-status` reports standard and experimental sizes separately, the selected identifier, backend, and parameter sizes.
- Provider identifiers: `1nf1d3l_kem_2048` and `1nf1d3l_kem_4096`.
- Workbench CLI accepts `-a 1nf1d3l-kem-2048` and `-a 1nf1d3l-kem-4096` for key generation, encapsulation, and decapsulation.

## Security Considerations

- The values “2048” and “4096” are labels for these project parameter sets; they do not indicate classical-equivalent security bits.
- The construction is custom, non-FIPS, not wire-compatible with FIPS 203, and not constant-time in Python.
- Extended variants remain experimental and are not recommended for production or regulated use until independently reviewed.
- Tests establish implementation consistency and tamper behavior only; they do not establish cryptographic security.

## Acceptance Criteria

- Both backends pass key-size, round-trip, wrong-key, tamper, and recipe-separation tests for both extended variants.
- A standard-library-only process can run key generation, encapsulation, and decapsulation for both variants.
- CLI/API names distinguish these custom variants from standardized ML-KEM identifiers.
- Benchmark output and status report runtime and memory costs without translating rank into a security-level claim.
