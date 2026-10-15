# RFC-0032: Persistent Evidence Chain and Timestamp Verification

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/evidence.py`, `providers/rfc_api.py`, CLI |
| Related | RFC-0011, RFC-0022, RFF-0003 |
| Version Target | v7.0.0 |

## Abstract

Define durable evidence records with canonical serialization, a verifiable append-only hash chain, optional node signatures, and honest OpenTimestamps submission/verification results.

## Design

- Canonicalize each record and bind its ID, timestamp, label, payload digest, and previous chain hash.
- Persist atomically before reporting capture success; recover and validate the chain on startup.
- Protect concurrent append/verify operations. Corruption, gaps, missing files, and unsupported chain providers are explicit errors.
- OpenTimestamps submission is optional. Persist its receipt/proof path and distinguish `submitted`, `confirmed`, `pending`, and `failed`.
- Bitcoin/Ethereum/Stellar submissions remain unsupported until a real transaction client, configuration, and receipt verification are implemented.

## API/CLI Changes

Keep evidence capture/status/chain/notarize/verify operations. Verification returns record integrity, chain integrity, and external timestamp status separately.

## Acceptance Criteria

- Tests cover restart/recovery, concurrent appends, edited/deleted/reordered records, proof unavailable, and invalid proof.
- No command reports `notarized` or `verified` unless local recomputation or the external proof actually passes.
- Evidence export excludes API secrets and private signing keys.
