# RFC-0022: Blockchain Evidence Notarization

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/evidence.py` |
| Related | RFC-0002, RFC-0001 |
| Version Target | v6.0.0 |

## Abstract

Timestamp SHA-256 hashes of forensic evidence on public blockchains for
tamper-evident chain of custody.

## Design

- On evidence capture, compute SHA-256 hash
- Merkle chain of hashes in local DB
- Submit chain root hash to: Bitcoin OP_RETURN, Ethereum, Stellar, or OTS
- Verification: recompute hash from archive, check blockchain timestamp
- Each entry signed with dedicated evidence key

## CLI

```
cpip evidence notarize <id>
cpip evidence verify <id>
cpip evidence notarize-all
cpip evidence chain
```

## Env

```
CPIP_EVIDENCE_NOTARIZE=0
CPIP_EVIDENCE_CHAIN=bitcoin|ethereum|stellar|ots
CPIP_EVIDENCE_BTC_API_KEY=
CPIP_EVIDENCE_ETH_RPC_URL=
CPIP_EVIDENCE_STELLAR_SECRET=
```
