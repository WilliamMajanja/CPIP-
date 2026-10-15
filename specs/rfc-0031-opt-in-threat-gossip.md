# RFC-0031: Opt-in Mesh Threat-Report Gossip

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/threat_intel.py`, `providers/mesh_security.py`, `server.py` |
| Related | RFC-0007, RFC-0021, RFC-0026, RFC-0028, RFF-0003 |
| Version Target | v7.0.0 |

## Abstract

Deliver authenticated, privacy-minimized threat reports over the existing E2EE mesh when an operator explicitly enables sharing. This is a bounded gossip protocol, not a public DHT.

## Report Schema

Reports contain a version, random report ID, coarse timestamp, threat category, confidence, optional salted cell hash, and expiry. Exact GPS, SUPI/IMSI, phone numbers, device serials, and raw sensor traces are excluded by default.

## Design

- Sharing is disabled by default and can be enabled/disabled at runtime; disable stops future export immediately.
- Reports are signed by the sending node identity, transported as E2EE mesh messages, deduplicated, freshness checked, and TTL limited.
- Local observations and peer reports remain separately attributable in status and scoring.
- Community quorum counts unique authenticated peers, not distinct coordinates or repeated reports from one peer.
- No report is treated as verified solely because a peer submitted it; trust and evidence source are visible.

## API/CLI Changes

Add report ingest/export status and recent-report endpoints. `cpip intel share on|off` controls only sharing; map/risk queries identify whether data is local or peer supplied.

## Acceptance Criteria

- Tests cover opt-in default, revocation, signature failure, replay, expiry, duplicate reports, peer quorum, and PII omission.
- Network transport tests use a local deterministic mesh fixture; no public DHT or third-party API is required.
