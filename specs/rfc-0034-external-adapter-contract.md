# RFC-0034: External Service Integration Adapter Contract

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/carrier.py`, `providers/modem.py`, `providers/ss7_monitor.py`, `providers/ai_assessor.py` |
| Related | RFC-0005, RFC-0013, RFC-0014, RFC-0018, RFC-0027, RFF-0001 |
| Version Target | v7.0.0 |

## Abstract

Standardize configuration, authentication, timeout, privacy, and failure behavior for optional external integrations without pretending that carrier, NVD, SigFW, or AI services are available by default.

## Design

- Each adapter declares required endpoint, credentials, scopes, network use, sent data, and supported operations.
- Secrets come from environment/secret storage, never provider status or logs. Requests use TLS certificate validation, bounded timeouts, response-size limits, and redacted logs.
- Webhooks validate a configured signature/HMAC and timestamp, reject replay, and cap body size before parsing.
- Carrier actions are advisory only until an authenticated carrier API explicitly confirms an operation. No automatic SIM change, port freeze, or key rotation is implied by a locally received unsigned event.
- SS7/PCAP analysis is read-only by default. AI/cloud assessment is off by default and discloses exactly which threat fields are sent.
- NVD queries are cached and rate-limited; results are labelled advisory and do not establish firmware integrity.

## API Changes

Provider status reports configured endpoints by service name, never credential values. Webhook responses distinguish accepted, rejected, and unavailable integration states.

## Acceptance Criteria

- Fake local endpoints test valid/invalid signatures, replay, TLS errors, timeouts, oversized responses, and secret redaction.
- No tests require vendor accounts, public internet, real subscriber data, or third-party keys.
- No external integration reports an action completed without a verifiable positive response from that service.
