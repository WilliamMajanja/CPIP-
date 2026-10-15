# RFF-0001: Truthful Provider Readiness Across Interfaces

| Field | Value |
|-------|-------|
| Status | Proposed |
| Component | `providers/`, `providers/rfc_api.py`, `server.py`, `cpip`, `cpip_tui.py`, `web/` |
| Related | RFC-0027, RFC-0030, RFC-0034, RFC-0035 |
| Version Target | v7.0.0 |

## User need

Operators need to tell whether an integration is implemented, configured, available on this machine, enabled, and actively running. A green status must not mean only that a Python class exists.

## Desired outcome

- The HTTP API exposes one consistent capability record per provider.
- The web dashboard, TUI, and CLI present the same state and any missing dependency or hardware requirement.
- Unsupported actions fail visibly with a non-success HTTP status and actionable explanation.
- Optional integrations do not create threads, open devices, transmit RF, or contact third parties until explicitly enabled.

## Acceptance criteria

1. Every registered provider reports `implemented`, `configured`, `available`, `enabled`, `running`, and `limitations` fields where applicable.
2. Hardware-independent tests can verify unavailable/configured/enabled states without physical devices.
3. Dashboard and TUI show provider states from the same API response schema.
4. The CLI help and API documentation describe only commands/routes that exist.
5. An unavailable provider never returns a successful “sent”, “verified”, or “active” result.

## Out of scope

This request does not implement every proposed physical, carrier, radio, or cloud integration. Those are separately specified and remain unavailable until their adapters pass their RFC acceptance tests.
