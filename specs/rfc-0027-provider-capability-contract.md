# RFC-0027: Provider Capability and Lifecycle Contract

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/base.py`, `providers/registry.py`, `providers/register_v6.py`, `providers/rfc_api.py`, UI clients |
| Related | RFF-0001 |
| Version Target | v7.0.0 |

## Abstract

Define common provider capability, lifecycle, and error semantics for core and optional integrations so every interface can report truthful runtime state.

## Design

Provider status records contain stable fields: `name`, `version`, `implemented`, `configured`, `available`, `enabled`, `running`, `limitations`, and `last_error`. Boolean state must not be inferred from a class being registered. Optional dependencies are probed without opening transmit-capable devices or contacting remote services.

Providers with background work implement idempotent `start()` and `stop()`. Server shutdown invokes `stop()` and joins bounded worker threads. Registry startup isolates provider failures and records them in status rather than swallowing them.

## API Changes

- `GET /cpip/providers` returns schema version and records for every provider.
- Provider-specific status endpoints use the same fields and JSON error envelope.
- Unsupported operation: HTTP 501; not configured/available: HTTP 503; invalid request: HTTP 400; unexpected failure: HTTP 500.

## CLI and Dashboard Changes

CLI provider commands and TUI/dashboard status views consume the shared status schema. Help text omits nonexistent commands. UI labels distinguish unavailable, disabled, and active states.

## Security Considerations

Capability probes must be read-only. Secrets, private keys, modem identifiers, and raw sensor data are excluded from general provider status.

## Acceptance Criteria

- Unit tests cover every lifecycle state and repeated start/stop.
- A broken optional provider does not prevent core server startup.
- No unsupported operation returns HTTP 2xx or claims completion.
