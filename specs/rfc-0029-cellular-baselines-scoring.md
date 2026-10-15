# RFC-0029: Cellular Baselines and Explainable Scoring

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/cellular.py`, `providers/scorer.py`, `providers/ai_assessor.py` |
| Related | RFC-0001, RFC-0006, RFC-0009, RFC-0016, RFF-0003 |
| Version Target | v7.0.0 |

## Abstract

Make cellular observations source-aware, persist baselines with bounded retention, and explain how measured evidence changes the threat score.

## Design

- Use ModemManager D-Bus when available and an explicitly labelled `mmcli` fallback; expose source and unsupported fields.
- Store normalized observations and baselines with timestamps, RAT, cell/operator identifiers, and signal units. Never mix signal-quality percentages with dBm.
- Retain a configurable rolling history and provide reset/export operations.
- Scoring consumes normalized observations, weights signal quality and source reliability, caps pair-synergy contribution, and returns a human-readable explanation.
- Ambiguous observations (for example, TA=0 alone or ordinary 2G coverage) cannot be labelled a confirmed attack.
- All database paths and retention are configurable; GPS is minimized and is not shared by default.

## API/CLI Changes

Keep `/cpip/cell/status`, `/scan`, `/history`, and `/baseline-reset`; add source diagnostics and retention metadata. Scorer status/explain/history/baselines use the same persisted records.

## Acceptance Criteria

- Fixture tests cover D-Bus variants, mmcli fallback, absent modem, unknown fields, and unit conversion.
- Deterministic tests verify baseline update, retention, reset, score bounds, and explanation output.
- No threat severity is elevated solely by an unsupported or single ambiguous field.
