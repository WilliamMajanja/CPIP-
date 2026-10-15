# RFF-0003: Explainable Threat Assessment and Verifiable Evidence

| Field | Value |
|-------|-------|
| Status | Proposed |
| Component | `providers/cellular.py`, `providers/scorer.py`, `providers/threat_intel.py`, `providers/evidence.py` |
| Related | RFC-0029, RFC-0030, RFC-0031, RFC-0032 |
| Version Target | v7.0.0 |

## User need

Operators need to understand why a threat score changed, how reliable its sensor inputs are, whether a community report was actually received, and whether stored evidence has changed since capture.

## Desired outcome

- Detections retain their source, timestamp, confidence, and data-quality limitations.
- Correlated signals affect the score in a documented and reproducible way.
- Sharing is explicit opt-in and distinguishes locally observed events from authenticated peer reports.
- Evidence records survive restart and can be verified locally; external timestamping reports actual submission/verification state.

## Acceptance criteria

1. Fixture-driven tests cover cellular anomalies, baseline reset/retention, score explanation, and confidence bounds.
2. No single ambiguous measurement is described as a confirmed surveillance event.
3. Threat reports include authentication, freshness, deduplication, retention, and opt-in checks.
4. Evidence-chain tests detect edits, removal, insertion, and broken links after restart.
5. Failed or unsupported external notarization is reported as failed/unsupported, never “notarized”.
