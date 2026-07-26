# RFC-0006: ML-Driven Anomaly Scoring Engine

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/scorer.py` |
| Related | RFC-0001, RFC-0002, RFC-0005, RFC-0009, RFC-0016 |
| Version Target | v6.0.0 |

## Abstract

Bayesian multi-heuristic anomaly scorer with temporal correlation,
historical baseline learning, and context-aware thresholds.

## Motivation

Individual detection heuristics produce false positives in isolation.
The ML scorer correlates signals across all detection providers to
produce a calibrated confidence score.

## Design

- Aggregates signals from all detection providers
- Each signal produces heuristic confidence (0.0-1.0)
- Temporal correlator: signal pairs within time window get synergy bonus
- Context-aware softening per environment (urban vs rural)
- Historical baseline: 7-day per-cell signal ranges
- IsolationForest optional for unsupervised anomaly detection
- Output: combined score 0.0-1.0 mapped to THREAT_NONE..CRITICAL

## CLI Changes

```
cpip assess status
cpip assess explain
cpip assess baselines
cpip assess history
```

## Env Variables

```
CPIP_CELL_ML_SCORING=1
CPIP_SCORER_MODE=heuristic|ml|hybrid
CPIP_SCORER_TEMPORAL_WINDOW=60
CPIP_SCORER_PAIR_BONUS=0.25
CPIP_SCORER_BASELINE_DAYS=7
```

## Limitations

- Requires data from multiple providers for effective correlation
- IsolationForest requires ~1000+ samples for training
