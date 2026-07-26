# RFC-0010: Tactical Field Operations Mode

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/field_ops.py`, `server.py` |
| Related | RFC-0007 |
| Version Target | v6.0.0 |

## Abstract

Radio silence mode, dead-man switch, geofenced auto-defense, and
coordinated mesh-wide sweep scheduling.

## Design

- Radio silence: suppress all CPIP RF transmits for configurable period
- Dead-man switch: auto-wipe + deception mode on missing re-arm
- Geofence: GPX/KML polygon triggers profile change on boundary crossing
- Coordinated sweep: time-synchronized multi-node band scan

## CLI Changes

```
cpip field radio-silence [duration]
cpip field deadman set [timeout]
cpip field deadman arm|disarm
cpip field geofence load <file.gpx>
cpip field plan-sweep [bands]
```

## Env Variables

```
CPIP_FIELD_RADIO_SILENT=0
CPIP_FIELD_DEADMAN_TIMEOUT=86400
CPIP_FIELD_GEOFENCE=/etc/cpip/safe_zone.gpx
```
