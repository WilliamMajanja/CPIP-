# RFC-0007: Multi-Node Mesh Detection Grid

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/mesh.py`, `providers/threat_intel.py` |
| Related | RFC-0001, RFC-0006, RFC-0026 |
| Version Target | v6.0.0 |

## Abstract

Distributed IMSI catcher detection and triangulation across CPIP mesh peers.

## Motivation

A single node's cellular scan cannot confirm whether a detected cell is a
threat. Multiple nodes at different locations reporting the same rogue cell
dramatically increases confidence and enables physical triangulation.

## Design

- E2EE gossip message type: "threat_intel"
- Payload: cell_id, mcc, mnc, lac, signal, timestamp, gps
- Triangulation: 3+ peers compute IMSI catcher location via multilateration
- Collective scoring: confidence increases with reporting peer count
- Opt-in sharing via CPIP_THREAT_SHARING

## CLI Changes

```
cpip mesh threat-report
cpip mesh intel-status
cpip intel map
```

## Env Variables

```
CPIP_THREAT_SHARING=0
CPIP_THREAT_REQUIRE_PEERS=3
CPIP_THREAT_GOSSIP_INTERVAL=60
```

## Limitations

- Requires 3+ participating nodes for triangulation
- RSSI-based distance has ±50% error in urban environments
