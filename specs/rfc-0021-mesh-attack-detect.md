# RFC-0021: Mesh Network Attack Detection

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/mesh_security.py` |
| Related | RFC-0007 |
| Version Target | v6.0.0 |

## Abstract

Detect Sybil, eclipse, partition, and replay attacks against the CPIP mesh.

## Design

- Sybil: track peers per /24; flag >5 from same /24. Track uptime vs age
- Eclipse: flag if >80% peers share same upstream IP or introducer
- Partition: periodic graph exchange; detect isolation inconsistencies
- Replay: monotonic nonce per sender; reject seen or future-dated ones
- Disappearance: trusted peer with >48h uptime stops heartbeating (HIGH)

## CLI

```
cpip mesh attack-detect status
cpip mesh attack-detect graph
cpip mesh attack-detect peers
```

## Env

```
CPIP_MESH_ATTACK_DETECT=1
CPIP_MESH_SYBIL_THRESHOLD=5
CPIP_MESH_ECLIPSE_THRESHOLD=0.8
CPIP_MESH_DISAPPEAR_HOURS=48
```
