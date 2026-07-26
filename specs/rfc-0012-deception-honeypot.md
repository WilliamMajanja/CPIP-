# RFC-0012: Deception & Honeypot Mode

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/deception.py` |
| Related | RFC-0020 |
| Version Target | v6.0.0 |

## Abstract

Emit fake IMSI/IMEI, simulate device profiles, run honeypot mesh nodes,
and inject deceptive traffic to confuse attackers.

## Design

- Fake IMSI-TMSI broadcast via modem to attract IMSI catchers
- Honeypot mesh: 3-5 fake CPIP nodes logging all connection attempts
- Deceptive chaff: realistic-looking message exchanges (not random noise)

## CLI

```
cpip deception status
cpip deception chaff-intensity [low|medium|high]
cpip deception honeypot [enable|disable]
```

## Env

```
CPIP_DECEPTION=0
CPIP_DECEPTION_CHAFF_INTENSITY=medium
CPIP_DECEPTION_HONEYPOT_COUNT=3
```
