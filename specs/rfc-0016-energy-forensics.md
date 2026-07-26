# RFC-0016: Energy & Battery Forensics

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/power.py` |
| Related | RFC-0006 |
| Version Target | v6.0.0 |

## Abstract

Monitor current draw to detect anomalous battery drain caused by IMSI
catcher forced re-attach attacks or surveillance firmware.

## Design

- Read current via sysfs iio, battery IC (BQ25601, MAX17332), INA219
- Baseline per network state (idle, 4G, 5G, mesh TX)
- Detect sustained draw above baseline → forced re-attach by fake tower
- Correlate drain anomalies with cell tower changes → ML score bonus
- Alert: 2x baseline drain for >10min

## CLI

```
cpip power status
cpip power log [minutes]
cpip power baseline reset
```

## Env

```
CPIP_POWER_MONITOR=1
CPIP_POWER_I2C_ADDR=0x40
CPIP_POWER_DRAIN_THRESHOLD=2.0
```
