# RFC-0001: AntiStingray v2 — Multi-Generation Cellular Scan Engine

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/cellular.py`, `server.py` |
| Related | RFC-0006, RFC-0007 |
| Version Target | v6.0.0 |

## Abstract

Upgrade AntiStingray from `mmcli` subprocess to full ModemManager D-Bus API.
Add LTE Timing Advance analysis, 5G NR monitoring, GPS correlation,
signal baseline learning, neighbor consistency checks, intra-LTE band
downgrade detection, and ghost neighbor detection.

## Motivation

The current AntiStingray implementation relies on parsing `mmcli -m 0 -S`
text output, which is fragile, slow, and provides limited data. Modern
ModemManager exposes a rich D-Bus API with structured access to all
cellular parameters including timing advance, 5G NR signal metrics, and
GPS location. v2 leverages this to provide comprehensive multi-generation
cellular threat detection.

## Design

- Replace `subprocess("mmcli")` with `pydbus` ModemManager D-Bus interface
- Poll ModemManager for: 3GPP registration state, operator, RAT,
  signal quality (RSSI/RSRP/RSRQ/SINR), cell ID, LAC/TAC, timing advance
- 5G NR: SS-RSRP, SS-RSQ, SS-SINR, NR ARFCN, NR Cell ID, TAC
- GPS: read `gpsd` or ModemManager location API; correlate cell changes
  with movement vectors
- SQLite baseline DB: per-cell signal history, typical neighbor lists,
  LAC-to-cellID mapping
- Heuristic triggers:
  * Timing Advance=0 with no tower at GPS location → THREAT_HIGH
  * Cell ID change at same GPS (stationary) → THREAT_MEDIUM
  * RAT downgrade 5G→4G→3G→2G → THREAT_HIGH per step
  * Signal jump >25dBm from baseline → THREAT_MEDIUM
  * Isolated cell (0 neighbors in scan) → THREAT_LOW
  * Intra-band frequency drop (n78→n71 or B4→B12) without movement → LOW

### D-Bus Interface

```
org.freedesktop.ModemManager1.Modem
├── .Signal                         — RSSI, RSRP, RSRQ, SINR
├── .Bearer                         — APN, IP config
├── .Modem3gpp                      — operator, registration, MNC/MCC
├── .Modem3gpp.Location             — GPS coordinates
├── .Modem3gpp.CellInfo             — serving + neighbor cells
│   ├── LTE: cell_id, lac, tac, timing_advance, rsrp, rsrq
│   └── NR:  nr_cell_id, tac, ss_rsrp, ss_rsrq, ss_sinr, nrarfcn
```

## API Changes

```
GET  /cpip/cell/status          — full cellular status + threat level
POST /cpip/cell/scan            — trigger immediate scan
GET  /cpip/cell/history         — baseline DB query
POST /cpip/cell/baseline-reset  — reset learned baselines
```

## CLI Changes

```
cpip cell status         — full cellular status + threat level
cpip cell scan           — trigger immediate scan
cpip cell history        — show baseline DB
cpip cell baseline reset — reset learned baselines
```

## Dashboard Changes

- New "Cellular" panel tab (replaces basic "Mobile" card)
- Real-time signal metrics chart (RSSI/RSRP/RSRQ over time)
- Neighbor cell list with signal deltas
- GPS location marker
- Threat timeline per detection vector
- Baseline learning progress indicator

## Env Variables

```
CPIP_CELL_SOURCE=mmcli|dbus          (default: dbus)
CPIP_CELL_5G=1                       enable 5G NR scanning
CPIP_CELL_TA_ANALYSIS=1              timing advance anomaly detection
CPIP_CELL_GPS_CORRELATE=1            GPS-movement correlation
CPIP_CELL_SIGNAL_DELTA=25            signal anomaly threshold (dBm)
CPIP_CELL_BASELINE_DB=/var/lib/cpip/cell_baseline.db
CPIP_CELL_SCAN_INTERVAL=30           cellular scan interval (seconds)
```

## Security Considerations

- D-Bus access to ModemManager may require polkit privileges
- GPS data is sensitive; encrypt baseline DB at rest
- Timing advance readings depend on modem firmware; TA=0 may be legitimate
  in small-cell deployments — require corroborating evidence for HIGH

## Limitations

- Requires ModemManager ≥1.20 for 5G NR cell info D-Bus API
- Timing advance not exposed by all modems (Qualcomm ≥MDM9x40)
- GPS correlation requires active GPS fix (may drain battery)
