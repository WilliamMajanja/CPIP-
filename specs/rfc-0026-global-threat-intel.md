# RFC-0026: Global Threat Correlation & Crowdsourced Intel

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/threat_intel.py` |
| Related | RFC-0007, RFC-0006 |
| Version Target | v6.0.0 |

## Abstract

Opt-in anonymized IMSI catcher threat sharing via P2P DHT with global
heatmap, roaming risk scoring, and community alerts.

## Design

- Anonymized payload: hash(cell_id,salt), mcc, mnc, geo(0.1°), hour, type
- Kademlia DHT backbone for distributed storage (TTL 24h)
- Global heatmap: dashboard density map of sightings
- Roaming risk: per-country/carrier risk score
- Community alerts: 5+ nodes report same cell_id hash → broadcast alert
- WiGLE/OpenCellID/BeaconDB tower verification

## API

```
GET /cpip/intel/global-map
GET /cpip/intel/risk-score?mcc=310&mnc=260
```

## CLI

```
cpip intel share [on|off]
cpip intel map
cpip intel risk-score <country_code>
cpip intel verify <cell_id>
```

## Env

```
CPIP_THREAT_SHARING=0
CPIP_THREAT_DHT_BOOTSTRAP=node1.cpip.net:8468,node2.cpip.net:8468
CPIP_THREAT_WIGLE_API_KEY=
CPIP_THREAT_OPENCELLID_API_KEY=
CPIP_THREAT_MIN_FOR_ALERT=5
```
