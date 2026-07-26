# RFC-0018: Carrier-Grade API Integration

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/carrier.py` |
| Related | RFC-0001 |
| Version Target | v6.0.0 |

## Abstract

Connect to cellular carrier fraud APIs for SIM swap alerts, port-out
protection, and eSIM profile management.

## Design

- Carrier API adapters: AT&T Fraud, T-Mobile Partner, Verizon Digital Edge
- Webhook endpoint at /cpip/carrier/webhook
- On SIM swap: alert (HIGH), evidence capture, mesh notify, key rotation
- Port-out freeze on THREAT_HIGH+
- eSIM profile switch via GSMA RSP on threat detection

## API

```
GET  /cpip/carrier/status
POST /cpip/carrier/webhook
```

## CLI

```
cpip carrier status
cpip carrier register-webhook
cpip carrier sim-change-history
```

## Env

```
CPIP_CARRIER_API=0
CPIP_CARRIER_ATT_FRAUD_KEY=
CPIP_CARRIER_TMO_PARTNER_KEY=
CPIP_CARRIER_VZ_EDGE_KEY=
CPIP_CARRIER_WEBHOOK_PORT=4180
```
