# RFC-0005: Anti-SS7 / Anti-Diameter Core

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/ss7_monitor.py` |
| Related | RFC-0006 |
| Version Target | v6.0.0 |

## Abstract

Monitor and filter SS7 MAP and Diameter signaling for location leaks,
SMS interception, and subscriber impersonation.

## Motivation

SS7 and Diameter are the signaling protocols that underpin global
telecommunications. They were designed in an era of trust and lack
modern authentication. Adversaries exploit these protocols to track
subscriber location, intercept SMS, redirect calls, and impersonate
subscribers.

## Design

- Passive SS7/Diameter monitoring via PCAP or SigFW integration
- SS7 MAP filters: AnyTimeInterrogation, ProvideSubscriberInfo,
  SendRoutingInfoForSM, ForwardSM from unexpected sources
- Diameter anomaly: CER/CEA from unexpected origins, DER/DEA anomalies
- SigPloit integration as subprocess for detection modules
- Alerts feed into ML scorer (RFC-0006)

## CLI Changes

```
cpip ss7 status
cpip ss7 log [lines]
cpip diameter status
cpip sigfw alerts
```

## Env Variables

```
CPIP_SS7_MONITOR=0
CPIP_SS7_IFACE=lo
CPIP_SS7_SIGFW_SOCKET=unix:///run/sigfw.sock
CPIP_SS7_BLOCK_ATI=1
```

## Limitations

- Requires SS7/Diameter network access
- SigPloit integration requires separate installation
- Primarily useful for CPIP nodes at carrier edge
