# RFC-0017: Anti-TEMPEST / EM-Sec

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/emsec.py` |
| Related | RFC-0004 |
| Version Target | v6.0.0 |

## Abstract

Detect intentional RF emissions for EM side-channel extraction, perform
Faraday cage integrity tests, defend against timing side-channel attacks.

## Design

- SDR at low gain detects nearby coherent carriers (side-channel receiver)
- Timing attack defense: jitter all crypto + mesh processing
- Faraday cage test: emit test pulse, measure reflected power
- CPU load pattern masking: random busy loops

## CLI

```
cpip em-sec scan
cpip em-sec faraday-test
cpip em-sec tempest-detect
```

## Env

```
CPIP_EMSEC=0
CPIP_EMSEC_FARADAY_TEST_INTERVAL=3600
CPIP_EMSEC_FARADAY_RX_GAIN=10
CPIP_EMSEC_TIMING_JITTER_MS=50
```
