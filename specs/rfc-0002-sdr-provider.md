# RFC-0002: SDR Provider — Baseband Analysis via Software-Defined Radio

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/sdr.py`, `radio/` |
| Related | RFC-0004, RFC-0024 |
| Version Target | v6.0.0 |

## Abstract

Expose RTL-SDR / HackRF functionality as a proper `BaseProvider`.
Enable passive GSM/LTE cell scanning, phantom tower detection,
IQ capture on alert, and spectrum monitoring.

## Motivation

CPIP already has RTL-SDR support in `radio/radio_if.c` (via `#ifdef USE_RTLSDR`)
but it's not exposed through the provider system or the dashboard. This RFC
wraps SDR functionality as a first-class provider with passive cell scanning,
phantom tower detection, and forensic IQ capture.

## Design

- `SDRProvider(BaseProvider)` with `ProviderType.RADIO`
- Backends: `librtlsdr` (via `radio_if.c`), `SoapySDR` (generic SDR)
- Passive cell scan: tune to LTE/5G bands, decode PSS/SSS, MIB, SIB1
- Phantom tower detection: compare SDR-observed cells vs OS-reported cells;
  any SDR-only tower is flagged
- IQ capture: on threat alert, dump N seconds of raw I/Q to
  `/var/lib/cpip/evidence/<timestamp>.iq`
- Spectrum waterfall: expose FFT data via WebSocket for dashboard
- RF fingerprinting: measure I/Q imbalance, CFO, phase noise per tower;
  build baseline profiles, flag deviations

## API Changes

```
GET  /cpip/sdr/status          — SDR hardware status
POST /cpip/sdr/scan            — trigger cell scan
GET  /cpip/sdr/spectrum        — FFT data (WebSocket streaming)
POST /cpip/sdr/capture         — manual IQ capture
```

## CLI Changes

```
cpip sdr status
cpip sdr scan [band]
cpip sdr spectrum
cpip sdr capture [seconds]
```

## Dashboard Changes

- New "SDR" panel tab with spectrum waterfall (WebSocket)
- Phantom tower alert list
- RF fingerprint table
- SDR gain/freq controls

## Env Variables

```
CPIP_SDR=0                        enable SDR provider
CPIP_SDR_DEVICE=rtlsdr|hackrf|soapy
CPIP_SDR_GAIN=auto|0-50           LNA gain
CPIP_SDR_BANDS="B2,B4,B5,B12,B13,B66,n71,n78"
CPIP_SDR_IQ_DIR=/var/lib/cpip/evidence
CPIP_SDR_CAPTURE_DURATION=10      seconds on alert
```

## Security Considerations

- IQ captures contain raw RF data that may include private communications
  from nearby devices. Encrypt evidence storage at rest.
- SDR scanning on certain bands may be regulated; document legal
  considerations per jurisdiction.

## Limitations

- Requires RTL-SDR, HackRF, or SoapySDR-compatible hardware
- LTE/5G signal decoding requires sufficient SNR (>10dB)
- Phantom tower detection requires OS-reported cell list (ModemManager)
