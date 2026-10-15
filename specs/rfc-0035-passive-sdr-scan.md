# RFC-0035: Passive SDR Scan and Spectrum API

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/sdr.py`, `radio/`, dashboard |
| Related | RFC-0002, RFC-0004, RFC-0017, RFC-0027 |
| Version Target | v7.0.0 |

## Abstract

Provide a receive-only SDR capability for bounded spectrum measurements and scan metadata. Do not claim LTE/5G cell decoding or tower identity unless a tested decoder supplies that data.

## Design

- Detect RTL-SDR/Soapy/HackRF backends and report RX/TX capability separately.
- Validate frequencies, sample rates, gains, duration, output path, and band against an allowlist; invoke subprocesses without a shell.
- Return measurements with calibrated units, sample time, hardware/backend, and decoder provenance. Raw IQ capture is opt-in, bounded, stored securely, and accompanied by retention controls.
- SDR waterfall streaming is a separate streaming endpoint with access control and bounded buffers.
- TX remains disabled by default and is never implied by SDR availability or a scan request.

## API/CLI Changes

Status/scan/capture responses report receive capability, decoder availability, and limitations. Spectrum streaming is exposed only when an actual backend produces measurements.

## Security Considerations

Raw IQ may contain sensitive nearby transmissions. Enforce file permissions, size/duration limits, retention settings, and explicit capture actions. Never shell-interpolate device or frequency input.

## Acceptance Criteria

- Mock backend tests cover valid/invalid settings, absent hardware, timeout, short captures, file permissions, and cancellation.
- A scan without a hardware decoder cannot return fabricated cell IDs or mark a signal as an IMSI catcher.
