# RFC-0011: Tamper & Physical Intrusion Detection

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/tamper.py` |
| Related | RFC-0008, RFC-0009 |
| Version Target | v6.0.0 |

## Abstract

Detect case opening, SD card/USB events, RTC rollback, vibration,
and thermal anomalies indicating physical device tampering.

## Design

- GPIO hall-effect sensor → case open (HIGH)
- udev monitor → SD card/USB events (MEDIUM)
- RTC vs NTP check → rollback detection (CRITICAL)
- Accelerometer → sustained vibration while stationary (LOW)
- Thermal sensor → rapid >+15°C rise = handling (LOW)
- All events logged with SHA-256 chain-of-custody

## CLI

```
cpip tamper status
cpip tamper log
cpip tamper test
```

## Env

```
CPIP_TAMPER_CASE_PIN=16
CPIP_TAMPER_USB_MONITOR=1
CPIP_TAMPER_RTC_CHECK=1
```
