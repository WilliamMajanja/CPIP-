# RFC-0025: Anti-Stalkerware & Device Hygiene

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/hygiene.py` |
| Related | RFC-0001, RFC-0011 |
| Version Target | v6.0.0 |

## Abstract

Scan for stalkerware/spyware, unauthorized baseband access, USB data
exfiltration, and filesystem integrity monitoring.

## Design

- Stalkerware scan: known signatures (mSpy, FlexiSPY, Cerberus, etc.)
- Baseband DIAG port scan: detect open QMI/smd ports
- USB host watchdog: alert on unknown USB host connection
- Camera/mic check: flag unexpected video4linux or ALSA streams
- Filesystem integrity: inotify + sha256 manifest for /etc, systemd, cron

## CLI

```
cpip hygiene scan [quick|full]
cpip hygiene monitor [processes|filesystem|usb]
cpip hygiene quarantine [process_name]
```

## Env

```
CPIP_HYGIENE_SCAN=1
CPIP_HYGIENE_FS_WATCH=/etc,/usr/lib/systemd
CPIP_HYGIENE_STALKERWARE_DB=/etc/cpip/stalkerware_signatures.json
```
