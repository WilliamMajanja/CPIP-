# RFC-0014: Cellular Modem Firmware Integrity

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/modem.py` |
| Related | RFC-0001 |
| Version Target | v6.0.0 |

## Abstract

Verify modem firmware integrity, detect rollback attacks, match chipset
version against known CVEs.

## Design

- Query firmware version via AT+GMR, QMI DMS, ModemManager
- SHA-256 compare against known-good manifest
- Rollback detection: flag if version downgraded since last boot
- CVE matching via NIST NVD API v2.0
- Alert on unexpected baseband reset or firmware load events

## CLI

```
cpip modem fw-check
cpip modem fw-history
cpip modem cve-scan
```

## Env

```
CPIP_MODEM_FW_CHECK=1
CPIP_MODEM_FW_MANIFEST=/etc/cpip/modem_firmware_manifest.json
CPIP_MODEM_NVD_API_KEY=
```
