# RFC-0020: Duress & Coercion Detection

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/duress.py` |
| Related | RFC-0012 |
| Version Target | v6.0.0 |

## Abstract

Silent duress codes, behavioral biometrics, panic delete, and false mesh
join mode for when the operator is under physical coercion.

## Design

- Duress codes: alternate passphrase triggers silent emergency
- Behavioral: detect typing speed/pattern changes indicating coercion
- Panic delete: GPIO triple-tap or CLI command wipes keys, reboots
- False mesh join: appears to join captor's mesh, feeds modified data
- On duress: rotate keys, send false "all clear", log captor activity

## CLI

```
cpip duress set-code <phrase>
cpip duress test
cpip duress status
cpip duress panic-delete
```

## Env

```
CPIP_DURESS_CODE=
CPIP_DURESS_BEHAVIORAL=0
CPIP_DURESS_PANIC_DELETE_PIN=26
```
