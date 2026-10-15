# CPIP Specification and Request Records

The `specs/` directory contains three kinds of project records. These identifiers
are local to CPIP and are **not** IETF RFC numbers, Internet Standards, or proof
that a feature has been implemented.

## Record types

- **CPIP-RFF-NNNN — Request for Feature:** intake record for a new capability.
  Start with [`rff-0000-template.md`](rff-0000-template.md). Acceptance means a maintainer is willing to
  consider or schedule work; it does not mean the feature exists.
- **RFC-CR-NNNN — Request for Change:** review record for modifying existing
  behavior, defaults, protocol/API compatibility, or data handling. Use the
  [`rfc-cr-0000-template.md`](rfc-cr-0000-template.md) and link it to the affected implementation and tests.
- **CPIP-RFC-NNNN — CPIP project specification:** design record for a substantial
  protocol or architectural change. Start with [`rfc-0000-template.md`](rfc-0000-template.md). This name
  is distinct from a publication in the IETF RFC Series; cite IETF documents by
  their official number and title.

## Status lifecycle

Use `Draft`, `Needs Review`, `Accepted`, `Deferred`, `Rejected`, `Implemented`,
or `Verified`. `Accepted` is not implementation; `Implemented` requires a linked
commit and tests; `Verified` requires a named reviewer, version, platform, and
results. Do not use a `Verified` label for an untested proposal.

## Current proposal inventory

At baseline CPIP commit `df93a5258a0d9e5297d30bd6b630f299969ec8bb`, the numbered
proposal files below identified themselves as `Draft` and targeted v6.0.0 while
package metadata reported CPIP v6.0.3. This documentation update adds request
templates but does not change those proposal statuses or assert that their
behavior is implemented. No numbered feature-request records existed in that
baseline; use the RFF template for future requests.

| ID | Topic | Record |
| --- | --- | --- |
| CPIP-RFC-0001 | Cellular scan engine | [spec](rfc-0001-antistringray-v2.md) |
| CPIP-RFC-0002 | Software-defined radio provider | [spec](rfc-0002-sdr-provider.md) |
| CPIP-RFC-0003 | Post-quantum subscriber identity | [spec](rfc-0003-pqc-suci.md) |
| CPIP-RFC-0004 | Spectrum defense | [spec](rfc-0004-spectrum-defense.md) |
| CPIP-RFC-0005 | SS7/Diameter | [spec](rfc-0005-ss7-diameter.md) |
| CPIP-RFC-0006 | ML scoring | [spec](rfc-0006-ml-scoring.md) |
| CPIP-RFC-0007 | Mesh detection grid | [spec](rfc-0007-mesh-detection-grid.md) |
| CPIP-RFC-0008 | Hardware/GPIO/firmware integration | [spec](rfc-0008-hardware-gpio.md) |
| CPIP-RFC-0009 | Ambient sensor correlation | [spec](rfc-0009-ambient-sensors.md) |
| CPIP-RFC-0010 | Field operations mode | [spec](rfc-0010-field-ops.md) |
| CPIP-RFC-0011 | Tamper detection | [spec](rfc-0011-tamper-detection.md) |
| CPIP-RFC-0012 | Deception/honeypot mode | [spec](rfc-0012-deception-honeypot.md) |
| CPIP-RFC-0013 | AI assessment | [spec](rfc-0013-ai-assessment.md) |
| CPIP-RFC-0014 | Modem firmware integrity | [spec](rfc-0014-modem-firmware.md) |
| CPIP-RFC-0015 | Out-of-band side channels | [spec](rfc-0015-ob-side-channels.md) |
| CPIP-RFC-0016 | Energy/battery forensics | [spec](rfc-0016-energy-forensics.md) |
| CPIP-RFC-0017 | TEMPEST/EM security | [spec](rfc-0017-anti-tempest.md) |
| CPIP-RFC-0018 | Carrier API integration | [spec](rfc-0018-carrier-api.md) |
| CPIP-RFC-0019 | Post-quantum mesh protocol | [spec](rfc-0019-pq-mesh-protocol.md) |
| CPIP-RFC-0020 | Duress/coercion detection | [spec](rfc-0020-duress-detection.md) |
| CPIP-RFC-0021 | Mesh attack detection | [spec](rfc-0021-mesh-attack-detect.md) |
| CPIP-RFC-0022 | Blockchain evidence | [spec](rfc-0022-blockchain-evidence.md) |
| CPIP-RFC-0023 | Censorship circumvention | [spec](rfc-0023-censorship-circumvention.md) |
| CPIP-RFC-0024 | Air-gap channels | [spec](rfc-0024-airgap-channels.md) |
| CPIP-RFC-0025 | Anti-stalkerware | [spec](rfc-0025-anti-stalkerware.md) |
| CPIP-RFC-0026 | Threat intelligence correlation | [spec](rfc-0026-global-threat-intel.md) |

## Implemented change requests

| ID | Change | Record |
| --- | --- | --- |
| RFC-CR-0001 | Correct RFC 7168 metadata URL | [change record](rfc-cr-0001-rfc7168-url.md) |

## Citation correction

The baseline CPIP v6.0.3 metadata at commit `df93a5258a0d9e5297d30bd6b630f299969ec8bb`
pointed its RFC-7168 project URL at RFC 2168. The documentation update corrected
that link to <https://www.rfc-editor.org/rfc/rfc7168>. This citation correction
does not change or validate the protocol design records above.
