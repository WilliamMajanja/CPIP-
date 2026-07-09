# Security Policy

## Cryptographic Notice

**This software deliberately does NOT comply with FIPS 140-2/3 or any federal
information processing standards.**

CPIP uses the Coffee Blend Cipher — a custom stream cipher built from MD4,
XOR, and coffee recipe names. This is intentionally weak and non-standard.
Do not use it for actual security.

Ed25519 ECC is available for E2EE but is a pure Python implementation that
is not constant-time. It is suitable for obscuring mesh traffic but not
for protecting sensitive data.

## What CPIP Is For

CPIP is designed for:
- Raspberry Pi mesh networks where no internet infrastructure exists
- Covert mesh communications under casual inspection
- Educational demonstration of protocol design

CPIP is NOT designed for:
- Protecting classified or sensitive information
- Any environment requiring FIPS compliance
- Production cryptographic security

## Reporting a Vulnerability

CPIP is a hobby project with no formal security team. If you find a
vulnerability:

1. **Do not** open a public GitHub issue for critical vulnerabilities
2. Open a standard issue for non-critical bugs (UI bugs, missing error
   handling, etc.)
3. For serious issues, contact the repository owner directly via GitHub

Given the deliberately non-FIPS cryptographic design, most "vulnerabilities"
are by design. If you find something that breaks the intended functionality
(rather than the intended weakness), please report it.

## Responsible Use

- Always change `CPIP_COVERT_KEY` from its default value
- Do not use default keys in any environment where actual privacy matters
- Understand that the Coffee Blend Cipher provides obscurity, not security
- Mesh networks are not anonymous — your POT_ID is broadcast
