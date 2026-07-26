# RFC-0023: Censorship Circumvention & Traffic Morphing

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/circumvention.py` |
| Related | RFC-0015 |
| Version Target | v6.0.0 |

## Abstract

Make CPIP traffic indistinguishable from common protocols (HTTPS, DNS, QUIC)
to evade DPI and network-level blocking.

## Design

- Protocol mimicry: HTTPS/1.1, HTTP/2, DNS-over-HTTPS, QUIC (aioquic)
- Domain fronting via Cloudflare Workers, Fastly, Azure CDN
- Pluggable transports: meek, Snowflake, obfs4
- Message padding to TLS record sizes (512, 1024, 4096, 16384)

## CLI

```
cpip circumvention status
cpip circumvention mode [https|dns|quic|meek|snowflake]
cpip circumvention front <domain>
```

## Env

```
CPIP_CIRCUMVENTION=0
CPIP_CIRCUMVENTION_MODE=https
CPIP_CIRCUMVENTION_FRONT_DOMAIN=cdn.cloudflare.com
CPIP_CIRCUMVENTION_DOH=1
```
