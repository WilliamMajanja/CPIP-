# CPIP v5.2.3 — Palantir Hardening + RFC 6969 + IP Spoofing

**Release Date:** 2026-07-26  
**Protocol:** CPIP/5.2.3  
**RFC Base:** RFC 2324 (HTCPCP) + RFC 7168 (HTCPCP-TEA) + RFC 6969 (OSPFv3 Instance ID)

---

## Build Notes

### RFC 6969 Integration (OSPFv3 Instance ID Routing)

CPIP v5.2.3 integrates the OSPFv3 Instance ID Registry (RFC 6969) to segregate mesh routing domains by transport layer. Each CPIP transport now maps to a dedicated OSPFv3 Instance ID:

| Instance ID | Transport | Address Family |
|-------------|-----------|----------------|
| 0           | LAN Mesh  | IPv6 unicast   |
| 64          | Satellite | IPv4 unicast   |
| 96          | Mobile    | IPv4 multicast |
| 128-191     | Radio     | Unassigned     |
| 192-255     | Covert    | Private Use    |

Instance IDs are carried in OSPFv3 packet headers alongside CPIP mesh messages, enabling the routing layer to distinguish and forward messages by transport domain without cross-contamination. The Instance ID registry update per RFC 6969 partitions the 128-255 range into Standards Action (128-191) and Private Use (192-255) — CPIP uses the Private Use range for covert channel routing.

### Palantir-Grade Counter-Surveillance Hardening

New module `providers/palantir.py` provides ten countermeasures against advanced data analytics:

1. **Constant-Time Message Sending** — All outbound sends take identical wall-clock time regardless of payload size, defeating timing analysis
2. **Fixed-Size Message Padding** — Messages padded to configurable size (default 1024B), eliminating packet-size correlation
3. **Message Mixing / Delay / Reorder** — Messages held 0.1-5s in a mix queue, shuffled before send, breaking sequencing attacks
4. **Chaff Traffic to All Peers** — Random fake messages at variable intervals to every known peer, masking real communication patterns
5. **Identity Rotation** — Periodic POT_ID and cryptographic key rotation (configurable interval, default 3600s) prevents long-term link analysis
6. **Traffic Profile Normalization** — Constant-bitrate (CBR) mode fills silent periods with padded messages, defeating pattern-of-life detection
7. **Auto-Evasion** — Automatically activates all countermeasures when AntiSurveillance detects DPI, SSL interception, or surveillance equipment
8. **Broadcast-All Mode** — Every message sent to every known peer regardless of intended recipient; non-target peers silently discard, masking who talks to whom
9. **Anti-Link-Analysis Cover Conversations** — Chaff messages generate realistic-looking conversations between random peer pairs
10. **Agent Log** — Internal audit trail of all hardening actions for post-event analysis

### IP Spoofing & Proxy Rotation

New module `providers/spoof.py` provides three rotation modes:

- **Tor Mode** — Routes all outbound connections through Tor SOCKS5 proxy (configurable via `CPIP_TOR_PROXY`)
- **Proxy Pool Mode** — Rotates through a configurable list of SOCKS5/HTTP proxies (`CPIP_PROXY_LIST` or `CPIP_PROXY_FILE`)
- **Source IP Mode** — Cycles through all available local IPs on each outbound connection (8 IPs discovered on target system)

### Build Configuration

```bash
# Full Palantir hardening + IP spoofing + Anti-ISP + all defenses
CPIP_PALANTIR=1 \
CPIP_PALANTIR_MODE=auto \
CPIP_PALANTIR_CHAFF=1 \
CPIP_PALANTIR_MIX_DELAY=5 \
CPIP_PALANTIR_FIXED_SIZE=1024 \
CPIP_PALANTIR_ID_ROTATE=3600 \
CPIP_PALANTIR_BROADCAST=1 \
CPIP_PALANTIR_TIMING=cbr \
CPIP_SPOOF=1 \
CPIP_SPOOF_MODE=tor \
CPIP_TOR_PROXY=socks5://127.0.0.1:9050 \
python3 server.py
```

### CLI Commands

```
cpip palantir status    — Show hardening status + agent log
cpip palantir enable    — Enable countermeasures
cpip palantir disable   — Disable countermeasures
cpip palantir chaff     — Toggle chaff traffic generation
cpip palantir broadcast — Toggle broadcast-all mode
cpip palantir evasion   — Activate full auto-evasion
cpip palantir log       — Show agent audit log

cpip spoof status       — Show IP spoofing/proxy status
cpip spoof rotate       — Force proxy rotation
cpip spoof reload       — Reload proxy list from file
```

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/cpip/palantir` | Hardening status + agent log |
| POST | `/cpip/palantir` | Control hardening (enable/disable/chaff/broadcast/evasion) |
| GET | `/cpip/spoof` | IP spoofing & proxy status |
| POST | `/cpip/spoof` | Control spoofing (rotate/reload) |

### Upgrading from v5.1.1

- No breaking changes to existing API or mesh protocol
- New features are opt-in via environment variables (all default to disabled)
- Existing `cpip.conf` / env config continues to work unchanged
- The Palantir module requires no database migration or persistence changes

### Security Considerations

- Palantir hardening increases bandwidth overhead (chaff + padding + broadcast multipliers)
- CBR timing mode may increase latency on constrained links
- Identity rotation breaks long-lived E2EE sessions — peers must re-establish
- Broadcast-all mode multiplies traffic by number of peers (O(n) per message)
- Tor/proxy mode introduces additional latency from SOCKS5 relay hops
- Source IP rotation requires multiple local IPs or network interfaces
