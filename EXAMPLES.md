# CPIP Usage Examples

## Basic Brewing

```bash
# Brew a cup of tea
cpip brew tea

# Brew coffee with milk and honey
cpip brew coffee "milk;variety=whole, sugar;variety=honey"

# Brew and get the 418 treatment (teapot can't brew coffee)
cpip 418
```

## 1nf1D3L's Kyber KEM (Post-Quantum)

`b4dm4n_cw.py` is invoked directly (it is not registered as a console script).
Its `encaps`/`decaps` take positional key/ciphertext args, and hybrid is selected
via `-a hybrid`, not via separate `hybrid-*` subcommands.

```bash
# Basic Kyber KEM (positional pubkey for encaps; privkey + ct for decaps)
./b4dm4n_cw.py keygen -o mykeys
./b4dm4n_cw.py encaps mykeys.pk -o ct.bin
./b4dm4n_cw.py decaps mykeys.sk ct.bin

# With a different coffee recipe (domain separation)
./b4dm4n_cw.py keygen --recipe cappuccino -o cap_keys
./b4dm4n_cw.py encaps --recipe cappuccino cap_keys.pk -o cap_ct.bin

# Hybrid ECDH P-256 + Kyber (defense in depth) — use the -a hybrid alias
./b4dm4n_cw.py keygen -a hybrid -o hybrid
./b4dm4n_cw.py encaps -a hybrid hybrid.pk -o hyb_ct.bin
./b4dm4n_cw.py decaps -a hybrid hybrid.sk hyb_ct.bin

# Benchmark
./b4dm4n_cw.py bench -n 50

# Show parameters
./b4dm4n_cw.py info

# Show ASCII art
./b4dm4n_cw.py coffee
```

## Mesh Messaging

```bash
# Scan for peers on the LAN mesh
cpip mesh scan
cpip mesh peers

# Send an E2EE message
cpip mesh send a1b2c3d4 "Hello from the coffee pot network"

# Broadcast to everyone
cpip mesh broadcast "Attention all pots: brew time is 15:00"

# Read your inbox
cpip mesh inbox
```

## Multi-Transport Mesh

```bash
# Start with all transports
CPIP_SAT=1 CPIP_RADIO=1 CPIP_MOBILE=1 ./server.py

# In another terminal, check each transport
cpip mesh sat      # Satellite peers
cpip mesh radio    # LoRa/TNC status
cpip mesh mobile   # 4G/5G peers

# Messages sent on any transport automatically
# forward to all others via cross-transport routing.
```

## Covert Channel

```bash
# Encode a secret message
cpip covert encode "The coffee is ready at midnight"

# This outputs an Accept-Additions header like:
# milk;variety=4d69646e, syrup;variety=69676874

# Decode a captured header
cpip covert decode "milk;variety=4d69646e, syrup;variety=69676874"

# Brew with a hidden message (sends it to a peer)
cpip covert brew "meet at the usual spot" a1b2c3d4

# Cover traffic runs automatically to hide real messages
cpip covert status
```

## ECC / Address Book

```bash
# Show your node's ECC address
cpip ecc address
# → coffee:2w3q2ay...

# Resolve an address to a POT_ID
cpip ecc resolve coffee:2w3q2ay...

# List all known addresses
cpip ecc book

# ECC status
cpip ecc status
```

## Dead Drops

```bash
# Leave a message (done automatically for offline peers)
# List available dead drops
cpip deaddrop list

# Claim one
cpip deaddrop claim <message_id>
```

## ITF Defense (In The Face)

```bash
# Check your defense posture
cpip itf status
# → 418 Teapot:    ACTIVE
# → Stealth:       OFF
# → Blacklisted:   3 address(es)

# List blacklisted IPs
cpip itf blacklist

# Probe check — see if an IP is banned
cpip itf probe 10.0.0.5

# Whitelist a falsely blacklisted address
cpip itf whitelist 10.0.0.5

# Emergency: clear the entire blacklist
cpip itf clear
```

## Defense Policy Toggles (Runtime)

Every Anti-ISP, Anti-Stingray, Anti-Surveillance and Net-Neutrality vector can be
toggled at runtime without restarting the server.

```bash
# View the live policy state for all four groups
curl -s http://localhost:4180/cpip/config | python3 -m json.tool | grep -A12 policies

# Disable the STUN transport (Anti-ISP)
curl -X POST -H "Content-Type: application/json" \
  -d '{"action":"toggle","feature":"stun","enabled":false}' \
  http://localhost:4180/cpip/anti-isp

# Disable the cellular scan but keep RF + signal-anomaly scans (Anti-Stingray)
curl -X POST -H "Content-Type: application/json" \
  -d '{"action":"toggle","feature":"cell_scan","enabled":false}' \
  http://localhost:4180/cpip/anti-stingray

# Force an immediate Stingray rescan
curl -X POST -H "Content-Type: application/json" \
  -d '{"action":"rescan"}' \
  http://localhost:4180/cpip/anti-stingray

# Disable DPI evasion (Anti-Surveillance)
curl -X POST -H "Content-Type: application/json" \
  -d '{"action":"toggle","feature":"dpi_evasion","enabled":false}' \
  http://localhost:4180/cpip/anti-surveillance

# Disable packet fragmentation (Net-Neutrality)
curl -X POST -H "Content-Type: application/json" \
  -d '{"action":"toggle","feature":"fragmentation","enabled":false}' \
  http://localhost:4180/cpip/net-neutrality

# Bulk-update several policies in one call
curl -X PUT -H "Content-Type: application/json" \
  -d '{"policies":{"anti_isp":{"stun":false,"upnp":true},"net_neutrality":{"jitter":true}}}' \
  http://localhost:4180/cpip/config
```

Unknown `feature` names return HTTP `400`. Toggling `enabled`/`master` on the
Anti-Stingray, Anti-Surveillance, or Net-Neutrality groups starts or stops the
background scan loop.

## Satellite Mesh (Internet-Wide)

```bash
# Start with satellite relay
CPIP_SAT=1 CPIP_SAT_LAT=51.5 CPIP_SAT_LON=-0.12 \
  CPIP_SAT_BOOTSTRAP="seed1.cpip.io:4195,seed2.cpip.io:4195" \
  ./server.py

# Check satellite status
cpip mesh sat
```

## Radio Transport (LoRa)

```bash
# Build the C radio interface
make -C radio

# Start with LoRa enabled
CPIP_RADIO=1 CPIP_RADIO_MODE=lora \
  CPIP_RADIO_FREQ=868000000 CPIP_RADIO_SF=12 \
  ./server.py

# Or use simulation mode (no hardware needed)
CPIP_RADIO=1 CPIP_RADIO_MODE=sim ./server.py

# Check radio status
cpip mesh radio
```

## Mobile Broadband (4G/5G)

```bash
# Start with mobile mesh
CPIP_MOBILE=1 CPIP_MOBILE_IFACE=wwan0 \
  CPIP_MOBILE_BOOTSTRAP="relay.cpip.io:4196" \
  ./server.py

# Check mobile status
cpip mesh mobile
```

## Prometheus Metrics

```bash
curl http://localhost:4180/cpip/metrics

# Example output:
# HELP cpip_brewing Current brewing state
# TYPE cpip_brewing gauge
# cpip_brewing 0
# HELP cpip_mesh_peers Number of mesh peers
# TYPE cpip_mesh_peers gauge
# cpip_mesh_peers 3
```

## Everything at Once

```bash
# Full status snapshot
cpip stats

# Full configuration
cpip config
```

## API Usage (curl)

```bash
# Brew
curl -X BREW http://localhost:4180/coffee

# Brew with additions
curl -X BREW -H "Accept-Additions: milk;variety=whole" http://localhost:4180/tea

# Stop
curl -X WHEN http://localhost:4180/

# Server status
curl http://localhost:4180/

# Mesh status
curl http://localhost:4180/cpip/mesh/status

# Send mesh message
curl -X POST -H "Content-Type: application/json" \
  -d '{"dst":"a1b2c3d4","data":"hello via coffee"}' \
  http://localhost:4180/cpip/mesh/send

# Encode covert message
curl -X POST -H "Content-Type: application/json" \
  -d '{"message":"secret"}' \
  http://localhost:4180/cpip/mesh/encode

# Decode covert message
curl -X POST -H "Content-Type: application/json" \
  -d '{"accept_additions":"milk;variety=736563726574"}' \
  http://localhost:4180/cpip/mesh/decode

# ITF defense
curl http://localhost:4180/cpip/defense
curl -X POST -H "Content-Type: application/json" \
  -d '{"action":"clear"}' \
  http://localhost:4180/cpip/defense

# Satellite status
curl http://localhost:4180/cpip/mesh/sat

# Radio status
curl http://localhost:4180/cpip/mesh/radio

# Mobile status
curl http://localhost:4180/cpip/mesh/mobile

# Dead drops
curl "http://localhost:4180/cpip/mesh/deaddrop?action=list"
```
