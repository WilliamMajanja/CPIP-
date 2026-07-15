# CPIP Usage Examples

## Basic Brewing

```bash
# Brew a cup of tea
htcpcp brew tea

# Brew coffee with milk and honey
htcpcp brew coffee "milk;variety=whole, sugar;variety=honey"

# Brew and get the 418 treatment (teapot can't brew coffee)
htcpcp 418
```

## 1nf1D3L's Kyber KEM (Post-Quantum)

```bash
# Basic Kyber KEM
b4dm4n-cw keygen -o mykeys
b4dm4n-cw encaps -k mykeys.pk -o ct.bin
b4dm4n-cw decaps -k mykeys.sk -c ct.bin

# With different coffee recipe (domain separation)
b4dm4n-cw keygen --recipe cappuccino -o cap_keys
b4dm4n-cw encaps --recipe cappuccino -k cap_keys.pk -o cap_ct.bin

# Hybrid ECDH P-256 + Kyber (defense in depth)
b4dm4n-cw hybrid-keygen -o hybrid
b4dm4n-cw hybrid-encaps -k hybrid.hp -o hyb_ct.bin
b4dm4n-cw hybrid-decaps -k hybrid.hs -c hyb_ct.bin

# Benchmark
b4dm4n-cw bench -n 50

# Show parameters
b4dm4n-cw info

# Show ASCII art
b4dm4n-cw art
```

## Mesh Messaging

```bash
# Scan for peers on the LAN mesh
htcpcp mesh scan
htcpcp mesh peers

# Send an E2EE message
htcpcp mesh send a1b2c3d4 "Hello from the coffee pot network"

# Broadcast to everyone
htcpcp mesh broadcast "Attention all pots: brew time is 15:00"

# Read your inbox
htcpcp mesh inbox
```

## Multi-Transport Mesh

```bash
# Start with all transports
CPIP_SAT=1 CPIP_RADIO=1 CPIP_MOBILE=1 ./server.py

# In another terminal, check each transport
htcpcp mesh sat      # Satellite peers
htcpcp mesh radio    # LoRa/TNC status
htcpcp mesh mobile   # 4G/5G peers

# Messages sent on any transport automatically
# forward to all others via cross-transport routing.
```

## Covert Channel

```bash
# Encode a secret message
htcpcp covert encode "The coffee is ready at midnight"

# This outputs an Accept-Additions header like:
# milk;variety=4d69646e, syrup;variety=69676874

# Decode a captured header
htcpcp covert decode "milk;variety=4d69646e, syrup;variety=69676874"

# Brew with a hidden message (sends it to a peer)
htcpcp covert brew "meet at the usual spot" a1b2c3d4

# Cover traffic runs automatically to hide real messages
htcpcp covert status
```

## ECC / Address Book

```bash
# Show your node's ECC address
htcpcp ecc address
# → coffee:2w3q2ay...

# Resolve an address to a POT_ID
htcpcp ecc resolve coffee:2w3q2ay...

# List all known addresses
htcpcp ecc book

# ECC status
htcpcp ecc status
```

## Dead Drops

```bash
# Leave a message (done automatically for offline peers)
# List available dead drops
htcpcp deaddrop list

# Claim one
htcpcp deaddrop claim <message_id>
```

## ITF Defense (In The Face)

```bash
# Check your defense posture
htcpcp itf status
# → 418 Teapot:    ACTIVE
# → Stealth:       OFF
# → Blacklisted:   3 address(es)

# List blacklisted IPs
htcpcp itf blacklist

# Probe check — see if an IP is banned
htcpcp itf probe 10.0.0.5

# Whitelist a falsely blacklisted address
htcpcp itf whitelist 10.0.0.5

# Emergency: clear the entire blacklist
htcpcp itf clear
```

## Satellite Mesh (Internet-Wide)

```bash
# Start with satellite relay
CPIP_SAT=1 CPIP_SAT_LAT=51.5 CPIP_SAT_LON=-0.12 \
  CPIP_SAT_BOOTSTRAP="seed1.cpip.io:4195,seed2.cpip.io:4195" \
  ./server.py

# Check satellite status
htcpcp mesh sat
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
htcpcp mesh radio
```

## Mobile Broadband (4G/5G)

```bash
# Start with mobile mesh
CPIP_MOBILE=1 CPIP_MOBILE_IFACE=wwan0 \
  CPIP_MOBILE_BOOTSTRAP="relay.cpip.io:4196" \
  ./server.py

# Check mobile status
htcpcp mesh mobile
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
htcpcp stats

# Full configuration
htcpcp config
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
