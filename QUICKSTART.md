# Quick Start

```bash
# 1. Start the server
./server.py

# 2. Open the dashboard
#    http://localhost:4180/dashboard

# 3. Brew something
curl -X BREW http://localhost:4180/coffee
curl -X WHEN http://localhost:4180/

# 4. Use the CLI
./cpip status
./cpip brew tea "milk;variety=whole"
./cpip when

# 5. Check the mesh
./cpip mesh status
./cpip mesh peers
./cpip mesh scan

# 6. Send a covert message
./cpip covert encode "hello world"

# 7. Check defenses
./cpip itf status
./cpip itf blacklist

# 8. Post-Quantum KEM (1nf1D3L's Kyber)
./b4dm4n_cw.py keygen -o mykeys
./b4dm4n_cw.py encaps -k mykeys.pk -o ct.bin
./b4dm4n_cw.py decaps -k mykeys.sk -c ct.bin

# 9. Hybrid ECDH + Kyber (defense in depth)
./b4dm4n_cw.py hybrid-keygen -o hybrid
./b4dm4n_cw.py hybrid-encaps -k hybrid.hp -o hyb_ct.bin
./b4dm4n_cw.py hybrid-decaps -k hybrid.hs -c hyb_ct.bin

# 10. Tune defense policies at runtime (no restart)
curl -s http://localhost:4180/cpip/config | python3 -m json.tool | grep -A12 policies
curl -X POST -H "Content-Type: application/json" \
  -d '{"action":"toggle","feature":"stun","enabled":false}' http://localhost:4180/cpip/anti-isp
```

## Configure defense policies (environment variables)

All defense vectors default to **on** and are individually configurable via
`CPIP_*` env vars (permanent) or toggled at runtime (temporary). See the
"Environment Variables" section of [README.md](README.md) for the full list
(`CPIP_ANTI_ISP`, `CPIP_STUN`, `CPIP_ANTI_STINGRAY`, `CPIP_STINGRAY_CELL`,
`CPIP_ANTI_SURVEILLANCE`, `CPIP_DPI_EVASION`, `CPIP_NET_NEUTRALITY`,
`CPIP_NN_FRAG_EVASION`, …).

```bash
# Start with a minimal policy: ISP transports + Stingray off, surveillance on
CPIP_ANTI_ISP=1 CPIP_ANTI_STINGRAY=0 CPIP_ANTI_SURVEILLANCE=1 ./server.py
```

## With extra transports

```bash
# Enable all transports
CPIP_SAT=1 CPIP_RADIO=1 CPIP_MOBILE=1 ./server.py

# Check each transport
./cpip mesh sat
./cpip mesh radio
./cpip mesh mobile
./cpip stats
```

## Docker

```bash
docker build -t cpip .
docker run -d -p 4180:4180 cpip
```

## Raspberry Pi

```bash
sudo ./deploy.sh
```

See [README.md](README.md) for full documentation.
