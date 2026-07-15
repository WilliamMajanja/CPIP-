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
./htcpcp status
./htcpcp brew tea "milk;variety=whole"
./htcpcp when

# 5. Check the mesh
./htcpcp mesh status
./htcpcp mesh peers
./htcpcp mesh scan

# 6. Send a covert message
./htcpcp covert encode "hello world"

# 7. Check defenses
./htcpcp itf status
./htcpcp itf blacklist

# 8. Post-Quantum KEM (1nf1D3L's Kyber)
./b4dm4n_cw.py keygen -o mykeys
./b4dm4n_cw.py encaps -k mykeys.pk -o ct.bin
./b4dm4n_cw.py decaps -k mykeys.sk -c ct.bin

# 9. Hybrid ECDH + Kyber (defense in depth)
./b4dm4n_cw.py hybrid-keygen -o hybrid
./b4dm4n_cw.py hybrid-encaps -k hybrid.hp -o hyb_ct.bin
./b4dm4n_cw.py hybrid-decaps -k hybrid.hs -c hyb_ct.bin
```

## With extra transports

```bash
# Enable all transports
CPIP_SAT=1 CPIP_RADIO=1 CPIP_MOBILE=1 ./server.py

# Check each transport
./htcpcp mesh sat
./htcpcp mesh radio
./htcpcp mesh mobile
./htcpcp stats
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
