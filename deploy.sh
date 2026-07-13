#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════
#  CPIP — Coffee Pot Internet Protocol v2.2
#  RFC 2324 + RFC 7168 + Ed25519 ECC + ML-KEM-768 + Mesh + 418 Defense
#  Full hardware install for Raspberry Pi Zero WH
#  Zero simulation. Post-quantum ready. All fangs.
# ═══════════════════════════════════════════════════════════════════════

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

info()  { printf "${CYAN}[*]%s %s${NC}\n" "" "$1"; }
ok()    { printf "${GREEN}[OK]%s %s${NC}\n" "" "$1"; }
warn()  { printf "${YELLOW}[!]%s %s${NC}\n" "" "$1"; }
fail()  { printf "${RED}[X]%s %s${NC}\n" "" "$1"; exit 1; }

# ── Preflight ────────────────────────────────────────────────────────
[ "$(id -u)" -ne 0 ] && fail "Run as root: sudo $0"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVER_SRC="${SCRIPT_DIR}/server.py"
CLI_SRC="${SCRIPT_DIR}/htcpcp"

[ ! -f "$SERVER_SRC" ] && fail "server.py not found at $SERVER_SRC"
[ ! -f "$CLI_SRC" ] && fail "htcpcp CLI not found at $CLI_SRC"

info "Checking Python3..."
if ! command -v python3 &>/dev/null; then
    info "Installing Python3..."
    apt-get update -qq && apt-get install -y -qq python3
else
    ok "Python3 $(python3 -c 'import sys;print(sys.version.split()[0])')"
fi

# ── Build radio interface ──────────────────────────────────────────────
info "Building radio interface..."
if [ -d "${SCRIPT_DIR}/radio" ]; then
    cd "${SCRIPT_DIR}/radio"
    if make 2>/dev/null; then
        ok "Radio interface built (LoRa SX1276 + KISS TNC + RTL-SDR)"
        # Build RTL-SDR variant if librtlsdr is available
        if pkg-config --exists librtlsdr 2>/dev/null || [ -f /usr/lib/*/librtlsdr.so ]; then
            make rtl 2>/dev/null && ok "RTL-SDR support compiled" || warn "RTL-SDR build skipped"
        fi
    else
        warn "Radio interface build failed — install gcc and run: cd radio/ && make"
    fi
    cd "$SCRIPT_DIR"
else
    warn "No radio/ directory found — radio features disabled"
fi
info "Installing RPi.GPIO (hardware GPIO — no simulation)..."
if python3 -c "import RPi.GPIO" 2>/dev/null; then
    ok "RPi.GPIO already installed"
else
    apt-get install -y -qq python3-rpi.gpio || \
        pip3 install RPi.GPIO 2>/dev/null || \
        warn "Could not install RPi.GPIO — GPIO features disabled (CPIP_GPIO=0)"
fi

# ── Install server ───────────────────────────────────────────────────
info "Installing server -> /opt/cpip/server.py"
mkdir -p /opt/cpip
cp "$SERVER_SRC" /opt/cpip/server.py
chmod +x /opt/cpip/server.py
ok "server.py installed"

# ── Install CLI ──────────────────────────────────────────────────────
info "Installing CLI -> /usr/local/bin/htcpcp"
cp "$CLI_SRC" /usr/local/bin/htcpcp
chmod +x /usr/local/bin/htcpcp
ok "htcpcp CLI installed"

# ── Install web dashboard (if web/ directory exists) ─────────────────
if [ -d "${SCRIPT_DIR}/web" ]; then
    info "Installing web dashboard..."
    mkdir -p /opt/cpip/web
    cp -r "${SCRIPT_DIR}/web/"* /opt/cpip/web/
    ok "Web dashboard installed"
else
    warn "No web/ directory found — dashboard is embedded in server.py"
fi

# ── Install Pi-Apps package (if present) ─────────────────────────────
if [ -d "${SCRIPT_DIR}/pi-apps" ]; then
    PI_APPS_DIR="/usr/local/share/pi-apps/apps/Coffee-Protocol"
    info "Installing Pi-Apps package -> ${PI_APPS_DIR}"
    mkdir -p "$PI_APPS_DIR"
    cp -r "${SCRIPT_DIR}/pi-apps/"* "$PI_APPS_DIR/"
    chmod +x "$PI_APPS_DIR/install" "$PI_APPS_DIR/uninstall" 2>/dev/null || true
    ok "Pi-Apps package installed"
fi

# ── Systemd service ──────────────────────────────────────────────────
info "Creating systemd service..."
cat << 'SVCEOF' > /etc/systemd/system/cpip.service
[Unit]
Description=CPIP v2.2 — Coffee Pot Internet Protocol (ECC + Mesh + 418 + Multi-Transport)
Documentation=https://github.com/coffee-protocol/cpip
After=network.target

[Service]
Type=simple
Environment=CPIP_DEVICE=hyper-text
Environment=CPIP_BIND=0.0.0.0
Environment=CPIP_PORT=4180
Environment=CPIP_MESH=1
Environment=CPIP_MESH_PORT=4191
Environment=CPIP_COVERT=1
Environment=CPIP_COVERT_KEY=
Environment=CPIP_COVER_TRAFFIC=1
Environment=CPIP_AVAHI=1
Environment=CPIP_GPIO=1
Environment=CPIP_NTP=1
Environment=CPIP_MESH_STEALTH=0
Environment=CPIP_THERMOS=0
Environment=CPIP_PITAIL=0
ExecStart=/usr/bin/python3 /opt/cpip/server.py
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
ok "Systemd unit created with full feature set"

# ── Start service ────────────────────────────────────────────────────
info "Starting cpip service..."
systemctl enable cpip.service
systemctl start cpip.service
sleep 2
if systemctl is-active --quiet cpip.service; then
    ok "Service is running"
else
    warn "Service may not have started — check: journalctl -u cpip -n 50 --no-pager"
fi

# ── Summary ──────────────────────────────────────────────────────────
IP_ADDR=$(hostname -I | awk '{print $1}')
POT_ID=$(python3 -c "import hashlib; print(hashlib.sha256(b'$(hostname):4180').hexdigest()[:8])")
ECC_ADDR=$(python3 -c "
import hashlib, base64
seed = hashlib.md5(b'CHANGE_ME_COFFEE_BLEND_2024' + b'$(hostname):4180').digest()
exec(open('/opt/cpip/server.py').read())
pk, seed, _, _ = Ed25519.generate_keypair(hashlib.sha256(seed + b'ed25519').digest())
print(Ed25519.pubkey_to_address(pk))
" 2>/dev/null || echo "(start server to see address)")

echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  CPIP v2.2 Deployed — Post-Quantum Ready${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Device     : hyper-text (coffee + tea)"
echo "  Pot ID     : ${POT_ID}"
echo "  ECC Addr   : ${ECC_ADDR}"
echo "  Listen     : 0.0.0.0:4180"
echo "  Mesh Port  : 4191 (UDP)"
echo "  Latent     : 4192, 4193, 4194 (port-knocking)"
  echo "  Defense    : 418 I'm a Teapot (probe + pentest tool blocking)"
echo "  Cipher     : CoffeeCipher v2 (SHA-256+HMAC+IV) + Ed25519 + ML-KEM-768"
echo "  PQ-KEM     : Hybrid ECDH + ML-KEM-768 (256-bit PQ security)"
echo "  Hash       : SHA-256 + SHA-3-256"
echo "  Incident IR: Auto-detection + mitigation"
echo "  GPIO       : RPi.GPIO Pin 17 (hardware only — no simulation)"
echo "  Server     : /opt/cpip/server.py"
echo "  CLI        : /usr/local/bin/htcpcp"
echo "  Service    : cpip.service"
echo ""
echo -e "${CYAN}  Dashboard:${NC}"
echo "    http://${IP_ADDR}:4180/dashboard"
echo ""
echo -e "${CYAN}  CLI Commands:${NC}"
echo "    htcpcp status                    # Server status"
echo "    htcpcp brew coffee               # Brew coffee"
echo "    htcpcp brew tea                  # Brew tea"
echo "    htcpcp when                      # Stop brewing"
echo "    htcpcp info                      # Pot metadata"
echo "    htcpcp mesh scan                 # Scan mesh for peers"
echo "    htcpcp mesh peers                # List mesh peers"
echo "    htcpcp mesh inbox                # Read mesh messages"
echo "    htcpcp mesh send <pot> <msg>     # Send mesh message"
echo "    htcpcp mesh broadcast <msg>      # Broadcast to mesh"
echo "    htcpcp covert encode <msg>       # Encode covert message (ECC)"
echo "    htcpcp covert decode <header>    # Decode covert header"
echo "    htcpcp covert brew <msg>         # Brew with hidden message"
echo ""
echo -e "${CYAN}  Env Overrides:${NC}"
echo "    CPIP_GPIO=1          # Enable RPi.GPIO pin 17 (default)"
echo "    CPIP_MESH=1          # Enable mesh (default)"
echo "    CPIP_MESH_STEALTH=0  # Stealth mode (no broadcast heartbeats)"
echo "    CPIP_THERMOS=0       # Aggregator node for encrypted dead-drops"
echo "    CPIP_PITAIL=0        # USB gadget mode (Pi Zero → host)"
echo "    CPIP_COVERT_KEY=...  # CHANGE THIS for production"
echo ""
echo -e "${CYAN}  Remote testing (from another machine):${NC}"
echo '    curl -X BREW http://'${IP_ADDR}':4180/coffee'
echo '    curl -X BREW -H "Accept-Additions: milk;variety=whole" http://'${IP_ADDR}':4180/tea'
echo '    curl http://'${IP_ADDR}':4180/cpip/mesh/status'
echo ""
echo -e "${YELLOW}  ⚠  CRYPTOGRAPHY NOTICE${NC}"
echo "  This software uses a hybrid cryptographic architecture:"
echo "  - CoffeeCipher v2: SHA-256+HMAC authenticated encryption (custom)"
echo "  - Ed25519: Pure Python ECC (NOT constant-time — side-channel risk)"
echo "  - ML-KEM-768: Post-quantum key encapsulation (lattice-based)"
echo "  - SHA-3-256: Tamper-evident audit logging"
echo "  - HMAC-SHA256: Mesh message authentication"
echo "  Does NOT comply with FIPS 140-2/3. See SECURITY.md for details."
echo ""
echo -e "${GREEN}  ☕  Brew mesh. Route covertly. Post-quantum ready. Fangs out.${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
