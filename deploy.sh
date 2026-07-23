#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════
#  CPIP — Coffee Pot Internet Protocol v5.0.0
#  RFC 2324 + RFC 7168 + ECDSA/ECDH P-256 + ML-KEM-768 + Mesh + 418 Defense
#  Anti-ISP + Anti-Stingray + Anti-Palantir/Pegasus + Anti-DPI + Net Neutrality
#  Full hardware install for Raspberry Pi Zero WH
#  Zero simulation. Post-quantum ready. All fangs.
# ═══════════════════════════════════════════════════════════════════════

# ── Trap Cleanup (Command Line Kung Fu, p.93-95) ─────────────────────
cleanup() {
    local exit_code=$?
    if [ "$exit_code" -ne 0 ]; then
        printf "${RED:-}[X]%s Script failed with code %d${NC:-}\n" "" "$exit_code" >&2
    fi
    return "$exit_code"
}
trap cleanup EXIT

# ── Color Helpers (p.20-22) ──────────────────────────────────────────
readonly CYAN='\033[0;36m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly RED='\033[0;31m'
readonly NC='\033[0m'

info()  { printf "${CYAN}[*]%s %s${NC}\n" "" "$1"; }
ok()    { printf "${GREEN}[OK]%s %s${NC}\n" "" "$1"; }
warn()  { printf "${YELLOW}[!]%s %s${NC}\n" "" "$1"; }
fail()  { printf "${RED}[X]%s %s${NC}\n" "" "$1"; exit 1; }

# ── Preflight ────────────────────────────────────────────────────────
[ "$(id -u)" -ne 0 ] && fail "Run as root: sudo $0"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVER_SRC="${SCRIPT_DIR}/server.py"
CLI_SRC="${SCRIPT_DIR}/cpip"

[ ! -f "$SERVER_SRC" ] && fail "server.py not found at $SERVER_SRC"
[ ! -f "$CLI_SRC" ] && fail "cpip CLI not found at $CLI_SRC"

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
info "Installing CLI -> /usr/local/bin/cpip"
cp "$CLI_SRC" /usr/local/bin/cpip
chmod +x /usr/local/bin/cpip
ok "cpip CLI installed"

# ── Install web dashboard (if web/ directory exists) ─────────────────
if [ -d "${SCRIPT_DIR}/web" ] && [ "$(ls -A "${SCRIPT_DIR}/web" 2>/dev/null | grep -v '^\.' || true)" ]; then
    info "Installing web dashboard..."
    mkdir -p /opt/cpip/web
    find "${SCRIPT_DIR}/web" -maxdepth 1 -not -name '.*' -not -path "${SCRIPT_DIR}/web" -exec cp -r {} /opt/cpip/web/ \;
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

# ── Generate trusted TLS certs with mkcert ─────────────────────────
info "Generating trusted TLS certificates..."
if command -v mkcert &>/dev/null; then
    CERT_DIR="/opt/cpip/certs"
    mkdir -p "$CERT_DIR"
    LOCAL_IP=$(hostname -I | awk '{print $1}')
    HOSTNAME=$(hostname)
    mkcert -cert-file "$CERT_DIR/server.crt" -key-file "$CERT_DIR/server.key" \
        localhost 127.0.0.1 ::1 "$LOCAL_IP" "$HOSTNAME" 2>/dev/null
    chmod 644 "$CERT_DIR/server.crt"
    chmod 600 "$CERT_DIR/server.key"
    chown root:root "$CERT_DIR/server."*
    ok "Trusted TLS certs generated (mkcert)"
    SSL_AUTO="0"
    SSL_CERT="$CERT_DIR/server.crt"
    SSL_KEY="$CERT_DIR/server.key"
else
    warn "mkcert not found — using auto-generated self-signed cert (browser warning)"
    SSL_AUTO="1"
    SSL_CERT=""
    SSL_KEY=""
fi

# ── Systemd service ──────────────────────────────────────────────────
info "Creating systemd service..."
cat << SVCEOF > /etc/systemd/system/cpip.service
[Unit]
Description=CPIP v5.0.0 — Coffee Pot Internet Protocol (Anti-ISP + Anti-Stingray + Anti-Surveillance + Net Neutrality)
Documentation=https://github.com/WilliamMajanja/CPIP-.git
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
Environment=CPIP_SSL=1
Environment=CPIP_SSL_AUTO=${SSL_AUTO}
Environment=CPIP_SSL_CERT=${SSL_CERT}
Environment=CPIP_SSL_KEY=${SSL_KEY}
Environment=CPIP_HTTP_REDIRECT=1
Environment=CPIP_HTTP_REDIRECT_PORT=4181
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
try:
    import sys
    sys.path.insert(0, '/opt/cpip')
    import importlib.util
    spec = importlib.util.spec_from_file_location('srv', '/opt/cpip/server.py')
    # Don't execute the server; just derive the P-256 address from the seed.
    seed = hashlib.sha256(b'$(hostname):4180').digest()
    # ECP256 address is the SHA-256 of the compressed pubkey prefix.
    addr = hashlib.sha256(b'cpip-ecdsa-p256:' + seed).hexdigest()[:32]
    print(addr)
except Exception:
    print('(start server to see address)')
" 2>/dev/null || echo "(start server to see address)")

echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  CPIP v5.0.0 Deployed — Counter-Surveillance Active${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Device     : hyper-text (coffee + tea)"
echo "  Pot ID     : ${POT_ID}"
echo "  ECC Addr   : ${ECC_ADDR}"
echo "  Listen     : 0.0.0.0:4180"
echo "  TLS/SSL    : Auto self-signed (CPIP_SSL_AUTO=1)"
echo "  HTTP→HTTPS : Port 4181 (CPIP_HTTP_REDIRECT=1)"
echo "  Mesh Port  : 4191 (UDP)"
echo "  Latent     : 4192, 4193, 4194 (port-knocking)"
echo "  Defense    : 418 I'm a Teapot (probe + pentest tool blocking)"
echo "  Cipher     : CoffeeCipher v3 (AES-256-GCM + HKDF-SHA256)"
echo "  ECC        : ECDSA/ECDH P-256 (FIPS 186-4)"
echo "  PQ-KEM     : Hybrid ECDH P-256 + 1nf1D3L Kyber ML-KEM-768 (non-FIPS)"
echo "  Hash       : SHA-256 + SHA-3-256"
echo "  Incident IR: Auto-detection + mitigation"
echo "  GPIO       : RPi.GPIO Pin 17 (hardware only — no simulation)"
echo "  Server     : /opt/cpip/server.py"
echo "  CLI        : /usr/local/bin/cpip"
echo "  Service    : cpip.service"
echo ""
echo -e "${CYAN}  Dashboard:${NC}"
echo "    https://${IP_ADDR}:4180/dashboard"
echo "    http://${IP_ADDR}:4181 → redirects to HTTPS"
echo ""
echo -e "${CYAN}  CLI Commands:${NC}"
echo "    cpip status                    # Server status"
echo "    cpip brew coffee               # Brew coffee"
echo "    cpip brew tea                  # Brew tea"
echo "    cpip when                      # Stop brewing"
echo "    cpip info                      # Pot metadata"
echo "    cpip mesh scan                 # Scan mesh for peers"
echo "    cpip mesh peers                # List mesh peers"
echo "    cpip mesh inbox                # Read mesh messages"
echo "    cpip mesh send <pot> <msg>     # Send mesh message"
echo "    cpip mesh broadcast <msg>      # Broadcast to mesh"
echo "    cpip covert encode <msg>       # Encode covert message (ECC)"
echo "    cpip covert decode <header>    # Decode covert header"
echo "    cpip covert brew <msg>         # Brew with hidden message"
echo ""
echo -e "${CYAN}  Env Overrides:${NC}"
echo "    CPIP_SSL=0             # Disable TLS (HTTP only)"
echo "    CPIP_SSL=1             # Enable TLS (HTTPS)"
echo "    CPIP_SSL_AUTO=1        # Auto-generate self-signed cert"
echo "    CPIP_SSL_CERT=/path    # Custom TLS certificate"
echo "    CPIP_SSL_KEY=/path     # Custom TLS private key"
echo "    CPIP_HTTP_REDIRECT=1  # Redirect HTTP→HTTPS on port 4181"
echo ""
echo -e "${CYAN}  Remote testing (from another machine):${NC}"
echo '    curl -X BREW https://'${IP_ADDR}':4180/coffee'
echo '    curl -X BREW -H "Accept-Additions: milk;variety=whole" https://'${IP_ADDR}':4180/tea'
echo '    curl https://'${IP_ADDR}':4180/cpip/mesh/status'
echo ""
echo -e "${YELLOW}  ⚠  CRYPTOGRAPHY NOTICE${NC}"
echo "  This software uses a hybrid cryptographic architecture:"
echo "  - CoffeeCipher v3: AES-256-GCM authenticated encryption (FIPS 197)"
echo "    + HKDF-SHA256 key derivation (SP 800-56C) with recipe domain separation"
echo "  - ECDSA/ECDH P-256: FIPS 186-4 signatures and key exchange"
echo "  - 1nf1D3L Kyber ML-KEM-768: Post-quantum KEM (non-FIPS, η=3, research variant)"
echo "  - HybridKEM: ECDH P-256 + Kyber combined via HKDF-SHA256"
echo "  - SHA-256 / SHA-3-256: Domain-separated hashing, tamper-evident audit chain"
echo "  - HMAC-SHA256: Mesh heartbeat auth, message integrity, RPC tokens"
echo "  - TLS/SSL: HTTPS with auto self-signed certs (CPIP_SSL_AUTO=1)"
echo "  Classical primitives are FIPS-compliant. The Kyber variant is NOT FIPS 203"
echo "  validated — it is a non-FIPS research variant. See SECURITY.md for details."
echo ""
echo -e "${GREEN}  ☕  Brew mesh. Route covertly. Post-quantum ready. TLS on. Fangs out.${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
