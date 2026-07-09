#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════
#  HTCPCP / HTCPCP-TEA  —  RFC 2324 + RFC 7168
#  Bare-metal deployment for Raspberry Pi Zero 2 WH
#  Zero containers. Zero bloat. Standard library only.
# ═══════════════════════════════════════════════════════════════════════

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

info()  { printf "${CYAN}[*]%s %s${NC}\n" "" "$1"; }
ok()    { printf "${GREEN}[OK]%s %s${NC}\n" "" "$1"; }
warn()  { printf "${YELLOW}[!]%s %s${NC}\n" "" "$1"; }
fail()  { printf "${RED}[X]%s %s${NC}\n" "" "$1"; exit 1; }

# ── Preflight ────────────────────────────────────────────────────────
[ "$(id -u)" -ne 0 ] && fail "Run as root: sudo $0"

info "Checking Python3..."
if ! command -v python3 &>/dev/null; then
    info "Installing Python3..."
    apt-get update -qq && apt-get install -y -qq python3
else
    ok "Python3 $(python3 -c 'import sys;print(sys.version.split()[0])')"
fi

# ── Write server ─────────────────────────────────────────────────────
info "Installing server -> /opt/htcpcp/server.py"
mkdir -p /opt/htcpcp

cat << 'PYEOF' > /opt/htcpcp/server.py
#!/usr/bin/env python3
"""HTCPCP/HTCPCP-TEA Server — RFC 2324 + RFC 7168

Lightweight implementation for constrained devices (Pi Zero 2 W).
Uses only the Python standard library — zero external dependencies.
"""

import json
import os
import signal
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

DEVICE_TYPE = os.environ.get("HTCPCP_DEVICE", "teapot")
BIND_ADDR = os.environ.get("HTCPCP_BIND", "0.0.0.0")
BIND_PORT = int(os.environ.get("HTCPCP_PORT", "4180"))

VALID_ADDITIONS = {
    "milk":    {"type": "dairy",     "variety": ["cream", "half-and-half", "whole", "part-skim", "skim", "non-dairy"]},
    "syrup":   {"type": "sweetener", "variety": ["vanilla", "caramel", "almond", "hazelnut", "chocolate"]},
    "sugar":   {"type": "sweetener", "variety": ["white", "brown", "raw", "honey", "artificial"]},
    "spice":   {"type": "flavoring", "variety": ["cinnamon", "cardamom", "nutmeg", "clove"]},
    "alcohol": {"type": "alcohol",   "variety": ["whisky", "rum", "kahlua", "aquavit", "brandy"]},
}

DEVICE_BEVERAGE_MAP = {
    "teapot":     ["tea"],
    "coffee-pot": ["coffee"],
    "hyper-text": ["coffee", "tea"],
}

ALCOHOL_DEVICES = {"hyper-text"}

BREW_MESSAGES = {
    "teapot":     "Your teapot is steeping. Send WHEN to stop.",
    "coffee-pot": "Your coffee pot is brewing. Send WHEN to stop.",
    "hyper-text": "Your hyper-text coffee pot is brewing. Send WHEN to stop.",
}

WHEN_MESSAGES = {
    "teapot":     "Tea is ready. Pouring stopped.",
    "coffee-pot": "Coffee is ready. Pouring stopped.",
    "hyper-text": "Beverage is ready. Pouring stopped.",
}


class PotState:
    brewing = False

    @classmethod
    def start(cls):
        cls.brewing = True

    @classmethod
    def stop(cls):
        cls.brewing = False

    @classmethod
    def is_brewing(cls):
        return cls.brewing


def parse_accept_additions(header_value: str) -> list:
    if not header_value:
        return []
    additions = []
    for token in header_value.split(","):
        token = token.strip()
        if not token:
            continue
        parts = token.split(";")
        name = parts[0].strip().lower()
        variety = None
        for part in parts[1:]:
            part = part.strip().lower()
            if part.startswith("variety="):
                variety = part.split("=", 1)[1].strip()
        additions.append({"name": name, "variety": variety})
    return additions


def check_additions(additions: list, device_type: str):
    allows_alcohol = device_type in ALCOHOL_DEVICES
    for addn in additions:
        name = addn["name"]
        if name not in VALID_ADDITIONS:
            return False, f"Unknown addition type: {name}"
        addn_def = VALID_ADDITIONS[name]
        if addn_def["type"] == "alcohol" and not allows_alcohol:
            return False, f"Device type '{device_type}' does not support alcohol additions"
        if addn["variety"] and addn["variety"] not in addn_def["variety"]:
            return False, f"Unknown variety '{addn['variety']}' for addition '{name}'"
    return True, None


def is_beverage_compatible(request_path: str, device_type: str) -> bool:
    allowed = DEVICE_BEVERAGE_MAP.get(device_type, ["tea"])
    path = urlparse(request_path).path.rstrip("/")
    if path.endswith("/coffee"):
        return "coffee" in allowed
    if path.endswith("/tea"):
        return "tea" in allowed
    return True


class HTCPCPHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        sys.stderr.write(f"[HTCPCP] {self.client_address[0]} {fmt % args}\n")

    def _json(self, code, reason, body: dict, extra_headers: dict = None):
        self.send_response(code, reason)
        payload = json.dumps(body, indent=2).encode()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/")
        if path in ("", "/"):
            self._json(200, "OK", {
                "device": DEVICE_TYPE,
                "brewing": PotState.is_brewing(),
                "protocol": "HTCPCP/1.0 (RFC 2324) + HTCPCP-TEA (RFC 7168)",
                "endpoints": {
                    "/":             "Server status (this page)",
                    "/coffee":       "BREW coffee (RFC 2324)",
                    "/tea":           "BREW tea (RFC 7168)",
                    "BREW method":    "Start brewing (POST accepted as fallback)",
                    "WHEN method":   "Stop pouring",
                    "PROPFIND":      "Pot metadata (RFC 2324 §3)",
                },
            })
        else:
            self._json(404, "Not Found", {"error": "Unknown endpoint", "path": path})

    def do_PROPFIND(self):
        self._json(200, "OK", {
            "device": DEVICE_TYPE,
            "brewing": PotState.is_brewing(),
            "additions_supported": list(VALID_ADDITIONS.keys()),
            "addition_details": {k: v["variety"] for k, v in VALID_ADDITIONS.items()},
            "beverages": DEVICE_BEVERAGE_MAP.get(DEVICE_TYPE, ["tea"]),
            "allows_alcohol": DEVICE_TYPE in ALCOHOL_DEVICES,
        })

    def _brew(self):
        if not is_beverage_compatible(self.path, DEVICE_TYPE):
            self._json(418, "I'm a teapot", {
                "error": "I'm a teapot",
                "status": 418,
                "reason": f"Device type '{DEVICE_TYPE}' cannot brew the requested beverage",
                "device": DEVICE_TYPE,
                "hint": f"Try /tea" if DEVICE_TYPE == "teapot" else f"Try /coffee",
            })
            return

        additions_header = self.headers.get("Accept-Additions", "")
        additions = parse_accept_additions(additions_header)

        ok, reason = check_additions(additions, DEVICE_TYPE)
        if not ok:
            self._json(418, "I'm a teapot", {
                "error": "I'm a teapot",
                "status": 418,
                "reason": reason,
                "device": DEVICE_TYPE,
            })
            return

        PotState.start()
        addition_names = [
            a["name"] + (f";variety={a['variety']}" if a.get("variety") else "")
            for a in additions
        ]

        safe_val = additions_header.replace("\r", "").replace("\n", "") if additions_header else ""
        self._json(202, "Brewing", {
            "status": "brewing",
            "device": DEVICE_TYPE,
            "additions": addition_names if addition_names else ["none"],
            "message": BREW_MESSAGES.get(DEVICE_TYPE, "Brewing started. Send WHEN to stop."),
        }, extra_headers={
            "Accept-Additions": safe_val,
            "Safe": "yes" if additions else "no",
        })

    def do_BREW(self):
        self._brew()

    def do_POST(self):
        self._brew()

    def do_WHEN(self):
        was_brewing = PotState.is_brewing()
        PotState.stop()
        self._json(200, "OK", {
            "status": "stopped",
            "device": DEVICE_TYPE,
            "was_brewing": was_brewing,
            "message": WHEN_MESSAGES.get(DEVICE_TYPE, "Pouring stopped."),
        })


def shutdown(signum, frame):
    print("\n[HTCPCP] Shutting down...", flush=True)
    sys.exit(0)


def main():
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    server = HTTPServer((BIND_ADDR, BIND_PORT), HTCPCPHandler)
    bev = DEVICE_BEVERAGE_MAP.get(DEVICE_TYPE, ["tea"])
    print(f"[HTCPCP] {DEVICE_TYPE} online @ {BIND_ADDR}:{BIND_PORT}", flush=True)
    print(f"[HTCPCP] Beverages: {', '.join(bev)}", flush=True)
    print(f"[HTCPCP] Alcohol:   {'yes' if DEVICE_TYPE in ALCOHOL_DEVICES else 'no'}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        print("[HTCPCP] Stopped.", flush=True)


if __name__ == "__main__":
    main()
PYEOF

chmod +x /opt/htcpcp/server.py
ok "server.py written"

# ── Write CLI client ─────────────────────────────────────────────────
info "Installing CLI -> /usr/local/bin/htcpcp"

cat << 'CLIEOF' > /usr/local/bin/htcpcp
#!/usr/bin/env bash
set -euo pipefail

HTCPCP_HOST="${HTCPCP_HOST:-localhost}"
HTCPCP_PORT="${HTCPCP_PORT:-4180}"

die() { echo "error: $*" >&2; exit 1; }

usage() {
cat << 'HELP'
htcpcp — Command-line client for HTCPCP/HTCPCP-TEA (RFC 2324 + RFC 7168)

Usage:
  htcpcp status                          Show server status
  htcpcp brew [tea|coffee] [additions]   Start brewing
  htcpcp pour [tea|coffee] [additions]   Alias for brew
  htcpcp when                            Stop pouring
  htcpcp info                            Pot metadata (PROPFIND)
  htcpcp 418                             Trigger 418 (brew coffee on a teapot)
  htcpcp 418-alcohol                     Trigger 418 (alcohol on a teapot)
  htcpcp additions                       List supported addition types
  htcpcp help                            Show this help

Addition syntax:
  milk;variety=whole,syrup;variety=vanilla,sugar;variety=raw

Environment:
  HTCPCP_HOST   Server hostname (default: localhost)
  HTCPCP_PORT   Server port     (default: 4180)
HELP
}

base_url() { echo "http://${HTCPCP_HOST}:${HTCPCP_PORT}"; }

brew_req() {
    local beverage="$1"; shift
    local url="/${beverage}"
    local header="${1:-}"
    echo "Brewing ${beverage}..."
    if [ -n "$header" ]; then
        echo "Additions: ${header#Accept-Additions: }"
    fi
    echo "---"
    if [ -n "$header" ]; then
        curl -sS -w "\n---\nHTTP %{http_code}\n" -X BREW -H "$header" "$(base_url)${url}" 2>/dev/null || \
        curl -sS -w "\n---\nHTTP %{http_code}\n" -X POST -H "$header" "$(base_url)${url}" 2>/dev/null || \
        die "Cannot connect to $(base_url)"
    else
        curl -sS -w "\n---\nHTTP %{http_code}\n" -X BREW "$(base_url)${url}" 2>/dev/null || \
        curl -sS -w "\n---\nHTTP %{http_code}\n" -X POST "$(base_url)${url}" 2>/dev/null || \
        die "Cannot connect to $(base_url)"
    fi
}

case "${1:-help}" in

    status)
        echo "Server status:"
        echo "---"
        curl -sS -w "\n---\nHTTP %{http_code}\n" "$(base_url)/" 2>/dev/null || die "Cannot connect to $(base_url)"
        ;;

    brew|pour)
        beverage="${2:-tea}"
        header=""
        if [ $# -ge 3 ]; then
            header="Accept-Additions: $3"
        fi
        brew_req "$beverage" "$header"
        ;;

    when)
        echo "Stopping pour..."
        echo "---"
        curl -sS -w "\n---\nHTTP %{http_code}\n" -X WHEN "$(base_url)/" 2>/dev/null || \
        die "Cannot connect to $(base_url)"
        ;;

    info)
        echo "Pot metadata:"
        echo "---"
        curl -sS -w "\n---\nHTTP %{http_code}\n" -X PROPFIND "$(base_url)/" 2>/dev/null || \
        die "Cannot connect to $(base_url)"
        ;;

    418)
        echo "Triggering 418 I'm a teapot (brewing coffee on a teapot)..."
        echo "---"
        curl -sS -w "\n---\nHTTP %{http_code}\n" -X BREW "$(base_url)/coffee" 2>/dev/null || \
        curl -sS -w "\n---\nHTTP %{http_code}\n" -X POST "$(base_url)/coffee" 2>/dev/null || \
        die "Cannot connect to $(base_url)"
        ;;

    418-alcohol)
        echo "Triggering 418 I'm a teapot (alcohol on a teapot)..."
        echo "---"
        curl -sS -w "\n---\nHTTP %{http_code}\n" -X BREW -H "Accept-Additions: alcohol;variety=rum" "$(base_url)/tea" 2>/dev/null || \
        curl -sS -w "\n---\nHTTP %{http_code}\n" -X POST -H "Accept-Additions: alcohol;variety=rum" "$(base_url)/tea" 2>/dev/null || \
        die "Cannot connect to $(base_url)"
        ;;

    additions)
        echo "Supported addition types (RFC 2324 §2.2.2 + RFC 7168):"
        echo ""
        echo "  Name      Category    Varieties"
        echo "  ----      --------    ----------"
        echo "  milk      dairy        cream, half-and-half, whole, part-skim, skim, non-dairy"
        echo "  syrup     sweetener    vanilla, caramel, almond, hazelnut, chocolate"
        echo "  sugar     sweetener    white, brown, raw, honey, artificial"
        echo "  spice     flavoring    cinnamon, cardamom, nutmeg, clove"
        echo "  alcohol   alcohol      whisky, rum, kahlua, aquavit, brandy (hyper-text only)"
        ;;

    help|--help|-h)
        usage
        ;;

    *)
        die "Unknown command: $1\nRun 'htcpcp help' for usage."
        ;;
esac
CLIEOF

chmod +x /usr/local/bin/htcpcp
ok "htcpcp CLI installed"

# ── Write systemd service ────────────────────────────────────────────
info "Creating systemd service..."
cat << 'SVCEOF' > /etc/systemd/system/htcpcp.service
[Unit]
Description=HTCPCP/HTCPCP-TEA Server (RFC 2324 + RFC 7168)
After=network.target

[Service]
Type=simple
Environment=HTCPCP_DEVICE=teapot
Environment=HTCPCP_BIND=0.0.0.0
Environment=HTCPCP_PORT=4180
ExecStart=/usr/bin/python3 /opt/htcpcp/server.py
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
ok "systemd unit installed"

# ── Start service ────────────────────────────────────────────────────
info "Starting htcpcp service..."
systemctl enable htcpcp.service
systemctl start htcpcp.service
sleep 1
if systemctl is-active --quiet htcpcp.service; then
    ok "Service is running"
else
    fail "Service failed to start — check: journalctl -u htcpcp"
fi

# ── Summary ──────────────────────────────────────────────────────────
DEVICE=$(grep HTCPCP_DEVICE /etc/systemd/system/htcpcp.service | head -1 | cut -d= -f3)
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  HTCPCP Server Deployed Successfully${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Device     : ${DEVICE}"
echo "  Listen     : 0.0.0.0:4180"
echo "  Server     : /opt/htcpcp/server.py"
echo "  CLI        : /usr/local/bin/htcpcp"
echo "  Service    : htcpcp.service"
echo ""
echo -e "${CYAN}  CLI Commands:${NC}"
echo "    htcpcp status              # GET / — server status"
echo "    htcpcp brew tea            # BREW /tea — start tea"
echo "    htcpcp pour tea milk;variety=whole  # BREW with additions"
echo "    htcpcp brew coffee         # BREW /coffee — start coffee"
echo "    htcpcp when                # WHEN — stop pouring"
echo "    htcpcp info                # PROPFIND — pot metadata"
echo "    htcpcp 418                 # Trigger 418 (coffee on teapot)"
echo "    htcpcp 418-alcohol         # Trigger 418 (alcohol on teapot)"
echo "    htcpcp additions           # List supported additions"
echo ""
echo -e "${CYAN}  Service Commands:${NC}"
echo "    systemctl status htcpcp"
echo "    systemctl stop htcpcp"
echo "    systemctl restart htcpcp"
echo "    journalctl -u htcpcp -f"
echo ""
echo -e "${CYAN}  Change device type:${NC}"
echo "    Edit Environment=HTCPCP_DEVICE= in /etc/systemd/system/htcpcp.service"
echo "    Then: systemctl daemon-reload && systemctl restart htcpcp"
echo "    Options: teapot (default), coffee-pot, hyper-text"
echo ""
echo -e "${CYAN}  Remote testing (replace <PI_IP>):${NC}"
echo '    curl -X BREW http://<PI_IP>:4180/tea'
echo '    curl -X BREW http://<PI_IP>:4180/coffee'
echo '    curl -X BREW -H "Accept-Additions: milk;variety=whole" http://<PI_IP>:4180/tea'
echo '    curl -X BREW -H "Accept-Additions: alcohol;variety=rum" http://<PI_IP>:4180/tea'
echo '    curl -X WHEN http://<PI_IP>:4180/'
echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"