#!/usr/bin/env bash
# ── CPIP Cluster Launcher ─────────────────────────────────────────────
# Launch multiple CPIP mesh nodes on a single machine for testing.
# Each node gets its own port, POT_ID, and mesh port.
#
# Usage:
#   ./cluster.sh start [nodes]    Start a cluster (default: 3 nodes)
#   ./cluster.sh stop             Stop all nodes
#   ./cluster.sh status           Show cluster status
#   ./cluster.sh connect          Mesh-connect all nodes
#   ./cluster.sh demo             Run a full demo (start + connect + test)
#
# Architecture:
#   Node 0: HTTP 4180, Mesh 4191 (gateway)
#   Node 1: HTTP 4181, Mesh 4192
#   Node 2: HTTP 4182, Mesh 4193
#   ...
# ──────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Trap Cleanup (Command Line Kung Fu, p.93-95) ─────────────────────
CLUSTER_DIR="/tmp/cpip-cluster"
LOG_DIR="$CLUSTER_DIR/logs"
PID_DIR="$CLUSTER_DIR/pids"
TLS_CERT_DIR="$CLUSTER_DIR/certs"

cleanup() {
    local exit_code=$?
    if [ "$exit_code" -ne 0 ]; then
        echo -e "${RED:-}[cluster] Script exited with code $exit_code${NC:-}" >&2
    fi
    return "$exit_code"
}
trap cleanup EXIT

# ── Color Helpers (p.20-22) ──────────────────────────────────────────
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

NODES=${1:-3}
SERVER_SCRIPT="$(dirname "$0")/server.py"

banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
  ██████╗██████╗  ██████╗ ███████╗██╗████████╗
 ██╔════╝██╔══██╗██╔═══██╗██╔════╝██║╚══██╔══╝
 ██║     ██████╔╝██║   ██║███████╗██║   ██║
 ██║     ██╔══██╗██║   ██║╚════██║██║   ██║
 ╚██████╗██║  ██║╚██████╔╝███████║██║   ██║
  ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █ CLUSTER LAUNCHER — Multi-Node Testing █
   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
EOF
    echo -e "${NC}"
}

log() { echo -e "${GREEN}[cluster]${NC} $*"; }
warn() { echo -e "${YELLOW}[cluster]${NC} $*"; }
err() { echo -e "${RED}[cluster]${NC} $*" >&2; }

ensure_dirs() {
    mkdir -p "$CLUSTER_DIR" "$LOG_DIR" "$PID_DIR" "$TLS_CERT_DIR"
}

generate_certs() {
    log "Generating TLS certificates for cluster..."
    if command -v openssl &>/dev/null; then
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
            -days 1 -nodes -keyout "$TLS_CERT_DIR/server.key" \
            -out "$TLS_CERT_DIR/server.crt" \
            -subj "/CN=cpip-cluster/O=CPIP" 2>/dev/null
        for i in $(seq 0 $((NODES - 1))); do
            cp "$TLS_CERT_DIR/server.crt" "$TLS_CERT_DIR/node${i}.crt"
            cp "$TLS_CERT_DIR/server.key" "$TLS_CERT_DIR/node${i}.key"
        done
        log "Certificates generated in $TLS_CERT_DIR"
    else
        warn "openssl not found, nodes will use self-signed certs"
    fi
}

start_node() {
    local i=$1
    local http_port=$((4180 + i))
    local mesh_port=$((4191 + i))
    local pid_file="$PID_DIR/node${i}.pid"
    local log_file="$LOG_DIR/node${i}.log"
    local pot_id=$(printf '%08x' $((RANDOM * RANDOM + i)))
    local hostname="pi-node-${i}"

    if [ -f "$pid_file" ] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
        warn "Node $i already running (PID $(cat "$pid_file"))"
        return
    fi

    export CPIP_PORT="$http_port"
    export MESH_PORT="$mesh_port"
    export MESH_ENABLED="true"
    export MESH_HEARTBEAT="10"
    export MESH_TTL="5"
    export COVERT_ENABLED="false"
    export SATELLITE_ENABLED="false"
    export MOBILE_ENABLED="false"
    export RADIO_ENABLED="false"
    export SSL_ENABLED="true"
    export SSL_AUTO_CERT="true"
    export SSL_CERT_DIR="$TLS_CERT_DIR"
    export NTP_SYNC="false"
    export PITAIL_ENABLED="false"
    export THERMOS_ENABLED="false"
    export COVERAGE_TRAFFIC="false"

    if [ -f "$TLS_CERT_DIR/node${i}.crt" ]; then
        export SSL_CERT="$TLS_CERT_DIR/node${i}.crt"
        export SSL_KEY="$TLS_CERT_DIR/node${i}.key"
    fi

    if [ "$i" -eq 0 ]; then
        export HTTP_REDIRECT="false"
    else
        export HTTP_REDIRECT="false"
    fi

    MESH_PEERS=""
    if [ "$i" -gt 0 ]; then
        MESH_PEERS="127.0.0.1:$((4191))"
    fi

    MESH_BOOTSTRAP="$MESH_PEERS" nohup python3 "$SERVER_SCRIPT" \
        > "$log_file" 2>&1 &
    local pid=$!
    echo "$pid" > "$pid_file"

    sleep 1
    if kill -0 "$pid" 2>/dev/null; then
        log "Node $i: HTTP :$http_port | Mesh :$mesh_port | PID $pid | $log_file"
    else
        err "Node $i failed to start. Check $log_file"
        rm -f "$pid_file"
    fi
}

cmd_start() {
    local count=${1:-$NODES}
    NODES=$count
    ensure_dirs
    banner
    log "Starting CPIP cluster with $NODES nodes..."
    echo ""
    generate_certs
    echo ""

    for i in $(seq 0 $((NODES - 1))); do
        start_node $i
    done

    echo ""
    log "Cluster started. Nodes:"
    for i in $(seq 0 $((NODES - 1))); do
        local http_port=$((4180 + i))
        local mesh_port=$((4191 + i))
        echo -e "  ${BLUE}Node $i${NC}: http://localhost:${http_port}/dashboard | mesh UDP :${mesh_port}"
    done
    echo ""
    log "Run '$0 connect' to mesh-connect all nodes"
    log "Run '$0 status' to check cluster health"
}

cmd_stop() {
    log "Stopping all CPIP nodes..."
    local stopped=0
    for pid_file in "$PID_DIR"/*.pid; do
        [ -f "$pid_file" ] || continue
        local pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
            sleep 0.5
            if kill -0 "$pid" 2>/dev/null; then
                kill -9 "$pid" 2>/dev/null
            fi
            stopped=$((stopped + 1))
        fi
        rm -f "$pid_file"
    done
    log "Stopped $stopped nodes"
}

cmd_status() {
    banner
    echo -e "${CYAN}Cluster Status${NC}"
    echo "────────────────────────────────────────────────"
    local running=0
    local status_lines=""
    for i in $(seq 0 $((NODES - 1))); do
        local pid_file="$PID_DIR/node${i}.pid"
        local http_port=$((4180 + i))
        local mesh_port=$((4191 + i))
        if [ -f "$pid_file" ] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
            local status=$(curl -sk "https://localhost:${http_port}/cpip/status" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','unknown'))" 2>/dev/null || echo "unreachable")
            echo -e "  ${GREEN}●${NC} Node $i: HTTP :$http_port | Mesh :$mesh_port | $status"
            running=$((running + 1))
        else
            echo -e "  ${RED}●${NC} Node $i: HTTP :$http_port | Mesh :$mesh_port | stopped"
        fi
    done
    echo ""
    echo -e "Running: ${GREEN}$running${NC} / $NODES"
    echo "────────────────────────────────────────────────"
}

cmd_connect() {
    local target="${1:-}"
    if [ -n "$target" ]; then
        local http_port=$((4180 + target))
        log "Mesh-connecting node $target to gateway (node 0)..."
        curl -sk -X POST "https://localhost:${http_port}/cpip/mesh/send" \
            -H "Content-Type: application/json" \
            -d "{\"dst\": \"$(printf '%08x' 0)\", \"message\": \"Cluster connect from node $target\"}" \
            2>/dev/null || warn "  Node $target not reachable"
        sleep 2
        local peers=$(curl -sk "https://localhost:${http_port}/cpip/mesh/peers" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('peers',{})))" 2>/dev/null || echo "?")
        echo -e "  Node $target: ${peers} peers"
        return
    fi
    log "Mesh-connecting all nodes via peer discovery..."
    for i in $(seq 1 $((NODES - 1))); do
        local http_port=$((4180 + i))
        log "  Connecting node $i to gateway (node 0)..."
        curl -sk -X POST "https://localhost:${http_port}/cpip/mesh/send" \
            -H "Content-Type: application/json" \
            -d "{\"dst\": \"$(printf '%08x' 0)\", \"message\": \"Cluster connect from node $i\"}" \
            2>/dev/null || warn "  Node $i not reachable"
    done
    sleep 2
    log "Checking mesh peer lists..."
    for i in $(seq 0 $((NODES - 1))); do
        local http_port=$((4180 + i))
        local peers=$(curl -sk "https://localhost:${http_port}/cpip/mesh/peers" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('peers',{})))" 2>/dev/null || echo "?")
        echo -e "  Node $i: ${peers} peers"
    done
}

cmd_demo() {
    banner
    log "Running full cluster demo..."
    echo ""

    cmd_stop 2>/dev/null || true
    cmd_start "${1:-3}"
    echo ""

    log "Waiting for nodes to stabilize..."
    sleep 3

    cmd_connect
    echo ""

    log "Registering DNS names..."
    for i in $(seq 0 $((NODES - 1))); do
        local http_port=$((4180 + i))
        curl -sk -X POST "https://localhost:${http_port}/cpip/dns/register" \
            -H "Content-Type: application/json" \
            -d "{\"name\": \"pi-${i}.pot\"}" \
            2>/dev/null || true
    done
    echo ""

    log "Publishing identities..."
    for i in $(seq 0 $((NODES - 0))); do
        local http_port=$((4180 + i))
        curl -sk -X POST "https://localhost:${http_port}/cpip/identity/publish" \
            -H "Content-Type: application/json" \
            -d '{}' \
            2>/dev/null || true
    done
    echo ""

    log "Creating group chat..."
    curl -sk -X POST "https://localhost:4180/cpip/groups/create" \
        -H "Content-Type: application/json" \
        -d '{"name": "Cluster Chat", "members": []}' \
        2>/dev/null || true
    echo ""

    log "Sending test messages..."
    for i in $(seq 0 2); do
        local http_port=$((4180 + i))
        curl -sk -X POST "https://localhost:${http_port}/cpip/sync/send" \
            -H "Content-Type: application/json" \
            -d "{\"channel\": \"general\", \"payload\": \"Hello from node $i!\"}" \
            2>/dev/null || true
    done
    echo ""

    log "Syncing clocks..."
    for i in $(seq 0 $((NODES - 1))); do
        local http_port=$((4180 + i))
        curl -sk "https://localhost:${http_port}/cpip/sync/clocks" 2>/dev/null | \
            python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  Node {$i}: {len(d)} clock entries')" 2>/dev/null || true
    done
    echo ""

    cmd_status
    echo ""

    echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Demo complete! Dashboards available at:${NC}"
    for i in $(seq 0 $((NODES - 1))); do
        local http_port=$((4180 + i))
        echo -e "  ${CYAN}  https://localhost:${http_port}/dashboard${NC}"
    done
    echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
}

cmd_help() {
    cat << 'HELP'
CPIP Cluster Launcher — Multi-Node Mesh Testing

Usage:
  ./cluster.sh start [N]     Start N nodes (default: 3)
  ./cluster.sh stop          Stop all nodes
  ./cluster.sh status        Show cluster health
  ./cluster.sh connect [N]   Mesh-connect all nodes (or just node N to gateway)
  ./cluster.sh demo          Full demo: start + connect + test
  ./cluster.sh help          This message

Node Layout:
  Node 0: HTTP :4180, Mesh UDP :4191 (gateway)
  Node 1: HTTP :4181, Mesh UDP :4192
  Node 2: HTTP :4182, Mesh UDP :4193
  ...

All nodes run on localhost with TLS (auto-generated certs).
Mesh network uses UDP peer-to-peer discovery.
HELP
}

case "${1:-help}" in
    start)  cmd_start "${2:-3}" ;;
    stop)   cmd_stop ;;
    status) cmd_status ;;
    connect) cmd_connect "$2" ;;
    demo)   cmd_demo "${2:-3}" ;;
    help|*) cmd_help ;;
esac
