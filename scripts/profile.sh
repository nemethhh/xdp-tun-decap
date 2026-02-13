#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# profile.sh - Integration test profiling with flame chart generation
#
# Orchestrates perf-based profiling during real XDP traffic processing:
# 1. Starts Docker containers (reuses existing docker-compose.yml)
# 2. Loads XDP program and configures whitelist
# 3. Enables BPF stats and JIT symbols
# 4. Records perf data during traffic generation
# 5. Generates flame chart SVG
# 6. Collects BPF program statistics
#
# Usage: sudo scripts/profile.sh [--quick] [--count N] [--freq F]
#
# Options:
#   --quick      Skip Docker setup/teardown (containers already running)
#   --count N    Packets per type to generate (default: 1000)
#   --freq F     Perf sampling frequency in Hz (default: 9999)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TESTS_DIR="$PROJECT_DIR/tests"
BUILD_DIR="$PROJECT_DIR/build"
PROFILE_DIR="$BUILD_DIR/profile"
FLAMEGRAPH_DIR="$PROJECT_DIR/tools/flamegraph"

# Defaults
QUICK_MODE=0
PKT_COUNT=1000
PERF_FREQ=9999

# Colors
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BOLD='\033[1m'
RESET='\033[0m'

log() { echo -e "${BOLD}[profile]${RESET} $*"; }
warn() { echo -e "${YELLOW}[profile]${RESET} $*"; }
err() { echo -e "${RED}[profile]${RESET} $*" >&2; }
ok() { echo -e "${GREEN}[profile]${RESET} $*"; }

usage() {
    cat <<EOF
Usage: sudo $0 [OPTIONS]

Profiles XDP tunnel decapsulation during real traffic processing.

Options:
  --quick      Skip Docker setup/teardown (containers already running)
  --count N    Packets per type to generate (default: $PKT_COUNT)
  --freq F     Perf sampling frequency in Hz (default: $PERF_FREQ)
  --help       Show this help

Output (in build/profile/):
  flamegraph.svg          Interactive flame chart (open in browser)
  bpf-stats.txt           BPF program runtime statistics
  bpftool-profile.txt     Per-program hardware counter stats
  perf.data               Raw perf data for further analysis
EOF
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --quick)      QUICK_MODE=1; shift ;;
        --count)      PKT_COUNT="$2"; shift 2 ;;
        --freq)       PERF_FREQ="$2"; shift 2 ;;
        --help|-h)    usage ;;
        *)            err "Unknown option: $1"; usage ;;
    esac
done

# Check root
if [[ $EUID -ne 0 ]]; then
    err "This script requires root privileges"
    echo "Run with: sudo $0"
    exit 1
fi

# Check required tools
for tool in perf bpftool docker; do
    if ! command -v "$tool" &>/dev/null; then
        err "Required tool not found: $tool"
        exit 1
    fi
done

# Check FlameGraph tools
if [[ ! -f "$FLAMEGRAPH_DIR/stackcollapse-perf.pl" ]] || \
   [[ ! -f "$FLAMEGRAPH_DIR/flamegraph.pl" ]]; then
    err "FlameGraph tools not found in $FLAMEGRAPH_DIR"
    echo "Download them:"
    echo "  curl -sL https://raw.githubusercontent.com/brendangregg/FlameGraph/master/stackcollapse-perf.pl > $FLAMEGRAPH_DIR/stackcollapse-perf.pl"
    echo "  curl -sL https://raw.githubusercontent.com/brendangregg/FlameGraph/master/flamegraph.pl > $FLAMEGRAPH_DIR/flamegraph.pl"
    echo "  chmod +x $FLAMEGRAPH_DIR/*.pl"
    exit 1
fi

# Create output directory
mkdir -p "$PROFILE_DIR"

# Track cleanup tasks
CLEANUP_TASKS=()
BPF_STATS_WAS_ENABLED=0
BPF_JIT_KALLSYMS_WAS=0
PERF_PID=0
BPFTOOL_PID=0

cleanup() {
    log "Cleaning up..."

    # Stop background processes
    if [[ $PERF_PID -ne 0 ]] && kill -0 "$PERF_PID" 2>/dev/null; then
        kill -INT "$PERF_PID" 2>/dev/null || true
        wait "$PERF_PID" 2>/dev/null || true
    fi
    if [[ $BPFTOOL_PID -ne 0 ]] && kill -0 "$BPFTOOL_PID" 2>/dev/null; then
        kill -INT "$BPFTOOL_PID" 2>/dev/null || true
        wait "$BPFTOOL_PID" 2>/dev/null || true
    fi

    # Restore sysctl settings
    if [[ $BPF_STATS_WAS_ENABLED -eq 0 ]]; then
        sysctl -qw kernel.bpf_stats_enabled=0 2>/dev/null || true
    fi
    if [[ $BPF_JIT_KALLSYMS_WAS -eq 0 ]]; then
        sysctl -qw net.core.bpf_jit_kallsyms=0 2>/dev/null || true
    fi

    # Tear down Docker if we started it
    if [[ $QUICK_MODE -eq 0 ]]; then
        log "Stopping Docker containers..."
        (cd "$TESTS_DIR" && docker compose down -v 2>/dev/null) || true
    fi

    log "Cleanup complete"
}
trap cleanup EXIT

# ===== Step 1: Build XDP program =====
log "Building XDP program..."
make -C "$PROJECT_DIR" all STATS=1 >/dev/null 2>&1

# ===== Step 2: Start Docker containers =====
if [[ $QUICK_MODE -eq 0 ]]; then
    log "Starting Docker containers..."
    (cd "$TESTS_DIR" && docker compose up -d --build 2>&1) | while IFS= read -r line; do
        echo "  [docker] $line"
    done
    sleep 2
else
    log "Quick mode: assuming containers are already running"
fi

# ===== Step 3: Enable BPF stats and JIT symbols =====
log "Enabling BPF stats and JIT kallsyms..."

# Save current settings
BPF_STATS_WAS_ENABLED=$(sysctl -n kernel.bpf_stats_enabled 2>/dev/null || echo 0)
BPF_JIT_KALLSYMS_WAS=$(sysctl -n net.core.bpf_jit_kallsyms 2>/dev/null || echo 0)

sysctl -qw kernel.bpf_stats_enabled=1
sysctl -qw net.core.bpf_jit_kallsyms=1 2>/dev/null || \
    warn "Could not enable bpf_jit_kallsyms (BPF function names may not appear in flame chart)"

# ===== Step 4: Load XDP program and configure whitelist =====
log "Loading XDP program onto target container..."

# Copy BPF object to target container
XDP_OBJECT="/build/tun_decap.bpf.o"
if ! docker compose -f "$TESTS_DIR/docker-compose.yml" exec -T xdp-target test -f "$XDP_OBJECT"; then
    err "XDP object not found in target container at $XDP_OBJECT"
    exit 1
fi

# Unload any existing XDP programs
docker compose -f "$TESTS_DIR/docker-compose.yml" exec -T xdp-target \
    xdp-loader unload eth0 --all >/dev/null 2>&1 || true
sleep 1

# Load XDP program in SKB mode (required for veth interfaces)
XDP_LOAD_OUTPUT=$(docker compose -f "$TESTS_DIR/docker-compose.yml" exec -T xdp-target \
    xdp-loader load -m skb --pin-path /sys/fs/bpf eth0 "$XDP_OBJECT" -s xdp 2>&1)
XDP_LOAD_EXIT=$?

if [ $XDP_LOAD_EXIT -ne 0 ]; then
    err "Failed to load XDP program:"
    echo "$XDP_LOAD_OUTPUT"
    exit 1
fi

log "Configuring whitelist for tunnel-source (10.200.0.20, fd00:db8:1::20)..."

# Add IPv4 whitelist entry (10.200.0.20 = 0a c8 00 14)
docker compose -f "$TESTS_DIR/docker-compose.yml" exec -T xdp-target \
    bpftool map update pinned /sys/fs/bpf/tun_decap_whitelist \
    key hex 0a c8 00 14 value hex 01 >/dev/null 2>&1

# Add IPv6 whitelist entry (fd00:db8:1::20 = fd00 0db8 0001 0000 0000 0000 0000 0020)
docker compose -f "$TESTS_DIR/docker-compose.yml" exec -T xdp-target \
    bpftool map update pinned /sys/fs/bpf/tun_decap_whitelist_v6 \
    key hex fd 00 0d b8 00 01 00 00 00 00 00 00 00 00 00 20 \
    value hex 01 >/dev/null 2>&1

# ===== Step 5: Collect pre-traffic BPF prog info =====
log "Collecting initial BPF program info..."
bpftool prog show > "$PROFILE_DIR/bpf-progs-before.txt" 2>&1 || true

# ===== Step 6: Start perf record in background =====
log "Starting perf record (freq=$PERF_FREQ Hz)..."
perf record -F "$PERF_FREQ" -a -g \
    --call-graph dwarf,16384 \
    -o "$PROFILE_DIR/perf.data" &
PERF_PID=$!
sleep 1

# Verify perf is running
if ! kill -0 "$PERF_PID" 2>/dev/null; then
    err "perf record failed to start"
    PERF_PID=0
    exit 1
fi

# ===== Step 7: Start bpftool profiling (if available) =====
# Note: XDP program is in container, so we run bpftool there
log "Starting bpftool prog profile in container..."
docker compose -f "$TESTS_DIR/docker-compose.yml" exec -T xdp-target bash -c '
    XDP_PROG_ID=$(bpftool prog show | grep -E "type xdp|ext.*xdp_tun_decap" | grep -v xdp_dispatcher | awk "{print \$1}" | tr -d ":" | head -1)
    if [ -n "$XDP_PROG_ID" ]; then
        timeout 120 bpftool prog profile id "$XDP_PROG_ID" \
            duration 60 \
            cycles instructions l1d_loads llc_misses 2>&1
    else
        echo "No XDP program found"
    fi
' > "$PROFILE_DIR/bpftool-profile.txt" 2>&1 &
BPFTOOL_PID=$!

# ===== Step 8: Generate high-volume traffic =====
log "Generating traffic ($PKT_COUNT packets per type)..."

# Use the generate-packets.py script from the tests directory
if [[ -f "$TESTS_DIR/generate-packets.py" ]]; then
    # Run packet generation from tunnel-source container (script is at /usr/local/bin)
    # Use --type all-with-ipv6 to test all packet types including IPv6
    docker compose -f "$TESTS_DIR/docker-compose.yml" exec -T tunnel-source \
        python3 /usr/local/bin/generate-packets.py --type all-with-ipv6 --count "$PKT_COUNT" 2>&1 | \
        while IFS= read -r line; do
            echo "  [traffic] $line"
        done || warn "Traffic generation had errors (some failures expected)"
else
    warn "generate-packets.py not found, using manual traffic generation"
    # Fallback: send raw packets with hping3 or scapy
    for i in $(seq 1 "$PKT_COUNT"); do
        docker compose -f "$TESTS_DIR/docker-compose.yml" exec -T tunnel-source \
            ping -c 1 -W 1 172.16.0.2 >/dev/null 2>&1 || true
    done
fi

# Let perf collect a bit more
log "Waiting for perf to settle..."
sleep 2

# ===== Step 9: Stop profiling =====
log "Stopping perf record..."
if [[ $PERF_PID -ne 0 ]] && kill -0 "$PERF_PID" 2>/dev/null; then
    kill -INT "$PERF_PID"
    wait "$PERF_PID" 2>/dev/null || true
    PERF_PID=0
fi

if [[ $BPFTOOL_PID -ne 0 ]] && kill -0 "$BPFTOOL_PID" 2>/dev/null; then
    kill -INT "$BPFTOOL_PID" 2>/dev/null || true
    wait "$BPFTOOL_PID" 2>/dev/null || true
    BPFTOOL_PID=0
fi

# ===== Step 10: Collect BPF stats =====
log "Collecting BPF program statistics..."
{
    echo "=== BPF Program Stats (after traffic) ==="
    echo ""
    bpftool prog show 2>/dev/null || echo "bpftool prog show failed"
    echo ""
    echo "=== BPF Map Stats ==="
    echo ""
    bpftool map show 2>/dev/null || echo "bpftool map show failed"
} > "$PROFILE_DIR/bpf-stats.txt"

# ===== Step 11: Generate flame chart =====
log "Generating flame chart..."

if [[ -f "$PROFILE_DIR/perf.data" ]]; then
    # Generate perf script output
    perf script -i "$PROFILE_DIR/perf.data" > "$PROFILE_DIR/perf-script.txt" 2>/dev/null || true

    if [[ -s "$PROFILE_DIR/perf-script.txt" ]]; then
        # Collapse stacks and generate SVG
        "$FLAMEGRAPH_DIR/stackcollapse-perf.pl" "$PROFILE_DIR/perf-script.txt" \
            > "$PROFILE_DIR/perf-collapsed.txt" 2>/dev/null

        "$FLAMEGRAPH_DIR/flamegraph.pl" \
            --title "XDP Tunnel Decap Profile" \
            --subtitle "perf record -F $PERF_FREQ -a -g" \
            --width 1800 \
            "$PROFILE_DIR/perf-collapsed.txt" \
            > "$PROFILE_DIR/flamegraph.svg" 2>/dev/null

        # Generate BPF-filtered flame chart (only XDP/BPF stacks)
        grep -i "bpf\|xdp\|tun_decap" "$PROFILE_DIR/perf-collapsed.txt" \
            > "$PROFILE_DIR/perf-collapsed-bpf.txt" 2>/dev/null || true

        if [[ -s "$PROFILE_DIR/perf-collapsed-bpf.txt" ]]; then
            "$FLAMEGRAPH_DIR/flamegraph.pl" \
                --title "XDP Tunnel Decap - BPF Only" \
                --subtitle "Filtered for BPF/XDP stacks" \
                --width 1800 \
                "$PROFILE_DIR/perf-collapsed-bpf.txt" \
                > "$PROFILE_DIR/flamegraph-bpf.svg" 2>/dev/null
        fi

        # Clean up intermediate files
        rm -f "$PROFILE_DIR/perf-script.txt" "$PROFILE_DIR/perf-collapsed.txt" \
              "$PROFILE_DIR/perf-collapsed-bpf.txt"

        ok "Flame chart generated: $PROFILE_DIR/flamegraph.svg"
    else
        warn "No perf data collected (perf script output empty)"
    fi
else
    warn "No perf.data file found"
fi

# ===== Step 12: Print summary =====
echo ""
echo -e "${BOLD}=== Profiling Complete ===${RESET}"
echo ""
echo "Output artifacts in $PROFILE_DIR/:"
ls -lh "$PROFILE_DIR/" 2>/dev/null | tail -n +2 | while IFS= read -r line; do
    echo "  $line"
done
echo ""

if [[ -f "$PROFILE_DIR/flamegraph.svg" ]]; then
    ok "Open in browser: file://$PROFILE_DIR/flamegraph.svg"
fi

if [[ -f "$PROFILE_DIR/bpf-stats.txt" ]]; then
    echo ""
    echo -e "${BOLD}BPF Program Stats:${RESET}"
    grep -E "run_time_ns|run_cnt|type xdp" "$PROFILE_DIR/bpf-stats.txt" 2>/dev/null | head -20
fi

if [[ -f "$PROFILE_DIR/bpftool-profile.txt" ]] && [[ -s "$PROFILE_DIR/bpftool-profile.txt" ]]; then
    echo ""
    echo -e "${BOLD}bpftool Profile:${RESET}"
    cat "$PROFILE_DIR/bpftool-profile.txt"
fi

echo ""
ok "Profiling complete!"
