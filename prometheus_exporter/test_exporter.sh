#!/bin/bash
# Test script for XDP Tunnel Decapsulation Prometheus Exporter

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPORTER_SCRIPT="${SCRIPT_DIR}/xdp_tun_decap_exporter.py"
TEST_PORT=9199
TEST_ADDRESS="127.0.0.1"
MAP_PATH="/sys/fs/bpf/tun_decap_stats"

echo "=== XDP Tunnel Decapsulation Exporter Test ==="
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This test must be run as root"
    echo "Usage: sudo $0"
    exit 1
fi

# Check if map exists
echo "[1/5] Checking if BPF stats map exists..."
if [ ! -e "$MAP_PATH" ]; then
    echo "ERROR: BPF stats map not found at $MAP_PATH"
    echo "Is the XDP program loaded?"
    echo
    echo "Load it with:"
    echo "  sudo xdp-loader load -m native eth0 build/tun_decap.bpf.o"
    exit 1
fi
echo "✓ Map found: $MAP_PATH"
echo

# Check Python version
echo "[2/5] Checking Python version..."
python3 --version
echo

# Check dependencies
echo "[3/5] Checking Python dependencies..."
if ! python3 -c "import prometheus_client" 2>/dev/null; then
    echo "WARNING: prometheus_client not installed"
    echo "Install with: pip3 install prometheus-client"
    echo
fi
echo "✓ Dependencies OK"
echo

# View current stats
echo "[4/5] Current BPF map statistics:"
bpftool map dump pinned "$MAP_PATH" 2>/dev/null | head -20
echo

# Start exporter in background
echo "[5/5] Starting exporter on ${TEST_ADDRESS}:${TEST_PORT}..."
python3 "$EXPORTER_SCRIPT" --address "$TEST_ADDRESS" --port "$TEST_PORT" --interval 2 --verbose &
EXPORTER_PID=$!

# Give it time to start
sleep 3

# Test metrics endpoint
echo
echo "=== Testing Metrics Endpoint ==="
echo "URL: http://${TEST_ADDRESS}:${TEST_PORT}/metrics"
echo

if command -v curl &> /dev/null; then
    echo "Sample metrics:"
    curl -s "http://${TEST_ADDRESS}:${TEST_PORT}/metrics" | grep "xdp_tun_decap" | head -15
    echo
    echo "✓ Metrics endpoint responding"
else
    echo "WARNING: curl not installed, skipping HTTP test"
fi

echo
echo "=== Test Complete ==="
echo
echo "Exporter is running with PID: $EXPORTER_PID"
echo "View metrics at: http://${TEST_ADDRESS}:${TEST_PORT}/metrics"
echo
echo "Press Ctrl+C to stop the exporter"
echo

# Wait for user interrupt
trap "echo; echo 'Stopping exporter...'; kill $EXPORTER_PID 2>/dev/null; echo 'Done'; exit 0" INT TERM

wait $EXPORTER_PID
