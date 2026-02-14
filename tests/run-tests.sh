#!/bin/bash
# Wrapper script to run integration tests from host (not inside Docker)
# This avoids Docker-in-Docker complexity

set -e

cd "$(dirname "$0")"

echo "=== XDP Tunnel Decapsulation Integration Tests ==="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check for debug mode
if [ "${DEBUG_TCPDUMP}" = "1" ]; then
    echo -e "${YELLOW}Debug mode enabled - tcpdump output will be verbose${NC}"
    echo ""
fi

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up containers..."
    docker compose down -v 2>/dev/null || true
    # Remove pinned BPF maps from host (shared bind mount)
    rm -f /sys/fs/bpf/tun_decap_* 2>/dev/null || true
}

# Trap to ensure cleanup on exit
trap cleanup EXIT INT TERM

# Ensure bpffs is mounted on HOST (required for bind mount to work)
echo "Checking if BPF filesystem is mounted on host..."
if ! mount | grep -q "bpf on /sys/fs/bpf"; then
    echo "BPF filesystem not mounted on host. Attempting to mount..."
    if [ "$(id -u)" -eq 0 ]; then
        mount -t bpf bpf /sys/fs/bpf
        echo -e "${GREEN}BPF filesystem mounted successfully${NC}"
    else
        echo -e "${YELLOW}Warning: BPF filesystem not mounted on host.${NC}"
        echo "Please run as root or manually mount with: sudo mount -t bpf bpf /sys/fs/bpf"
        echo "Continuing anyway - containers will mount their own bpffs..."
    fi
else
    echo -e "${GREEN}BPF filesystem already mounted on host${NC}"
fi
echo ""

# Clean up any existing containers and stale pinned maps
echo "Cleaning up any existing containers..."
docker compose down -v 2>/dev/null || true
rm -f /sys/fs/bpf/tun_decap_* 2>/dev/null || true

# Start containers
echo "Starting test containers..."
docker compose up -d --build

# Wait for containers to be ready
echo "Waiting for containers to be ready..."
sleep 5

# Check containers are running
if ! docker ps | grep -q xdp-target; then
    echo -e "${RED}Error: xdp-target container not running${NC}"
    exit 1
fi

if ! docker ps | grep -q tunnel-source; then
    echo -e "${RED}Error: tunnel-source container not running${NC}"
    exit 1
fi

echo -e "${GREEN}Containers are ready${NC}"
echo ""

# Run the integration tests (this now runs from host using docker exec)
# Pass through DEBUG_TCPDUMP environment variable
if [ "${DEBUG_TCPDUMP}" = "1" ]; then
    DEBUG_TCPDUMP=1 ./run-integration-tests.sh
else
    ./run-integration-tests.sh
fi

EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ All integration tests passed!${NC}"
else
    echo -e "${RED}✗ Integration tests failed${NC}"
fi

exit $EXIT_CODE
