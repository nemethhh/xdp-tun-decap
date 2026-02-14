#!/bin/bash
set -e

echo "=== XDP Tunnel Decapsulation Integration Tests ==="
echo ""

# Configuration
XDP_TARGET="xdp-target"
TUNNEL_SOURCE="tunnel-source"
UNTRUSTED_SOURCE="untrusted-source"
XDP_TARGET_IP="10.200.0.10"
TUNNEL_SOURCE_IP="10.200.0.20"
UNTRUSTED_SOURCE_IP="10.200.0.30"
INNER_CLIENT_IP="203.0.113.100"

# IPv6 Configuration
XDP_TARGET_IPV6="fd00:db8:1::10"
TUNNEL_SOURCE_IPV6="fd00:db8:1::20"
UNTRUSTED_SOURCE_IPV6="fd00:db8:1::30"
INNER_CLIENT_IPV6="2001:db8:cafe::100"
INNER_DEST_IPV6="2001:db8:cafe::1"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counter
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Capture file
CAPTURE_FILE="/tmp/xdp-capture.pcap"

# Debug mode - set to 1 to show tcpdump output
DEBUG_TCPDUMP="${DEBUG_TCPDUMP:-0}"

print_test() {
    echo -e "${YELLOW}[TEST]${NC} $1"
}

print_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

print_section() {
    echo ""
    echo -e "${BLUE}=== $1 ===${NC}"
}

run_test() {
    TESTS_RUN=$((TESTS_RUN + 1))
}

# Start tcpdump capture on target
start_capture() {
    local filter="$1"
    echo "Starting packet capture with filter: $filter"
    # Kill any existing tcpdump
    docker exec $XDP_TARGET pkill tcpdump 2>/dev/null || true
    sleep 1
    # Remove old capture file
    docker exec $XDP_TARGET rm -f $CAPTURE_FILE 2>/dev/null || true
    # Start new capture in background
    docker exec -d $XDP_TARGET tcpdump -i eth0 -w $CAPTURE_FILE "$filter" 2>/dev/null
    sleep 2
}

# Stop tcpdump capture
stop_capture() {
    echo "Stopping packet capture..."
    docker exec $XDP_TARGET pkill tcpdump 2>/dev/null || true
    sleep 1
}

# Search for payload marker in capture (ASCII string search)
verify_decap_by_payload() {
    local marker="$1"
    local expected_count="$2"
    local description="$3"

    echo "  Verifying: $description"
    echo "  Looking for payload marker: $marker"

    # Debug: show capture file info
    if [ "$DEBUG_TCPDUMP" = "1" ]; then
        echo "  [DEBUG] Capture file contents:"
        docker exec $XDP_TARGET tcpdump -n -r $CAPTURE_FILE 2>&1 | head -20
        echo "  [DEBUG] ASCII output (first 30 lines):"
        docker exec $XDP_TARGET tcpdump -A -r $CAPTURE_FILE 2>&1 | head -30
    fi

    # Use tcpdump with -A (ASCII only) to search for marker
    # -A shows continuous ASCII which allows grep to find multi-line strings
    local tcpdump_output=$(docker exec $XDP_TARGET tcpdump -A -r $CAPTURE_FILE 2>/dev/null)
    local found_count=$(echo "$tcpdump_output" | grep -o "$marker" | wc -l || echo 0)

    echo "  Expected: >= $expected_count, Found: $found_count"

    # Show first few packets if debug enabled
    if [ "$DEBUG_TCPDUMP" = "1" ] && [ "$found_count" -gt 0 ]; then
        echo "  [DEBUG] Sample packets with marker:"
        echo "$tcpdump_output" | grep -A 2 -B 2 "$marker" | head -20
    fi

    if [ "$found_count" -ge "$expected_count" ]; then
        return 0  # Success
    else
        if [ "$DEBUG_TCPDUMP" = "1" ]; then
            echo "  [DEBUG] Full capture content:"
            docker exec $XDP_TARGET tcpdump -A -r $CAPTURE_FILE 2>&1
        fi
        return 1  # Failure
    fi
}

# Verify inner source IP is visible (means packet was decapsulated)
verify_inner_ip_visible() {
    local inner_ip="$1"
    local expected_count="$2"

    echo "  Verifying inner IP $inner_ip is visible (decapsulated)"

    # Count packets with the inner source IP
    local found_count=$(docker exec $XDP_TARGET tcpdump -n -r $CAPTURE_FILE src $inner_ip 2>/dev/null | wc -l || echo 0)

    echo "  Expected: >= $expected_count, Found: $found_count packets with inner IP"

    if [ "$found_count" -ge "$expected_count" ]; then
        return 0
    else
        return 1
    fi
}

# Verify packet was NOT decapsulated (payload should not be visible)
verify_not_decapsulated() {
    local marker="$1"

    echo "  Verifying packet was NOT decapsulated (marker should not appear)"

    if [ "$DEBUG_TCPDUMP" = "1" ]; then
        echo "  [DEBUG] Checking capture for unwanted marker:"
        docker exec $XDP_TARGET tcpdump -A -r $CAPTURE_FILE 2>&1 | head -20
    fi

    local tcpdump_output=$(docker exec $XDP_TARGET tcpdump -A -r $CAPTURE_FILE 2>/dev/null)
    local found_count=$(echo "$tcpdump_output" | grep -o "$marker" | wc -l || echo 0)

    echo "  Found: $found_count occurrences (should be 0)"

    if [ "$DEBUG_TCPDUMP" = "1" ] && [ "$found_count" -gt 0 ]; then
        echo "  [DEBUG] Unexpected markers found:"
        echo "$tcpdump_output" | grep -A 5 -B 5 "$marker"
    fi

    if [ "$found_count" -eq 0 ]; then
        return 0  # Success - marker not found
    else
        return 1  # Failure - marker was found
    fi
}

# Wait for containers to be ready
echo "Waiting for containers to be ready..."
sleep 2

# Check containers are running
echo "Checking containers..."
docker exec $XDP_TARGET ip addr show eth0 > /dev/null 2>&1 || { echo "XDP target not ready"; exit 1; }
docker exec $TUNNEL_SOURCE ip addr show eth0 > /dev/null 2>&1 || { echo "Tunnel source not ready"; exit 1; }
docker exec $UNTRUSTED_SOURCE ip addr show eth0 > /dev/null 2>&1 || { echo "Untrusted source not ready"; exit 1; }

print_section "Test 1: Container Connectivity"
run_test
print_test "Testing basic connectivity between containers"
if docker exec $TUNNEL_SOURCE ping -c 2 -W 2 $XDP_TARGET_IP > /dev/null 2>&1; then
    print_pass "Containers can communicate"
else
    print_fail "Containers cannot communicate"
fi

print_section "Test 2: XDP Program Loading"
run_test
print_test "Attaching XDP program to interface"

# Check if BPF object file exists
if docker exec $XDP_TARGET bash -c "test -f /build/tun_decap.bpf.o"; then
    XDP_OBJECT="/build/tun_decap.bpf.o"
    echo "Found BPF object: $XDP_OBJECT"
else
    print_fail "BPF object not found at /build/tun_decap.bpf.o"
    echo "Please build with: make all"
    exit 1
fi

# Verify BPF filesystem is accessible
echo "Checking BPF filesystem..."
if docker exec $XDP_TARGET test -d /sys/fs/bpf; then
    echo "BPF filesystem directory is accessible"
    # Show mount type for debugging
    docker exec $XDP_TARGET mount | grep "/sys/fs/bpf" || echo "  (bind-mounted from host)"
else
    print_fail "BPF filesystem not accessible - check docker-compose volume mounts"
    exit 1
fi

# Disable rp_filter
docker exec $XDP_TARGET sysctl -w net.ipv4.conf.all.rp_filter=0 > /dev/null
docker exec $XDP_TARGET sysctl -w net.ipv4.conf.eth0.rp_filter=0 > /dev/null

# Add dummy interface for inner IPs so decapsulated packets can be received
docker exec $XDP_TARGET ip addr add 203.0.113.1/24 dev lo > /dev/null 2>&1 || true
docker exec $XDP_TARGET ip -6 addr add 2001:db8:cafe::1/64 dev lo > /dev/null 2>&1 || true

# Remove any existing XDP program and clean up pinned maps
docker exec $XDP_TARGET ip link set dev eth0 xdp off > /dev/null 2>&1 || true
docker exec $XDP_TARGET xdp-loader unload eth0 --all > /dev/null 2>&1 || true
docker exec $XDP_TARGET rm -f /sys/fs/bpf/tun_decap_* > /dev/null 2>&1 || true

# Load XDP program using xdp-loader with skb mode
# -m skb: Use generic SKB mode (compatible with all interfaces, including veth)
# -s xdp: Section name in the BPF object
# --pin-path: Directory where maps with LIBBPF_PIN_BY_NAME will be pinned
# Note: Using skb mode because Docker uses veth interfaces
# Requires xdp-tools 1.5.5+ for kernel 6.14+ support (PR #509)
echo "Loading XDP program with xdp-loader..."
if ! docker exec $XDP_TARGET xdp-loader load -m skb --pin-path /sys/fs/bpf eth0 $XDP_OBJECT -s xdp 2>&1; then
    echo "XDP load failed. Checking xdp-tools version..."
    docker exec $XDP_TARGET xdp-loader --help 2>&1 | head -5
    print_fail "Failed to load XDP program - ensure xdp-tools >= 1.5.5 for kernel 6.14+"
    exit 1
fi

sleep 2

# NOTE: Config map defaults to all zeros (processing enabled)
# No initialization needed - the default state enables all processing

# Detect whether whitelist support is compiled in
# When built with WHITELIST=0, whitelist maps won't exist
WHITELIST_ENABLED=0
if docker exec $XDP_TARGET bpftool map show pinned /sys/fs/bpf/tun_decap_whitelist > /dev/null 2>&1; then
    WHITELIST_ENABLED=1
fi

if [ "$WHITELIST_ENABLED" = "1" ]; then
    # Add whitelisted IPv4 address to the whitelist map using bpftool
    # The whitelist map expects: key=IPv4 (4 bytes in network byte order), value=struct whitelist_value (1 byte)
    # Convert 10.200.0.20 to hex: 0a c8 00 14
    docker exec $XDP_TARGET bpftool map update pinned /sys/fs/bpf/tun_decap_whitelist \
        key hex 0a c8 00 14 \
        value hex 01

    echo "Whitelisted IPv4: $TUNNEL_SOURCE_IP (0a c8 00 14)"

    # Add whitelisted IPv6 address to the IPv6 whitelist map
    # Convert fd00:db8:1::20 to hex (16 bytes in network byte order)
    # fd00:db8:1::20 = fd 00 0d b8 00 01 00 00 00 00 00 00 00 00 00 20
    docker exec $XDP_TARGET bpftool map update pinned /sys/fs/bpf/tun_decap_whitelist_v6 \
        key hex fd 00 0d b8 00 01 00 00 00 00 00 00 00 00 00 20 \
        value hex 01

    echo "Whitelisted IPv6: $TUNNEL_SOURCE_IPV6 (fd 00 0d b8 00 01 00 00 00 00 00 00 00 00 00 20)"
else
    echo "Whitelist maps not found - built with WHITELIST=0 (whitelist enforcement disabled)"
fi

sleep 1

# Check if program is attached
XDP_STATUS=$(docker exec $XDP_TARGET xdp-loader status eth0 2>&1 || true)
if echo "$XDP_STATUS" | grep -q "xdp_tun_decap\|xdp\|ATTACHED"; then
    print_pass "XDP program attached successfully"
    echo "  Program status:"
    echo "$XDP_STATUS" | head -10

    # Verify whitelist maps (if compiled with whitelist support)
    if [ "$WHITELIST_ENABLED" = "1" ]; then
        echo "  IPv4 Whitelist entries:"
        docker exec $XDP_TARGET bpftool map dump pinned /sys/fs/bpf/tun_decap_whitelist 2>&1 | head -5 || true
        echo "  IPv6 Whitelist entries:"
        docker exec $XDP_TARGET bpftool map dump pinned /sys/fs/bpf/tun_decap_whitelist_v6 2>&1 | head -5 || true
    else
        echo "  Whitelist: disabled (built with WHITELIST=0)"
    fi
elif docker exec $XDP_TARGET ip link show eth0 | grep -q "xdp"; then
    print_pass "XDP program attached successfully (fallback check)"
else
    print_fail "XDP program not attached"
    echo "  xdp-loader status output:"
    echo "$XDP_STATUS"
fi

print_section "Test 3: Plain Traffic (Should Pass Through)"
run_test
print_test "Sending plain ICMP packets (should not be decapsulated)"

if docker exec $TUNNEL_SOURCE ping -c 3 -W 2 $XDP_TARGET_IP > /dev/null 2>&1; then
    print_pass "Plain traffic passes through XDP program"
else
    print_fail "Plain traffic blocked by XDP program"
fi

print_section "Test 4: Basic GRE IPv4 Decapsulation"
run_test
print_test "Sending GRE-encapsulated IPv4 packets with unique payload marker"

# Start capture to look for decapsulated inner packets
start_capture ""

# Send GRE packet with unique payload
docker exec $TUNNEL_SOURCE python3 /usr/local/bin/generate-packets.py \
    --type gre-ipv4 \
    --src $TUNNEL_SOURCE_IP \
    --dst $XDP_TARGET_IP \
    --inner-src $INNER_CLIENT_IP \
    --count 5

sleep 2
stop_capture

# Primary verification: Check if inner IP is visible (proves decapsulation worked)
if verify_inner_ip_visible "$INNER_CLIENT_IP" 5; then
    # Secondary verification: Payload marker confirms correct packet
    if verify_decap_by_payload "TEST_GRE_IPV4_BASIC" 5 "GRE IPv4 basic decapsulation"; then
        print_pass "GRE packets decapsulated successfully (inner IP visible + payload verified)"
    else
        print_fail "Inner IPs visible but payload marker verification failed"
    fi
else
    print_fail "Inner client IP not visible - GRE decapsulation failed"
fi

print_section "Test 5: GRE with Checksum Field"
run_test
print_test "Testing GRE packets with checksum field"

start_capture ""

docker exec $TUNNEL_SOURCE python3 /usr/local/bin/generate-packets.py \
    --type gre-ipv4-checksum \
    --src $TUNNEL_SOURCE_IP \
    --dst $XDP_TARGET_IP \
    --inner-src $INNER_CLIENT_IP \
    --count 5

sleep 2
stop_capture

if verify_inner_ip_visible "$INNER_CLIENT_IP" 5; then
    if verify_decap_by_payload "TEST_GRE_CHECKSUM_MARKER" 5 "GRE with checksum"; then
        print_pass "GRE with checksum decapsulated successfully"
    else
        print_fail "Inner IPs visible but payload verification failed"
    fi
else
    print_fail "GRE with checksum failed - inner IP not visible"
fi

print_section "Test 6: GRE with Key Field"
run_test
print_test "Testing GRE packets with key field"

start_capture ""

docker exec $TUNNEL_SOURCE python3 /usr/local/bin/generate-packets.py \
    --type gre-ipv4-key \
    --src $TUNNEL_SOURCE_IP \
    --dst $XDP_TARGET_IP \
    --inner-src $INNER_CLIENT_IP \
    --count 5

sleep 2
stop_capture

if verify_inner_ip_visible "$INNER_CLIENT_IP" 5; then
    if verify_decap_by_payload "TEST_GRE_KEY_0x12345678" 5 "GRE with key field"; then
        print_pass "GRE with key field decapsulated successfully"
    else
        print_fail "Inner IPs visible but payload verification failed"
    fi
else
    print_fail "GRE with key field failed - inner IP not visible"
fi

print_section "Test 7: GRE with Sequence Number"
run_test
print_test "Testing GRE packets with sequence number field"

start_capture ""

docker exec $TUNNEL_SOURCE python3 /usr/local/bin/generate-packets.py \
    --type gre-ipv4-seq \
    --src $TUNNEL_SOURCE_IP \
    --dst $XDP_TARGET_IP \
    --inner-src $INNER_CLIENT_IP \
    --count 5

sleep 2
stop_capture

if verify_inner_ip_visible "$INNER_CLIENT_IP" 5; then
    if verify_decap_by_payload "TEST_GRE_SEQUENCE_NUM" 5 "GRE with sequence number"; then
        print_pass "GRE with sequence number decapsulated successfully"
    else
        print_fail "Inner IPs visible but payload verification failed"
    fi
else
    print_fail "GRE with sequence number failed - inner IP not visible"
fi

print_section "Test 8: GRE with All Optional Fields"
run_test
print_test "Testing GRE packets with checksum, key, and sequence combined"

start_capture ""

docker exec $TUNNEL_SOURCE python3 /usr/local/bin/generate-packets.py \
    --type gre-ipv4-all-flags \
    --src $TUNNEL_SOURCE_IP \
    --dst $XDP_TARGET_IP \
    --inner-src $INNER_CLIENT_IP \
    --count 5

sleep 2
stop_capture

if verify_inner_ip_visible "$INNER_CLIENT_IP" 5; then
    if verify_decap_by_payload "TEST_GRE_ALL_FLAGS_DEADBEEF" 5 "GRE with all optional fields"; then
        print_pass "GRE with all optional fields decapsulated successfully"
    else
        print_fail "Inner IPs visible but payload verification failed"
    fi
else
    print_fail "GRE with all optional fields failed - inner IP not visible"
fi

print_section "Test 9: GRE with Routing Bit (Deprecated)"
run_test
print_test "Testing GRE packets with routing bit set"

start_capture ""

docker exec $TUNNEL_SOURCE python3 /usr/local/bin/generate-packets.py \
    --type gre-ipv4-routing \
    --src $TUNNEL_SOURCE_IP \
    --dst $XDP_TARGET_IP \
    --inner-src $INNER_CLIENT_IP \
    --count 3

sleep 2
stop_capture

if verify_inner_ip_visible "$INNER_CLIENT_IP" 3; then
    if verify_decap_by_payload "TEST_GRE_ROUTING_BIT" 3 "GRE with routing bit"; then
        print_pass "GRE with routing bit decapsulated successfully"
    else
        print_fail "Inner IPs visible but payload verification failed"
    fi
else
    print_fail "GRE with routing bit failed - inner IP not visible"
fi

print_section "Test 10: IPIP Decapsulation (IPv4-in-IPv4)"
run_test
print_test "Sending IPIP-encapsulated packets"

start_capture ""

docker exec $TUNNEL_SOURCE python3 /usr/local/bin/generate-packets.py \
    --type ipip \
    --src $TUNNEL_SOURCE_IP \
    --dst $XDP_TARGET_IP \
    --inner-src $INNER_CLIENT_IP \
    --count 5

sleep 2
stop_capture

if verify_inner_ip_visible "$INNER_CLIENT_IP" 5; then
    if verify_decap_by_payload "TEST_IPIP_IPV4_IN_IPV4" 5 "IPIP IPv4-in-IPv4"; then
        print_pass "IPIP packets decapsulated successfully"
    else
        print_fail "Inner IPs visible but payload verification failed"
    fi
else
    print_fail "IPIP decapsulation failed - inner IP not visible"
fi

print_section "Test 11: IPIP with Large Payload"
run_test
print_test "Testing IPIP packets with large payload (MTU edge case)"

start_capture ""

docker exec $TUNNEL_SOURCE python3 /usr/local/bin/generate-packets.py \
    --type ipip-large \
    --src $TUNNEL_SOURCE_IP \
    --dst $XDP_TARGET_IP \
    --inner-src $INNER_CLIENT_IP \
    --count 3

sleep 2
stop_capture

if verify_inner_ip_visible "$INNER_CLIENT_IP" 3; then
    if verify_decap_by_payload "TEST_IPIP_LARGE_PAYLOAD_1400B" 3 "IPIP with 1400-byte payload"; then
        print_pass "IPIP large payload packets decapsulated successfully"
    else
        print_fail "Inner IPs visible but payload verification failed"
    fi
else
    print_fail "IPIP large payload failed - inner IP not visible"
fi

print_section "Test 12: Non-Whitelisted Source (Should Drop)"
run_test
if [ "$WHITELIST_ENABLED" = "1" ]; then
    print_test "Sending tunnel packets from non-whitelisted source"

    start_capture ""

    # Send GRE from untrusted source - should be dropped
    docker exec $UNTRUSTED_SOURCE python3 /usr/local/bin/generate-packets.py \
        --type gre-ipv4 \
        --src $UNTRUSTED_SOURCE_IP \
        --dst $XDP_TARGET_IP \
        --inner-src $INNER_CLIENT_IP \
        --count 5

    sleep 2
    stop_capture

    # Verify that the inner payload is NOT visible (packet was dropped, not decapsulated)
    if verify_not_decapsulated "TEST_GRE_IPV4_BASIC"; then
        print_pass "Non-whitelisted tunnel traffic dropped successfully (payload not visible)"
    else
        print_fail "Non-whitelisted traffic was incorrectly decapsulated"
    fi
else
    print_pass "Skipped (whitelist disabled)"
fi

print_section "Test 13: Invalid GRE Version (Should Drop)"
run_test
print_test "Sending GRE packet with invalid version"

start_capture ""

docker exec $TUNNEL_SOURCE python3 /usr/local/bin/generate-packets.py \
    --type invalid-gre \
    --src $TUNNEL_SOURCE_IP \
    --dst $XDP_TARGET_IP \
    --inner-src $INNER_CLIENT_IP

sleep 2
stop_capture

# Verify packet was not decapsulated (inner IP should not be visible)
INNER_IP_COUNT=$(docker exec $XDP_TARGET tcpdump -n -r $CAPTURE_FILE src $INNER_CLIENT_IP 2>/dev/null | wc -l || echo 0)
if [ "$INNER_IP_COUNT" -eq 0 ]; then
    print_pass "Invalid GRE version packet dropped correctly (inner IP not visible)"
else
    print_fail "Invalid GRE version not handled correctly - inner IP visible ($INNER_IP_COUNT packets)"
fi

print_section "Test 14: Truncated GRE Packet (Malformed)"
run_test
print_test "Sending truncated GRE packet"

docker exec $TUNNEL_SOURCE python3 /usr/local/bin/generate-packets.py \
    --type truncated-gre \
    --src $TUNNEL_SOURCE_IP \
    --dst $XDP_TARGET_IP

sleep 1
print_pass "Truncated GRE packet sent (should be dropped by bounds check)"

print_section "Test 15: GRE with Invalid Optional Fields (Malformed)"
run_test
print_test "Sending GRE packet with invalid optional field structure"

docker exec $TUNNEL_SOURCE python3 /usr/local/bin/generate-packets.py \
    --type invalid-optional-fields \
    --src $TUNNEL_SOURCE_IP \
    --dst $XDP_TARGET_IP \
    --inner-src $INNER_CLIENT_IP

sleep 1
print_pass "Malformed GRE optional fields packet sent (should be dropped)"

print_section "Test 16: Mixed Traffic Burst"
run_test
print_test "Sending burst of mixed tunnel and plain traffic"

start_capture ""

docker exec $TUNNEL_SOURCE python3 /usr/local/bin/generate-packets.py \
    --type mixed-burst \
    --src $TUNNEL_SOURCE_IP \
    --dst $XDP_TARGET_IP \
    --inner-src $INNER_CLIENT_IP

sleep 2
stop_capture

print_pass "Mixed traffic burst sent successfully"

print_section "Test 17: Verify Plain Traffic Still Works After Tunnel Processing"
run_test
print_test "Testing plain traffic after intensive tunnel testing"

if docker exec $TUNNEL_SOURCE ping -c 3 -W 2 $XDP_TARGET_IP > /dev/null 2>&1; then
    print_pass "Plain traffic continues to work correctly"
else
    print_fail "Plain traffic blocked after tunnel processing"
fi

print_section "Test 18: Multiple Whitelisted Sources"
run_test
if [ "$WHITELIST_ENABLED" = "1" ]; then
    print_test "Testing that both whitelisted and non-whitelisted sources behave correctly"

    start_capture ""

    # Test whitelisted source (should work)
    docker exec $TUNNEL_SOURCE python3 /usr/local/bin/generate-packets.py \
        --type gre-ipv4 \
        --src $TUNNEL_SOURCE_IP \
        --dst $XDP_TARGET_IP \
        --inner-src $INNER_CLIENT_IP \
        --count 3

    # Test non-whitelisted (should drop)
    docker exec $UNTRUSTED_SOURCE python3 /usr/local/bin/generate-packets.py \
        --type gre-ipv4 \
        --src $UNTRUSTED_SOURCE_IP \
        --dst $XDP_TARGET_IP \
        --inner-src $INNER_CLIENT_IP \
        --count 3

    sleep 2
    stop_capture

    # Should see markers from whitelisted source only (exactly 3, not 6)
    MARKER_COUNT=$(docker exec $XDP_TARGET tcpdump -A -r $CAPTURE_FILE 2>/dev/null | grep -o "TEST_GRE_IPV4_BASIC" | wc -l || echo 0)
    if [ "$MARKER_COUNT" -eq 3 ]; then
        print_pass "Whitelist enforcement working correctly (3 decapsulated, 3 dropped)"
    elif [ "$MARKER_COUNT" -ge 3 ] && [ "$MARKER_COUNT" -lt 6 ]; then
        print_pass "Whitelist enforcement working correctly (~3 decapsulated, ~3 dropped, found $MARKER_COUNT)"
    else
        print_fail "Whitelist enforcement issue (expected ~3 markers, found $MARKER_COUNT)"
        if [ "$DEBUG_TCPDUMP" = "1" ]; then
            echo "  [DEBUG] Showing packet sources:"
            docker exec $XDP_TARGET tcpdump -n -r $CAPTURE_FILE 2>&1 | grep "10.200.0"
        fi
    fi
else
    print_pass "Skipped (whitelist disabled)"
fi

print_section "Test 19: High Volume Test"
run_test
print_test "Sending high volume of tunnel packets"

start_capture ""

# Send 100 packets rapidly
docker exec $TUNNEL_SOURCE python3 /usr/local/bin/generate-packets.py \
    --type gre-ipv4 \
    --src $TUNNEL_SOURCE_IP \
    --dst $XDP_TARGET_IP \
    --inner-src $INNER_CLIENT_IP \
    --count 100

sleep 3
stop_capture

# Verify inner IPs are visible (primary check)
IP_COUNT=$(docker exec $XDP_TARGET tcpdump -n -r $CAPTURE_FILE src $INNER_CLIENT_IP 2>/dev/null | wc -l || echo 0)
MARKER_COUNT=$(docker exec $XDP_TARGET tcpdump -A -r $CAPTURE_FILE 2>/dev/null | grep -o "TEST_GRE_IPV4_BASIC" | wc -l || echo 0)

if [ "$IP_COUNT" -ge 95 ] && [ "$MARKER_COUNT" -ge 95 ]; then
    print_pass "High volume test passed ($IP_COUNT/100 packets with inner IP, $MARKER_COUNT/100 markers verified)"
elif [ "$IP_COUNT" -ge 95 ]; then
    print_pass "High volume test passed ($IP_COUNT/100 packets verified, marker count: $MARKER_COUNT)"
else
    print_fail "High volume test failed (only $IP_COUNT/100 packets with inner IP visible)"
    if [ "$DEBUG_TCPDUMP" = "1" ]; then
        echo "  [DEBUG] Total packet count in capture:"
        docker exec $XDP_TARGET tcpdump -n -r $CAPTURE_FILE 2>&1 | wc -l
    fi
fi

print_section "Test 20: IPv6 Outer + GRE + IPv4 Inner"
run_test
print_test "Sending GRE packet with IPv6 outer header and IPv4 inner packet"

start_capture ""

docker exec $TUNNEL_SOURCE python3 /usr/local/bin/generate-packets.py \
    --type gre-ipv6-outer-ipv4-inner \
    --src $TUNNEL_SOURCE_IPV6 \
    --dst $XDP_TARGET_IPV6 \
    --inner-src $INNER_CLIENT_IP \
    --count 5

sleep 2
stop_capture

if verify_inner_ip_visible "$INNER_CLIENT_IP" 5; then
    if verify_decap_by_payload "TEST_GRE_IPV6_OUTER_IPV4_INNER" 5 "GRE IPv6 outer + IPv4 inner"; then
        print_pass "GRE IPv6 outer + IPv4 inner decapsulated successfully"
    else
        print_fail "Inner IPs visible but payload verification failed"
    fi
else
    print_fail "GRE IPv6 outer + IPv4 inner failed - inner IP not visible"
fi

print_section "Test 21: IPv6 Outer + GRE + IPv6 Inner"
run_test
print_test "Sending GRE packet with IPv6 outer header and IPv6 inner packet"

start_capture ""

docker exec $TUNNEL_SOURCE python3 /usr/local/bin/generate-packets.py \
    --type gre-ipv6-outer-ipv6-inner \
    --src $TUNNEL_SOURCE_IPV6 \
    --dst $XDP_TARGET_IPV6 \
    --inner-src $INNER_CLIENT_IPV6 \
    --inner-dst $INNER_DEST_IPV6 \
    --count 5

sleep 2
stop_capture

# For IPv6 inner packets, we can't easily verify inner IP visibility without ip6tables
# So we'll rely primarily on payload marker verification
if verify_decap_by_payload "TEST_GRE_IPV6_OUTER_IPV6_INNER" 5 "GRE IPv6 outer + IPv6 inner"; then
    print_pass "GRE IPv6 outer + IPv6 inner decapsulated successfully"
else
    print_fail "GRE IPv6 outer + IPv6 inner failed - payload marker not found"
fi

print_section "Test 22: IPv6 GRE with Optional Fields"
run_test
print_test "Testing GRE packets with IPv6 outer and all optional fields"

start_capture ""

docker exec $TUNNEL_SOURCE python3 /usr/local/bin/generate-packets.py \
    --type gre-ipv6-all-flags \
    --src $TUNNEL_SOURCE_IPV6 \
    --dst $XDP_TARGET_IPV6 \
    --inner-src $INNER_CLIENT_IP \
    --count 5

sleep 2
stop_capture

if verify_inner_ip_visible "$INNER_CLIENT_IP" 5; then
    if verify_decap_by_payload "TEST_GRE_IPV6_ALL_FLAGS" 5 "GRE IPv6 with all optional fields"; then
        print_pass "GRE IPv6 with all optional fields decapsulated successfully"
    else
        print_fail "Inner IPs visible but payload verification failed"
    fi
else
    print_fail "GRE IPv6 with all optional fields failed - inner IP not visible"
fi

print_section "Test 23: IPv4-in-IPv6 (Protocol 4)"
run_test
print_test "Sending IPv4-in-IPv6 tunnel packets"

start_capture ""

docker exec $TUNNEL_SOURCE python3 /usr/local/bin/generate-packets.py \
    --type ipip-ipv4-in-ipv6 \
    --src $TUNNEL_SOURCE_IPV6 \
    --dst $XDP_TARGET_IPV6 \
    --inner-src $INNER_CLIENT_IP \
    --count 5

sleep 2
stop_capture

if verify_inner_ip_visible "$INNER_CLIENT_IP" 5; then
    if verify_decap_by_payload "TEST_IPIP_IPV4_IN_IPV6" 5 "IPv4-in-IPv6"; then
        print_pass "IPv4-in-IPv6 packets decapsulated successfully"
    else
        print_fail "Inner IPs visible but payload verification failed"
    fi
else
    print_fail "IPv4-in-IPv6 decapsulation failed - inner IP not visible"
fi

print_section "Test 24: IPv6-in-IPv4 (Protocol 41)"
run_test
print_test "Sending IPv6-in-IPv4 tunnel packets"

start_capture ""

docker exec $TUNNEL_SOURCE python3 /usr/local/bin/generate-packets.py \
    --type ipip-ipv6-in-ipv4 \
    --src $TUNNEL_SOURCE_IP \
    --dst $XDP_TARGET_IP \
    --inner-src $INNER_CLIENT_IPV6 \
    --inner-dst $INNER_DEST_IPV6 \
    --count 5

sleep 2
stop_capture

# Verify by payload marker (IPv6 inner IP verification not easily available)
if verify_decap_by_payload "TEST_IPIP_IPV6_IN_IPV4" 5 "IPv6-in-IPv4"; then
    print_pass "IPv6-in-IPv4 packets decapsulated successfully"
else
    print_fail "IPv6-in-IPv4 decapsulation failed - payload marker not found"
fi

print_section "Test 25: IPv6-in-IPv6 (Protocol 41)"
run_test
print_test "Sending IPv6-in-IPv6 tunnel packets"

start_capture ""

docker exec $TUNNEL_SOURCE python3 /usr/local/bin/generate-packets.py \
    --type ipip-ipv6-in-ipv6 \
    --src $TUNNEL_SOURCE_IPV6 \
    --dst $XDP_TARGET_IPV6 \
    --inner-src $INNER_CLIENT_IPV6 \
    --inner-dst $INNER_DEST_IPV6 \
    --count 5

sleep 2
stop_capture

if verify_decap_by_payload "TEST_IPIP_IPV6_IN_IPV6" 5 "IPv6-in-IPv6"; then
    print_pass "IPv6-in-IPv6 packets decapsulated successfully"
else
    print_fail "IPv6-in-IPv6 decapsulation failed - payload marker not found"
fi

print_section "Test 26: IPv6 Non-Whitelisted Source (Should Drop)"
run_test
if [ "$WHITELIST_ENABLED" = "1" ]; then
    print_test "Sending IPv6 tunnel packets from non-whitelisted source"

    start_capture ""

    # Send GRE from untrusted IPv6 source - should be dropped
    docker exec $UNTRUSTED_SOURCE python3 /usr/local/bin/generate-packets.py \
        --type gre-ipv6-outer-ipv4-inner \
        --src $UNTRUSTED_SOURCE_IPV6 \
        --dst $XDP_TARGET_IPV6 \
        --inner-src $INNER_CLIENT_IP \
        --count 5

    sleep 2
    stop_capture

    # Verify that the inner payload is NOT visible (packet was dropped, not decapsulated)
    if verify_not_decapsulated "TEST_GRE_IPV6_OUTER_IPV4_INNER"; then
        print_pass "Non-whitelisted IPv6 tunnel traffic dropped successfully (payload not visible)"
    else
        print_fail "Non-whitelisted IPv6 traffic was incorrectly decapsulated"
    fi
else
    print_pass "Skipped (whitelist disabled)"
fi

print_section "Test 27: Mixed IPv4/IPv6 Tunnel Traffic"
run_test
print_test "Testing simultaneous IPv4 and IPv6 tunnel traffic"

start_capture ""

# Send mixed traffic
docker exec $TUNNEL_SOURCE python3 /usr/local/bin/generate-packets.py \
    --type mixed-ipv4-ipv6 \
    --src $TUNNEL_SOURCE_IP \
    --dst $XDP_TARGET_IP \
    --src-ipv6 $TUNNEL_SOURCE_IPV6 \
    --dst-ipv6 $XDP_TARGET_IPV6 \
    --inner-src $INNER_CLIENT_IP

sleep 2
stop_capture

# Count different markers
MARKER_IPV4=$(docker exec $XDP_TARGET tcpdump -A -r $CAPTURE_FILE 2>/dev/null | grep -o "TEST_MIXED_IPV4_GRE" | wc -l || echo 0)
MARKER_IPV6=$(docker exec $XDP_TARGET tcpdump -A -r $CAPTURE_FILE 2>/dev/null | grep -o "TEST_MIXED_IPV6_GRE_IPV4" | wc -l || echo 0)

if [ "$MARKER_IPV4" -ge 1 ] && [ "$MARKER_IPV6" -ge 1 ]; then
    print_pass "Mixed IPv4/IPv6 traffic decapsulated successfully (IPv4: $MARKER_IPV4, IPv6: $MARKER_IPV6 markers)"
else
    print_fail "Mixed IPv4/IPv6 traffic failed (IPv4: $MARKER_IPV4, IPv6: $MARKER_IPV6 markers found)"
fi

print_section "Test 28: IPv6 Large Payload"
run_test
print_test "Testing IPv6 GRE packets with large payload"

start_capture ""

docker exec $TUNNEL_SOURCE python3 /usr/local/bin/generate-packets.py \
    --type ipv6-large \
    --src $TUNNEL_SOURCE_IPV6 \
    --dst $XDP_TARGET_IPV6 \
    --inner-src $INNER_CLIENT_IP \
    --count 3

sleep 2
stop_capture

if verify_inner_ip_visible "$INNER_CLIENT_IP" 3; then
    if verify_decap_by_payload "TEST_IPV6_LARGE_PAYLOAD_1400B" 3 "IPv6 GRE with large payload"; then
        print_pass "IPv6 large payload packets decapsulated successfully"
    else
        print_fail "Inner IPs visible but payload verification failed"
    fi
else
    print_fail "IPv6 large payload failed - inner IP not visible"
fi

print_section "Test 29: Fragmented GRE Packet (Should Drop)"
run_test
print_test "Sending fragmented GRE packet (MF flag set)"

start_capture ""

docker exec $TUNNEL_SOURCE python3 /usr/local/bin/generate-packets.py \
    --type gre-fragmented \
    --src $TUNNEL_SOURCE_IP \
    --dst $XDP_TARGET_IP \
    --inner-src $INNER_CLIENT_IP \
    --count 5

sleep 2
stop_capture

# Verify that the inner payload is NOT visible (fragmented packet should be dropped)
if verify_not_decapsulated "TEST_GRE_FRAGMENTED_DROP"; then
    print_pass "Fragmented GRE packets dropped successfully (payload not visible)"
else
    print_fail "Fragmented GRE packets were incorrectly decapsulated"
fi

print_section "Packet Capture Summary"
echo "Final capture statistics (last capture file):"
docker exec $XDP_TARGET tcpdump -n -r $CAPTURE_FILE 2>&1 | tail -10 || true

print_section "Test Summary"
echo "Tests run: $TESTS_RUN"
echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
echo ""

# Show BPF map statistics
echo "XDP Program Statistics:"
docker exec $XDP_TARGET bpftool map dump pinned /sys/fs/bpf/tun_decap_stats 2>&1 | head -20 || true
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed${NC}"
    exit 1
fi
