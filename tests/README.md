# Integration Tests

Comprehensive Docker Compose-based integration tests for the XDP tunnel decapsulation program using **tcpdump-based verification** with unique payload markers. Includes full IPv4 and IPv6 support.

## Test Methodology

The integration tests use a **robust verification approach** based on tcpdump packet captures rather than relying solely on eBPF logs:

1. **Unique Payload Markers**: Each test packet contains a unique ASCII marker (e.g., `TEST_GRE_IPV4_BASIC`)
2. **Packet Capture**: tcpdump captures all traffic on the XDP target interface
3. **Payload Verification**: Tests search for payload markers in captures to verify decapsulation
4. **Proof of Decapsulation**: If the inner payload marker is visible in tcpdump output, the packet was successfully decapsulated

This approach provides **definitive proof** that packets are actually being decapsulated at the network level, not just processed by the XDP program.

## Prerequisites

- Docker and Docker Compose installed with IPv6 support
- Compiled XDP program: `make all` (builds `build/tun_decap.bpf.o`)
- Host kernel with XDP support (Linux 5.17+ with `CONFIG_DEBUG_INFO_BTF=y`)
- Host kernel with IPv6 support enabled (standard in modern kernels)
- xdp-tools 1.5.5+ (automatically built from source in test container)
  - **Important**: Kernel 6.14+ requires xdp-tools 1.5.5+ (includes PR #509 fix for packet modification)
  - Earlier versions will fail with "Extension program changes packet data" error

## Architecture

The test environment consists of three containers orchestrated from the host.

**Note**: Docker containers use virtual Ethernet (veth) interfaces, which require XDP to run in **SKB (generic) mode** instead of native mode. This mode has lower performance but works with all network interfaces. For production deployments on physical servers, use native mode for best performance.

### Container Setup

1. **xdp-target**: Container where the XDP program is attached
   - Runs with privileged mode and CAP_BPF for XDP attachment
   - Receives tunnel traffic and decapsulates it
   - IPv4: 10.200.0.10
   - IPv6: fd00:db8:1::10
   - Has xdp-tools and bpftool for program management

2. **tunnel-source**: Container that generates tunnel traffic (whitelisted)
   - Sends GRE/IPIP encapsulated packets using Scapy
   - Simulates CDN/tunnel provider
   - IPv4: 10.200.0.20
   - IPv6: fd00:db8:1::20

3. **untrusted-source**: Container for non-whitelisted source testing
   - Generates tunnel traffic that should be dropped
   - Tests whitelist enforcement (IPv4 and IPv6)
   - IPv4: 10.200.0.30
   - IPv6: fd00:db8:1::30

Test orchestration runs from the HOST using `docker exec` to communicate with containers.
This avoids Docker-in-Docker complexity.

### IPv6 Support

The test environment fully supports IPv6 tunneling:
- Containers have both IPv4 and IPv6 addresses assigned
- Separate IPv6 whitelist map (`tun_decap_whitelist_v6`) for IPv6 source addresses
- Tests cover all IPv4/IPv6 outer/inner header combinations
- Docker network is configured with IPv6 subnet: `fd00:db8:1::/64`

**Key IPv6 Features:**
- IPv6 outer headers with GRE (both IPv4 and IPv6 inner)
- IPv4-in-IPv6 (protocol 4) and IPv6-in-IPv6 (protocol 41) tunnels
- Independent whitelist management for IPv4 and IPv6
- Per-CPU hash maps for lock-free IPv6 address lookups

## Running Tests

### Run All Integration Tests

```bash
cd tests
./run-tests.sh
```

This script will:
1. Build and start containers with `docker compose`
2. Run the comprehensive test suite using `run-integration-tests.sh`
3. Clean up containers automatically

Exit code 0 indicates all tests passed.

### Debug Mode

To enable detailed tcpdump output for debugging test failures:

```bash
cd tests
DEBUG_TCPDUMP=1 ./run-tests.sh
```

Or run tests manually with debug mode:

```bash
cd tests
docker compose up -d --build
DEBUG_TCPDUMP=1 ./run-integration-tests.sh
docker compose down -v
```

Debug mode shows:
- Capture file contents for each test
- ASCII/hex tcpdump output
- Sample packets containing markers
- Full capture analysis on failures
- Packet sources and counts

### Manual Container Management

Start containers manually:
```bash
cd tests
docker compose up -d --build
```

Run tests:
```bash
./run-integration-tests.sh
```

Clean up:
```bash
docker compose down -v
```

## Test Cases

### Test 1: Container Connectivity
Verifies basic network connectivity between containers using ping.

### Test 2: XDP Program Loading
Attaches the XDP program to the eth0 interface using **xdp-loader** and manages the whitelist using **bpftool**. Verifies attachment using `xdp-loader status`. This ensures the program can coexist with other XDP programs using libxdp multi-program support.

### Test 3: Plain Traffic Pass-Through
Sends regular ICMP traffic (non-tunnel) to verify XDP_PASS behavior for non-tunnel protocols.

### Test 4: Basic GRE IPv4 Decapsulation
**Payload Marker**: `TEST_GRE_IPV4_BASIC`

Sends GRE-encapsulated IPv4 packets from whitelisted source. Uses tcpdump to capture traffic and searches for the payload marker. If the marker is visible in the capture, decapsulation succeeded.

### Test 5: GRE with Checksum Field
**Payload Marker**: `TEST_GRE_CHECKSUM_MARKER`

Tests GRE packets with the checksum flag (C bit) set, adding 4 bytes to header. Verifies decapsulation via tcpdump.

### Test 6: GRE with Key Field
**Payload Marker**: `TEST_GRE_KEY_0x12345678`

Tests GRE packets with the key flag (K bit) set and key value 0x12345678, adding 4 bytes to header.

### Test 7: GRE with Sequence Number
**Payload Marker**: `TEST_GRE_SEQUENCE_NUM`

Tests GRE packets with the sequence number flag (S bit) set, adding 4 bytes to header.

### Test 8: GRE with All Optional Fields
**Payload Marker**: `TEST_GRE_ALL_FLAGS_DEADBEEF`

Tests GRE packets with checksum, key (0xDEADBEEF), and sequence fields all present (16-byte header total).

### Test 9: GRE with Routing Bit (Deprecated)
**Payload Marker**: `TEST_GRE_ROUTING_BIT`

Tests GRE packets with the routing flag (R bit) set - deprecated but should be handled gracefully.

### Test 10: IPIP Decapsulation (IPv4-in-IPv4)
**Payload Marker**: `TEST_IPIP_IPV4_IN_IPV4`

Sends IPv4-in-IPv4 encapsulated packets (protocol 4) and verifies decapsulation.

### Test 11: IPIP with Large Payload
**Payload Marker**: `TEST_IPIP_LARGE_PAYLOAD_1400B`

Tests IPIP packets with 1400-byte payload to verify MTU edge cases and bounds checking.

### Test 12: Non-Whitelisted Source (Should Drop)
**Payload Marker**: `TEST_GRE_IPV4_BASIC` (should NOT appear)

Sends tunnel traffic from untrusted-source container (10.200.0.30) which is not in the whitelist.
Uses **negative verification**: captures packets and confirms the payload marker does NOT appear in tcpdump output, proving packets were dropped, not decapsulated.

### Test 13: Invalid GRE Version (Should Drop)
Sends GRE packets with version != 0 to verify malformed packet detection and dropping.

### Test 14: Truncated GRE Packet (Malformed)
Sends incomplete GRE header (only 2 bytes instead of 4) to test bounds checking.

### Test 15: GRE with Invalid Optional Fields (Malformed)
Sends GRE packet claiming to have optional fields (via flags) but missing the actual field data.

### Test 16: Mixed Traffic Burst
Sends a burst containing plain traffic, GRE, IPIP, UDP, and TCP to verify correct handling of mixed packet types.

### Test 17: Verify Plain Traffic Still Works After Tunnel Processing
Validates that plain traffic continues to work correctly after extensive tunnel packet processing.

### Test 18: Multiple Whitelisted Sources
**Verification**: Counts payload markers (expects exactly 3 from whitelisted source, 0 from untrusted)

Tests that both whitelisted and non-whitelisted sources behave correctly when sending traffic simultaneously. Verifies selective decapsulation based on source IP.

### Test 19: High Volume Test
**Payload Marker**: `TEST_GRE_IPV4_BASIC` (100 packets)

Sends 100 GRE packets rapidly and verifies at least 95% are successfully decapsulated (allows for minor packet loss during high volume).

### Test 20: IPv6 Outer + GRE + IPv4 Inner
**Payload Marker**: `TEST_GRE_IPV6_OUTER_IPV4_INNER`

Tests GRE tunnel with IPv6 outer header and IPv4 inner packet. Verifies IPv6 source address whitelist checking and proper decapsulation.

### Test 21: IPv6 Outer + GRE + IPv6 Inner
**Payload Marker**: `TEST_GRE_IPV6_OUTER_IPV6_INNER`

Tests GRE tunnel with both IPv6 outer and IPv6 inner headers. Validates full IPv6 encapsulation/decapsulation path.

### Test 22: IPv6 GRE with Optional Fields
**Payload Marker**: `TEST_GRE_IPV6_ALL_FLAGS`

Tests IPv6 GRE packets with checksum, key, and sequence fields to verify optional field handling with IPv6 outer headers.

### Test 23: IPv4-in-IPv6 (Protocol 4)
**Payload Marker**: `TEST_IPIP_IPV4_IN_IPV6`

Tests IPv4-in-IPv6 tunnel (protocol 4) with IPv6 outer header and IPv4 inner packet.

### Test 24: IPv6-in-IPv4 (Protocol 41)
**Payload Marker**: `TEST_IPIP_IPV6_IN_IPV4`

Tests IPv6-in-IPv4 tunnel (protocol 41) with IPv4 outer header and IPv6 inner packet.

### Test 25: IPv6-in-IPv6 (Protocol 41)
**Payload Marker**: `TEST_IPIP_IPV6_IN_IPV6`

Tests IPv6-in-IPv6 tunnel (protocol 41) with both IPv6 outer and inner headers.

### Test 26: IPv6 Non-Whitelisted Source (Should Drop)
**Payload Marker**: `TEST_GRE_IPV6_BASIC` (should NOT appear)

Sends tunnel traffic from untrusted IPv6 source that is not in the IPv6 whitelist. Uses negative verification to confirm packets were dropped.

### Test 27: Mixed IPv4/IPv6 Tunnel Traffic
**Verification**: Counts markers from both IPv4 and IPv6 tunnel packets

Tests simultaneous processing of IPv4 and IPv6 tunnel traffic from whitelisted sources. Verifies independent whitelist management for both IP versions.

### Test 28: IPv6 Large Payload
**Payload Marker**: `TEST_IPV6_LARGE_PAYLOAD_1400B`

Tests IPv6 GRE tunnel with large 1400-byte payload to verify MTU handling and bounds checking for IPv6 packets.

## Test Coverage Summary

**Total Tests: 28** (19 IPv4 + 9 IPv6)

**Protocol Coverage:**

**IPv4 Tests:**
- GRE IPv4 (basic, checksum, key, sequence, all flags, routing bit)
- IPIP (IPv4-in-IPv4, including large payload)
- Plain traffic (pass-through)

**IPv6 Tests:**
- GRE with IPv6 outer headers (IPv4 inner, IPv6 inner, optional fields)
- IPIP with IPv6 (IPv4-in-IPv6, IPv6-in-IPv4, IPv6-in-IPv6)
- IPv6 whitelist enforcement
- Mixed IPv4/IPv6 traffic
- IPv6 large payload handling

**Full Protocol Support:**
- GRE with IPv4/IPv6 outer headers and IPv4/IPv6 inner packets
- IPIP protocol 4 (IPv4-in-IPv4, IPv4-in-IPv6)
- IPIP protocol 41 (IPv6-in-IPv4, IPv6-in-IPv6)
- Separate whitelist maps for IPv4 and IPv6 source addresses

**Security Testing:**
- IPv4 whitelist enforcement (allowed and blocked sources)
- IPv6 whitelist enforcement (separate map)
- Multiple source verification (IPv4 and IPv6)
- Mixed IPv4/IPv6 whitelist validation

**Robustness Testing:**
- Invalid GRE version
- Truncated packets
- Malformed optional fields
- Mixed traffic bursts (IPv4 and IPv6)
- High volume (100 packets)

**Edge Cases:**
- Large payloads (MTU testing for IPv4 and IPv6)
- All GRE flag combinations
- Deprecated routing flag
- Simultaneous tunnel and plain traffic
- All IPv4/IPv6 outer/inner combinations

## Manual Testing

### Interactive Testing

Start containers without running tests:

```bash
cd tests
docker compose up -d xdp-target tunnel-source untrusted-source
```

Attach to target container:

```bash
docker exec -it xdp-target bash
```

Inside the container, attach XDP program:

```bash
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.eth0.rp_filter=0

# Mount BPF filesystem (required for libxdp and map pinning)
mount -t bpf bpf /sys/fs/bpf

# Load XDP program using xdp-loader
# Use -m skb for Docker veth interfaces (generic mode)
# Use -m native for physical interfaces (better performance, requires driver support)
xdp-loader load -m skb eth0 /build/tun_decap.bpf.o -s xdp

# Add whitelisted IPv4 address (10.200.0.20 = 0a c8 00 14)
bpftool map update pinned /sys/fs/bpf/tun_decap_whitelist \
    key hex 0a c8 00 14 \
    value hex 01

# Add whitelisted IPv6 address (fd00:db8:1::20)
# IPv6: fd00:db8:1::20 = fd 00 0d b8 00 01 00 00 00 00 00 00 00 00 00 20
bpftool map update pinned /sys/fs/bpf/tun_decap_whitelist_v6 \
    key hex fd 00 0d b8 00 01 00 00 00 00 00 00 00 00 00 20 \
    value hex 01

# Check program status
xdp-loader status eth0

# View IPv4 whitelist
bpftool map dump pinned /sys/fs/bpf/tun_decap_whitelist

# View IPv6 whitelist
bpftool map dump pinned /sys/fs/bpf/tun_decap_whitelist_v6

# View statistics
bpftool map dump pinned /sys/fs/bpf/tun_decap_stats
```

In another terminal, generate test packets:

```bash
docker exec -it tunnel-source bash
python3 /usr/local/bin/generate-packets.py --type gre-ipv4 --count 10
```

Monitor traffic on target:

```bash
docker exec xdp-target tcpdump -i eth0 -n
```

### Generate Specific Packet Types

From the tunnel-source or untrusted-source container:

```bash
# GRE IPv4 (basic)
python3 /usr/local/bin/generate-packets.py --type gre-ipv4

# GRE IPv4 with checksum
python3 /usr/local/bin/generate-packets.py --type gre-ipv4-checksum

# GRE IPv4 with key
python3 /usr/local/bin/generate-packets.py --type gre-ipv4-key

# GRE IPv4 with sequence number
python3 /usr/local/bin/generate-packets.py --type gre-ipv4-seq

# GRE IPv4 with all optional fields
python3 /usr/local/bin/generate-packets.py --type gre-ipv4-all-flags

# GRE IPv4 with routing bit
python3 /usr/local/bin/generate-packets.py --type gre-ipv4-routing

# IPIP
python3 /usr/local/bin/generate-packets.py --type ipip

# IPIP with large payload
python3 /usr/local/bin/generate-packets.py --type ipip-large

# Plain traffic
python3 /usr/local/bin/generate-packets.py --type plain

# Invalid GRE version
python3 /usr/local/bin/generate-packets.py --type invalid-gre

# Truncated GRE packet
python3 /usr/local/bin/generate-packets.py --type truncated-gre

# GRE with invalid optional fields
python3 /usr/local/bin/generate-packets.py --type invalid-optional-fields

# Mixed traffic burst
python3 /usr/local/bin/generate-packets.py --type mixed-burst

# All packet types (IPv4)
python3 /usr/local/bin/generate-packets.py --type all

# IPv6 GRE with IPv4 inner
python3 /usr/local/bin/generate-packets.py --type gre-ipv6-outer-ipv4-inner

# IPv6 GRE with IPv6 inner
python3 /usr/local/bin/generate-packets.py --type gre-ipv6-outer-ipv6-inner

# IPv6 GRE with all optional fields
python3 /usr/local/bin/generate-packets.py --type gre-ipv6-all-flags

# IPv4-in-IPv6 (protocol 4)
python3 /usr/local/bin/generate-packets.py --type ipip-ipv4-in-ipv6

# IPv6-in-IPv4 (protocol 41)
python3 /usr/local/bin/generate-packets.py --type ipip-ipv6-in-ipv4

# IPv6-in-IPv6 (protocol 41)
python3 /usr/local/bin/generate-packets.py --type ipip-ipv6-in-ipv6

# IPv6 large payload
python3 /usr/local/bin/generate-packets.py --type ipv6-large

# Mixed IPv4/IPv6 traffic
python3 /usr/local/bin/generate-packets.py --type mixed-ipv4-ipv6

# All packet types (IPv4 and IPv6)
python3 /usr/local/bin/generate-packets.py --type all-with-ipv6
```

### Custom Parameters

```bash
# Send IPv4 GRE from specific source IP
python3 /usr/local/bin/generate-packets.py \
  --type gre-ipv4 \
  --src 10.200.0.30 \
  --dst 10.200.0.10 \
  --inner-src 203.0.113.100 \
  --inner-dst 203.0.113.1 \
  --count 50

# Send IPv6 GRE from specific source
python3 /usr/local/bin/generate-packets.py \
  --type gre-ipv6-outer-ipv4-inner \
  --src fd00:db8:1::30 \
  --dst fd00:db8:1::10 \
  --inner-src 203.0.113.100 \
  --inner-dst 203.0.113.1 \
  --count 50

# Send IPv6-in-IPv6 from specific source
python3 /usr/local/bin/generate-packets.py \
  --type ipip-ipv6-in-ipv6 \
  --src fd00:db8:1::20 \
  --dst fd00:db8:1::10 \
  --inner-src 2001:db8:cafe::100 \
  --inner-dst 2001:db8:cafe::1 \
  --count 50
```

## Troubleshooting

### XDP Program Won't Attach

**"Extension program changes packet data" Error:**

This error occurs on kernel 6.14+ with xdp-tools < 1.5.5:
```
Extension program changes packet data, while original does not
```

**Solution**: Ensure xdp-tools version 1.5.5+ is installed (includes [PR #509](https://github.com/xdp-project/xdp-tools/pull/509) fix). The test container automatically builds this version from source.

**Verify version**:
```bash
docker exec xdp-target xdp-loader --help | head -1
# Should show version >= 1.5.5
```

**Other common issues:**
- **BPF filesystem not mounted**: Most common issue. Mount with `mount -t bpf bpf /sys/fs/bpf`
- Ensure kernel has XDP support: `ls /sys/kernel/btf/vmlinux`
- Check Docker has privileged mode and proper capabilities
- Verify program is compiled: `ls -l ../build/tun_decap.bpf.o`
- Check kernel logs: `docker exec xdp-target dmesg | tail`
- Verify xdp-tools is installed: `docker exec xdp-target which xdp-loader`
- Check xdp-loader status: `docker exec xdp-target xdp-loader status eth0`
- Verify bpffs is mounted: `docker exec xdp-target mount | grep bpf`

### Packets Not Being Decapsulated

**IPv4 Tunnels:**
- Check IPv4 whitelist includes tunnel source IP (10.200.0.20 = 0a c8 00 14)
- Verify rp_filter is disabled: `sysctl net.ipv4.conf.eth0.rp_filter`
- Check IPv4 whitelist: `bpftool map dump pinned /sys/fs/bpf/tun_decap_whitelist`

**IPv6 Tunnels:**
- Check IPv6 whitelist includes tunnel source (fd00:db8:1::20)
- Convert IPv6 address to hex format: fd 00 0d b8 00 01 00 00 00 00 00 00 00 00 00 20
- Check IPv6 whitelist: `bpftool map dump pinned /sys/fs/bpf/tun_decap_whitelist_v6`

**General Debugging:**
- Use tcpdump to see if outer tunnel packets are arriving
- Check XDP program is actually attached: `xdp-loader status eth0` or `ip link show eth0`
- View statistics: `bpftool map dump pinned /sys/fs/bpf/tun_decap_stats`

### Container Network Issues

**IPv4 Connectivity:**
- Ensure Docker network created: `docker network ls`
- Check IPv4 assignments: `docker exec xdp-target ip addr`
- Verify IPv4 routing: `docker exec xdp-target ip route`
- Test IPv4 connectivity: `docker exec tunnel-source ping 10.200.0.10`

**IPv6 Connectivity:**
- Check IPv6 assignments: `docker exec xdp-target ip -6 addr`
- Verify IPv6 routing: `docker exec xdp-target ip -6 route`
- Test IPv6 connectivity: `docker exec tunnel-source ping6 fd00:db8:1::10`
- Ensure IPv6 is enabled: `docker exec xdp-target sysctl net.ipv6.conf.all.disable_ipv6`
  (should be 0)

### IPv6-Specific Issues

**IPv6 packets not being decapsulated:**
- Verify IPv6 whitelist is populated (separate from IPv4):
  ```bash
  bpftool map dump pinned /sys/fs/bpf/tun_decap_whitelist_v6
  ```
- Check IPv6 address format (16 bytes, network byte order)
- Verify IPv6 is enabled in containers: `sysctl net.ipv6.conf.all.disable_ipv6`
- Use tcpdump with IPv6 filter: `tcpdump -i eth0 -n ip6`
- Check statistics for IPv6 counters (indices 3-6)

**IPv6 address conversion issues:**
- Use the Python helper script provided in the BPF Map Management section
- Remember IPv6 addresses must be in network byte order (big-endian)
- Double-check hex format has all 16 bytes (32 hex chars, 16 byte pairs)

### Tests Failing

**First, enable debug mode to see tcpdump output:**
```bash
DEBUG_TCPDUMP=1 ./run-tests.sh
```

This will show you:
- What packets are being captured
- Whether payload markers are visible
- The actual tcpdump ASCII/hex output
- Why verification is failing

**Common issues and solutions:**
- **Markers not found**: Check if packets are using UDP/TCP instead of ICMP (UDP payloads may not show up in ASCII tcpdump)
- **Whitelist issues**: Verify only whitelisted IPs are in the XDP program using bpftool
- **Capture issues**: Make sure tcpdump is running and capturing on the correct interface
- Rebuild containers: `docker compose down -v && docker compose up -d --build`
- Ensure program is built: `make all` from project root
- Check for sufficient system resources (memory, CPU)
- Review test output logs for specific failure messages

## Verification Methods

The test suite uses multiple verification methods to ensure comprehensive validation:

### 1. Inner IP Verification (Primary Method)
- **How it works**: Checks if the inner client IP is visible in tcpdump output after decapsulation
- **Verification**: Uses `tcpdump src <inner_ip>` to count packets with the exposed inner IP
- **Success criteria**: Inner IP visible = packet was decapsulated and IP header is correct
- **Advantage**: Directly validates the program's primary goal (exposing real client IPs)
- **Use case**: All GRE and IPIP decapsulation tests

### 2. Payload Marker Verification (Secondary Method)
- **How it works**: Each test packet contains a unique ASCII payload marker
- **Verification**: tcpdump captures traffic and searches for the marker in ASCII output (`-A` flag)
- **Success criteria**: Marker visible in capture = correct packet was decapsulated
- **Advantage**: Differentiates between test scenarios, confirms packet integrity
- **Note**: Uses `tcpdump -A` (ASCII-only) to allow grep to find markers that span multiple hex dump lines

### 3. Dual Verification (Recommended)
- **How it works**: Combines inner IP check (primary) with payload marker check (secondary)
- **Success criteria**: Both verifications must pass
- **Advantage**: Comprehensive validation - proves decapsulation worked AND correct packet was processed
- **Example**:
  ```bash
  if verify_inner_ip_visible "$INNER_CLIENT_IP" 5; then
      if verify_decap_by_payload "TEST_MARKER" 5 "test description"; then
          print_pass "Test passed"
      fi
  fi
  ```

### 4. Negative Verification (For Dropped Packets)
- **How it works**: Captures traffic and confirms payload markers do NOT appear
- **Use case**: Verifying non-whitelisted sources are dropped
- **Success criteria**: Marker NOT visible = packet was dropped correctly

### 5. Statistics Verification
- **How it works**: Analyzes XDP program statistics using bpftool
- **Use case**: Overall program behavior and counter validation
- **Advantage**: Provides insight into XDP program decisions
- **Command**: `bpftool map dump pinned /sys/fs/bpf/tun_decap_stats`

### 6. Count Verification
- **How it works**: Counts IP occurrences and payload markers in captures
- **Use case**: High volume tests, whitelist enforcement
- **Success criteria**: Count matches expected number of decapsulated packets

## BPF Map Management

### IPv4 Whitelist Map

The IPv4 whitelist map stores allowed IPv4 source addresses for tunnel decapsulation.

**Add IPv4 address to whitelist:**
```bash
# Example: Add 10.200.0.20 (hex: 0a c8 00 14)
bpftool map update pinned /sys/fs/bpf/tun_decap_whitelist \
    key hex 0a c8 00 14 \
    value hex 01
```

**Remove IPv4 address from whitelist:**
```bash
bpftool map delete pinned /sys/fs/bpf/tun_decap_whitelist \
    key hex 0a c8 00 14
```

**List whitelisted IPv4 addresses:**
```bash
bpftool map dump pinned /sys/fs/bpf/tun_decap_whitelist
```

### IPv6 Whitelist Map

The IPv6 whitelist map stores allowed IPv6 source addresses for tunnel decapsulation (separate from IPv4 map).

**Add IPv6 address to whitelist:**
```bash
# Example: Add fd00:db8:1::20
# IPv6 addresses are stored as 16 bytes in network byte order
# fd00:db8:1::20 = fd 00 0d b8 00 01 00 00 00 00 00 00 00 00 00 20
bpftool map update pinned /sys/fs/bpf/tun_decap_whitelist_v6 \
    key hex fd 00 0d b8 00 01 00 00 00 00 00 00 00 00 00 20 \
    value hex 01

# Example: Add 2001:db8::1
# 2001:db8::1 = 20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01
bpftool map update pinned /sys/fs/bpf/tun_decap_whitelist_v6 \
    key hex 20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01 \
    value hex 01

# Example: Add fe80::1 (link-local)
# fe80::1 = fe 80 00 00 00 00 00 00 00 00 00 00 00 00 00 01
bpftool map update pinned /sys/fs/bpf/tun_decap_whitelist_v6 \
    key hex fe 80 00 00 00 00 00 00 00 00 00 00 00 00 00 01 \
    value hex 01
```

**Remove IPv6 address from whitelist:**
```bash
# Example: Remove fd00:db8:1::20
bpftool map delete pinned /sys/fs/bpf/tun_decap_whitelist_v6 \
    key hex fd 00 0d b8 00 01 00 00 00 00 00 00 00 00 00 20
```

**List whitelisted IPv6 addresses:**
```bash
bpftool map dump pinned /sys/fs/bpf/tun_decap_whitelist_v6
```

**Helper: Convert IPv6 to hex format:**
```bash
# Use Python to convert IPv6 address to hex
python3 -c "import socket; import binascii; print(binascii.hexlify(socket.inet_pton(socket.AF_INET6, 'fd00:db8:1::20')).decode())"
# Output: fd000db80001000000000000000000020

# Format for bpftool (add spaces between bytes)
python3 -c "import socket; import binascii; h=binascii.hexlify(socket.inet_pton(socket.AF_INET6, 'fd00:db8:1::20')).decode(); print(' '.join(h[i:i+2] for i in range(0, len(h), 2)))"
# Output: fd 00 0d b8 00 01 00 00 00 00 00 00 00 00 00 20
```

### Statistics Map

View packet processing statistics:

```bash
bpftool map dump pinned /sys/fs/bpf/tun_decap_stats
```

Statistics indices:
- 0: RX total (all packets)
- 1: RX GRE packets
- 2: RX IPIP packets
- 3: RX IPv6-in-IPv4 (protocol 41) packets
- 4: RX IPv6 outer header packets
- 5: RX GRE with IPv6 inner packets
- 6: RX IPIP with IPv6 inner packets
- 7: Decapsulation success
- 8: Decapsulation failed
- 9: Dropped (not whitelisted)
- 10: Dropped (malformed)
- 11: Passed (non-tunnel)

**Note**: Statistics are per-CPU counters. To get total counts, sum values across all CPUs.

## Continuous Integration

These tests are suitable for CI/CD pipelines. Example usage:

```bash
#!/bin/bash
set -e

# Build project
make all

# Run integration tests
cd tests
./run-tests.sh

# Exit code 0 = all tests passed
```

## Test Execution Time

Expected test execution time: ~3-4 minutes for all 28 tests (19 IPv4 + 9 IPv6).
- Container startup: ~10-15 seconds
- XDP program attachment: ~5 seconds
- Test execution: ~2-3 minutes
- Cleanup: ~5 seconds
