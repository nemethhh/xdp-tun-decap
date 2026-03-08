# XDP Tunnel Decapsulation

High-performance XDP program for decapsulating GRE and IPIP tunnel traffic with whitelist-based access control.

## Features

- **GRE decapsulation** (protocol 47) - RFC 2784/2890 compliant
- **IPIP decapsulation** (protocol 4) - RFC 2003 compliant
- **libxdp multi-program support** - Works alongside other XDP programs
- **Fast whitelist lookups** - O(1) hash map lookups with RCU protection (compile-time configurable)
- **CO-RE support** - Compile Once, Run Everywhere portability
- **Comprehensive statistics** - 14 per-CPU counters for monitoring (compile-time configurable)

## Requirements

- Linux kernel 5.17+ with `CONFIG_DEBUG_INFO_BTF=y`
- clang/LLVM (for BPF compilation)
- bpftool (for skeleton generation)
- libbpf-dev (BPF library)
- libxdp-dev (optional, for multi-program support)

### Installing dependencies

**Fedora/RHEL:**
```bash
sudo dnf install clang llvm bpftool libbpf-devel libxdp-devel
```

**Debian/Ubuntu:**
```bash
sudo apt install clang llvm linux-tools-generic libbpf-dev libxdp-dev
```

## Building

```bash
# Build everything (BPF program + skeleton)
make all

# Build and run tests
make test-helpers          # Helper tests (no root required)
make test                  # All unit tests (requires root)
make test-all              # Unit + integration tests

# Verify program loads correctly
sudo make verify

# Show all available targets
make help
```

### Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `WHITELIST=0` | `1` (enabled) | Disable whitelist enforcement. Removes whitelist maps and lookups entirely for maximum throughput when source filtering is not needed. |
| `STATS=1` | `0` (disabled) | Enable per-CPU statistics counters. Adds one map lookup per packet for 14 monitoring counters. |

```bash
# Build without whitelist (no source IP filtering)
make all WHITELIST=0

# Build with statistics enabled
make all STATS=1

# Build with both disabled for maximum performance
make all WHITELIST=0 STATS=0

# Compare instruction counts
make analyze WHITELIST=1    # ~460 instructions
make analyze WHITELIST=0    # ~419 instructions
```

Options must be passed consistently to all make targets in a session (e.g., `make all WHITELIST=0 && make test WHITELIST=0`).

## Usage

### Loading the XDP program

```bash
# Using xdp-loader (recommended for multi-program)
xdp-loader load -m native eth0 build/tun_decap.bpf.o

# Or using ip link directly
sudo ip link set dev eth0 xdp obj build/tun_decap.bpf.o sec xdp
```

### Managing the whitelist

> **Note:** Whitelist maps only exist when built with `WHITELIST=1` (the default). When built with `WHITELIST=0`, all tunnel traffic is decapsulated without source IP filtering.

The whitelist map is pinned at `/sys/fs/bpf/tun_decap_whitelist`.

```bash
# Add an IP to whitelist (10.0.0.1)
sudo bpftool map update pinned /sys/fs/bpf/tun_decap_whitelist \
    key hex 0a 00 00 01 value hex 01

# Remove an IP from whitelist
sudo bpftool map delete pinned /sys/fs/bpf/tun_decap_whitelist \
    key hex 0a 00 00 01

# List all whitelisted IPs
sudo bpftool map dump pinned /sys/fs/bpf/tun_decap_whitelist
```

### Viewing statistics

```bash
# Dump all statistics (single struct with 14 counters per CPU)
sudo bpftool map dump pinned /sys/fs/bpf/tun_decap_stats

# Or use the Python manager tool for formatted output:
sudo python3 map_manager/xdp_tun_decap_manager.py stats

# Statistics fields (struct tun_decap_stats):
#  0 - rx_total               (Total packets received)
#  1 - rx_gre                 (GRE tunnel packets)
#  2 - rx_ipip                (IPIP tunnel packets)
#  3 - rx_ipv6_in_ipv4        (IPv6-in-IPv4 tunnel packets)
#  4 - rx_ipv6_outer          (Packets with IPv6 outer header)
#  5 - rx_gre_ipv6_inner      (GRE with IPv6 inner)
#  6 - rx_ipip_ipv6_inner     (IPIP with IPv6 inner)
#  7 - rx_ipv6_in_ipv6        (IPv6-in-IPv6 tunnel packets)
#  8 - decap_success          (Successfully decapsulated)
#  9 - decap_failed           (Decapsulation failures)
# 10 - drop_not_whitelisted   (Dropped: not whitelisted)
# 11 - drop_malformed         (Dropped: malformed packet)
# 12 - drop_fragmented        (Dropped: fragmented outer)
# 13 - pass_non_tunnel        (Non-tunnel traffic passed)
```

### Runtime configuration

Runtime configuration is stored as a BPF global variable (`cfg_global`) in the program's `.bss` map. Fields are zero-initialized, meaning all processing is enabled by default with no bypass. Configuration can be modified at any time while the program is running.

**Config fields (`struct tun_decap_config`):**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `disabled` | `__u8` | 0 | Master disable switch (1=disable all processing) |
| `disable_gre` | `__u8` | 0 | Disable GRE decapsulation |
| `disable_ipip` | `__u8` | 0 | Disable IPIP decapsulation |
| `disable_stats` | `__u8` | 0 | Disable statistics collection |
| `bypass_dst_net` | `__be32` | 0 | Inner destination subnet to skip decap (network byte order, 0=disabled) |
| `bypass_dst_mask` | `__be32` | 0 | Subnet mask for bypass (network byte order) |

To modify configuration, find the `.bss` map ID and update it with `bpftool`:

```bash
# Find the .bss map ID
bpftool map show | grep bss
# Example output: 11: array  name tun_deca.bss  flags 0x400

# View current config
bpftool map dump id <MAP_ID>

# Disable all processing
bpftool map update id <MAP_ID> \
    key hex 00 00 00 00 \
    value hex 01 00 00 00 00 00 00 00 00 00 00 00

# Re-enable all processing (reset to defaults)
bpftool map update id <MAP_ID> \
    key hex 00 00 00 00 \
    value hex 00 00 00 00 00 00 00 00 00 00 00 00
```

#### Bypass destination subnet

When the XDP program is attached to an interface that also terminates a kernel GRE tunnel, it will decapsulate all GRE packets — including control plane traffic (BGP keepalives, health checks) that the kernel tunnel needs to process. This causes the kernel tunnel to lose connectivity.

The bypass destination subnet solves this: packets whose inner IPv4 destination matches the configured subnet are passed through to the kernel without decapsulation.

**Example:** A server runs a GRE tunnel to Imperva for BGP route announcements. The tunnel uses subnet `172.20.5.48/30`. Clean traffic (destined to VIPs) should be decapsulated by XDP, but tunnel control traffic (destined to `172.20.5.48/30`) must reach the kernel GRE interface intact.

```bash
# Load XDP program
sudo ip link set dev enp1s0 xdp obj build/tun_decap.bpf.o sec xdp

# Find .bss map ID
bpftool map show | grep bss

# Set bypass for 172.20.5.48/30
# Value layout: [disabled, disable_gre, disable_ipip, disable_stats,
#                bypass_dst_net (4 bytes), bypass_dst_mask (4 bytes)]
#
# 172.20.5.48 = ac 14 05 30
# /30 mask    = ff ff ff fc
bpftool map update id <MAP_ID> \
    key hex 00 00 00 00 \
    value hex 00 00 00 00 ac 14 05 30 ff ff ff fc

# Verify config
bpftool map dump id <MAP_ID>

# Verify kernel tunnel still works
birdc show protocols  # BGP session should stay Established
```

To disable the bypass (decapsulate everything), set `bypass_dst_net` back to zero:

```bash
bpftool map update id <MAP_ID> \
    key hex 00 00 00 00 \
    value hex 00 00 00 00 00 00 00 00 00 00 00 00
```

### Unloading

```bash
# Using xdp-loader
xdp-loader unload eth0 --all

# Or using ip link
sudo ip link set dev eth0 xdp off

# Clean up pinned maps
sudo rm -f /sys/fs/bpf/tun_decap_*
```

## Architecture

### Packet Flow

```
Incoming Packet
      │
      ▼
┌─────────────────┐
│ Parse Ethernet  │
│ Parse IPv4/IPv6 │
└────────┬────────┘
         │
    ┌────┴────┐
    │Protocol?│
    └────┬────┘
         │
    ┌────┼────┐
    ▼    ▼    ▼
   GRE  IPIP Other
    │    │    │
    ▼    ▼    │
┌────────────┐│
│ Whitelist  ││  (only with WHITELIST=1)
│   Check    ││
└─────┬──────┘│
      │       │
   ┌──┴──┐    │
   ▼     ▼    │
  OK   DROP   │
   │          │
   ▼          │
┌──────────┐  │
│ Decap    │  │
│ (adjust  │  │
│  head)   │  │
└────┬─────┘  │
     │        │
     ▼        ▼
    XDP_PASS (chain to next program)
```

### Map Definitions

| Map | Type | Purpose | Compile flag |
|-----|------|---------|--------------|
| `tun_decap_whitelist` | HASH | IPv4 source whitelist (RCU-protected) | `WHITELIST=1` |
| `tun_decap_whitelist_v6` | HASH | IPv6 source whitelist (RCU-protected) | `WHITELIST=1` |
| `tun_decap_stats` | PERCPU_ARRAY | Per-CPU statistics (single struct with 14 counters) | `STATS=1` |

**Note:** Runtime configuration is stored as a BPF global variable (`cfg_global`), accessible via the program's `.bss` map. Maps marked with a compile flag are only present when built with that flag enabled.

## libxdp Multi-Program Support

This program is designed to work with libxdp's multi-program dispatcher:

- **Priority**: 10 (runs early to decapsulate before other programs)
- **Chain on XDP_PASS**: Decapsulated and non-tunnel traffic continues to next program
- **Don't chain on XDP_DROP**: Blocked traffic terminates immediately

To use with other XDP programs:

```bash
# Load multiple programs (they chain automatically)
xdp-loader load -m native eth0 tun_decap.bpf.o other_prog.o
```

## Testing

The project includes three levels of testing:

### 1. Helper Unit Tests (No Root Required)

Fast userspace tests for helper functions that **don't require elevated permissions**:

```bash
# Run helper tests only (no sudo needed)
make test-helpers

# Build helper test binaries
make test-helpers-build
```

**Coverage:**
- **Parsing helpers** (`test_parsing_helpers`) - 23 tests
  - Cursor management and bounds checking
  - Ethernet/IPv4/IPv6 header parsing
  - Multi-layer packet parsing
- **GRE protocol helpers** (`test_gre_helpers`) - 26 tests
  - Header length calculation with various flags
  - Flag validation (RFC 2784 compliance)
  - Key extraction with/without checksum
- **IPv6 and shared types** (`test_ipv6_helpers`) - 22 tests
  - IPv6 address structure and conversion
  - Configuration structure validation
  - Constants and enum values

**Total: 71 tests** running in **< 0.1 seconds** without kernel interaction.

### 2. BPF Unit Tests (Requires Root)

Tests actual XDP program execution using `BPF_PROG_TEST_RUN`:

```bash
# Run BPF tests only (requires root)
make test-bpf

# Run all unit tests (helper + BPF)
make test
```

**Coverage:**
- GRE decapsulation with whitelisted source
- GRE drop for non-whitelisted source
- GRE with optional fields (key, checksum, sequence)
- GRE with IPv6 inner packets
- IPIP decapsulation (IPv4-in-IPv4)
- IPv6-in-IPv4 decapsulation (protocol 41)
- IPv6 outer header handling
- IPv4-in-IPv6 and IPv6-in-IPv6 decapsulation
- Non-tunnel traffic passthrough
- Malformed packet handling
- Statistics accuracy

### 3. Integration Tests (Requires Root + Docker)

End-to-end tests with real network interfaces and packet capture:

```bash
# Run Docker-based integration tests
make integration-test

# Run all tests (unit + integration)
make test-all
```

**Coverage:**
- Real packet decapsulation on veth interfaces
- tcpdump verification with unique payload markers
- Multi-container network isolation

### Test Organization

| Test Type | Files | Requires Root? | Run Time | What It Tests |
|-----------|-------|----------------|----------|---------------|
| Helper tests | `test_*_helpers.c` | ❌ No | ~0.1s | Pure C helper functions |
| BPF tests | `test_decap.c` | ✅ Yes | ~2s | XDP program logic |
| Integration | `tests/*.sh` | ✅ Yes | ~30s | End-to-end packet flow |

### Quick Test Commands

```bash
# Fast development feedback (no root)
make test-helpers

# Full unit test suite
make test

# Everything (unit + integration)
make test-all

# Verify BPF program loads successfully
sudo make verify
```

## Python Tools

### Map Manager (`map_manager/`)

Python tool for managing BPF maps (no external dependencies):

```bash
cd map_manager

# Add IPs to whitelist (auto-detects IPv4/IPv6)
sudo python3 xdp_tun_decap_manager.py whitelist-add 10.200.0.20
sudo python3 xdp_tun_decap_manager.py whitelist-add 2001:db8::1

# View statistics (aggregated across all CPUs)
sudo python3 xdp_tun_decap_manager.py stats
```

**Note:** Runtime configuration is now a BPF global variable. To modify config, use `bpftool` to update the program's `.bss` map (see [map_manager/README.md](map_manager/README.md) for details).

See [map_manager/README.md](map_manager/README.md) for complete documentation.

### Prometheus Exporter (`prometheus_exporter/`)

Export XDP statistics as Prometheus metrics:

```bash
cd prometheus_exporter

# Install dependencies
pip3 install -r requirements.txt

# Run exporter
sudo python3 xdp_tun_decap_exporter.py --address 0.0.0.0 --port 9100

# View metrics
curl http://localhost:9100/metrics | grep xdp_tun_decap
```

See [prometheus_exporter/README.md](prometheus_exporter/README.md) for complete documentation.

## Project Structure

```
xdp-tun-decap/
├── src/                       # XDP BPF program source code
│   ├── bpf/
│   │   ├── vmlinux.h          # Generated kernel types (CO-RE)
│   │   ├── tun_decap.bpf.c    # Main XDP program
│   │   ├── gre.h              # GRE protocol definitions
│   │   └── parsing.h          # Packet parsing helpers
│   ├── include/
│   │   └── tun_decap.h        # Shared types (BPF + userspace)
│   └── test/
│       ├── test_decap.c             # BPF unit tests (requires root)
│       ├── test_packets.h           # Test packet data
│       ├── test_parsing_helpers.c   # Parsing helpers tests (no root)
│       ├── test_gre_helpers.c       # GRE helpers tests (no root)
│       └── test_ipv6_helpers.c      # IPv6/config tests (no root)
├── map_manager/               # BPF map management tool
│   ├── xdp_tun_decap_manager.py
│   ├── README.md
│   └── QUICKSTART.md
├── prometheus_exporter/       # Prometheus metrics exporter
│   ├── xdp_tun_decap_exporter.py
│   ├── README.md
│   ├── QUICKSTART.md
│   └── docker-compose.lint.yml  # Linting infrastructure
├── tests/                     # Integration tests (Docker-based)
├── build/                     # Build output
├── Makefile
├── README.md                  # This file
└── CLAUDE.md                  # Technical documentation
```

## License

GPL-2.0-or-later
