# XDP Tunnel Decapsulation

High-performance XDP program for decapsulating GRE and IPIP tunnel traffic with whitelist-based access control.

## Features

- **GRE decapsulation** (protocol 47) - RFC 2784/2890 compliant
- **IPIP decapsulation** (protocol 4) - RFC 2003 compliant
- **libxdp multi-program support** - Works alongside other XDP programs
- **Per-CPU whitelist** - Lock-free O(1) lookups
- **CO-RE support** - Compile Once, Run Everywhere portability
- **Comprehensive statistics** - Per-CPU counters for monitoring (configurable at runtime)

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

## Usage

### Loading the XDP program

```bash
# Using xdp-loader (recommended for multi-program)
xdp-loader load -m native eth0 build/tun_decap.bpf.o

# Or using ip link directly
sudo ip link set dev eth0 xdp obj build/tun_decap.bpf.o sec xdp
```

### Managing the whitelist

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
# Dump all statistics
sudo bpftool map dump pinned /sys/fs/bpf/tun_decap_stats

# Statistics indices:
# 0 - RX total
# 1 - RX GRE
# 2 - RX IPIP
# 3 - Decap success
# 4 - Decap failed
# 5 - Drop (not whitelisted)
# 6 - Drop (malformed)
# 7 - Pass (non-tunnel)
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
│ Parse IPv4      │
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
│ Whitelist  ││
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

| Map | Type | Purpose |
|-----|------|---------|
| `tun_decap_whitelist` | PERCPU_HASH | Source IP whitelist |
| `tun_decap_stats` | PERCPU_ARRAY | Per-CPU statistics |
| `tun_decap_config` | ARRAY | Runtime configuration |

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

# Runtime configuration
sudo python3 xdp_tun_decap_manager.py config-disable-gre
sudo python3 xdp_tun_decap_manager.py config-disable-stats  # Disable statistics for performance
sudo python3 xdp_tun_decap_manager.py config-show

# View statistics
sudo python3 xdp_tun_decap_manager.py stats
```

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
