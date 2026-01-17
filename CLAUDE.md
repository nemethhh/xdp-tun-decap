# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an XDP (eXpress Data Path) program for high-performance decapsulation of GRE and IPIP tunnel traffic. It operates in kernel space for line-rate packet processing with whitelist-based access control.

## Build Commands

```bash
# Full build (vmlinux.h + BPF object + skeleton)
make all

# Generate vmlinux.h from running kernel's BTF
make vmlinux

# Compile BPF program only
make bpf

# Generate BPF skeleton header for userspace
make skel

# Build test binary
make test-build

# Run tests (requires root)
make test

# Verify BPF program loads successfully
sudo make verify

# Show BPF disassembly for debugging
make dump

# Show BTF type information
make btf

# Clean build artifacts
make clean
```

## Testing

### Unit Tests
```bash
# Build and run unit tests (uses BPF_PROG_TEST_RUN)
make test
```

### Integration Tests
```bash
# Run Docker-based integration tests
cd tests
./run-tests.sh

# Debug mode (shows tcpdump output)
DEBUG_TCPDUMP=1 ./run-tests.sh

# Manual container management
docker compose up -d --build
./run-integration-tests.sh
docker compose down -v
```

Integration tests use Docker containers with tcpdump-based verification. Tests verify decapsulation by searching for unique payload markers in packet captures.

## Architecture

### Core Components

**Main XDP Program** (`src/bpf/tun_decap.bpf.c`):
- Entry point: `xdp_tun_decap()` - processes every incoming packet
- Returns `XDP_PASS` to chain to next program or `XDP_DROP` to block
- Configured for libxdp multi-program support with priority 10 (runs early)

**Packet Processing Flow**:
1. Parse Ethernet and IPv4 headers
2. Check protocol: GRE (47) or IPIP (4)
3. Verify source IP against whitelist (per-CPU hash map lookup)
4. Calculate decapsulation length (outer IP + tunnel header)
5. Call `decapsulate()` which:
   - Saves Ethernet header to stack
   - Calls `bpf_xdp_adjust_head()` to remove outer headers
   - **CRITICAL**: Refetches `ctx->data` and `ctx->data_end` (all pointers invalidated)
   - Restores Ethernet header at new position
   - Updates EtherType to IPv4

**GRE Handling** (`handle_gre()`):
- Validates GRE version must be 0
- Only decapsulates IPv4 inner packets (not IPv6)
- Handles optional fields: checksum, key, sequence number
- Variable header length: 4-16 bytes depending on flags

**IPIP Handling** (`handle_ipip()`):
- No tunnel header, just IPv4-in-IPv4
- Only removes outer IP header
- Validates inner IP header (version 4, IHL >= 5)

### BPF Maps

Three pinned maps (accessible via `/sys/fs/bpf/tun_decap_*`):

1. **Whitelist** (`BPF_MAP_TYPE_PERCPU_HASH`):
   - Key: IPv4 address (network byte order)
   - Value: `struct whitelist_value` (simple flag)
   - Lock-free per-CPU lookups for performance

2. **Statistics** (`BPF_MAP_TYPE_PERCPU_ARRAY`):
   - Per-CPU counters: rx_total, rx_gre, rx_ipip, decap_success, decap_failed, drop_not_whitelisted, drop_malformed, pass_non_tunnel
   - Indices defined in `enum stat_idx` (src/include/tun_decap.h:26)

3. **Config** (`BPF_MAP_TYPE_ARRAY`):
   - Runtime control to disable processing (processing is **enabled by default**)
   - Uses inverted logic: zero-initialized map = all processing enabled
   - Fields: `disabled`, `disable_gre`, `disable_ipip` (0=enabled, 1=disabled)
   - No initialization required - works out of the box

### Helper Libraries

**Parsing Helpers** (`src/bpf/parsing.h`):
- `struct hdr_cursor` pattern for tracking parse position
- Verifier-friendly bounds checking functions
- Functions: `parse_ethhdr()`, `parse_iphdr()`, `peek_iphdr()`
- **CRITICAL**: `cursor_reinit()` must be called after `bpf_xdp_adjust_head()`

**GRE Protocol** (`src/bpf/gre.h`):
- `struct gre_base_hdr` definition
- `gre_validate_flags()` - checks version == 0
- `gre_hdr_len()` - calculates variable header length from flags

### Shared Types

`src/include/tun_decap.h` defines types shared between BPF and userspace:
- Statistics indices and names
- Map structures
- Configuration constants
- Protocol numbers

## BPF Verifier Constraints

This program operates under strict BPF verifier rules:

1. **Bounds Checking**: Every pointer dereference requires explicit bounds check comparing against `data_end`
2. **Pointer Invalidation**: After `bpf_xdp_adjust_head()`, ALL previous pointers are invalid and must be refetched from `ctx`
3. **Loop Constraints**: No unbounded loops (must be provably terminating)
4. **Stack Limit**: 512 bytes total stack space
5. **Helper Restrictions**: Only whitelisted BPF helpers allowed (`bpf_xdp_adjust_head`, `bpf_map_lookup_elem`, etc.)

## CO-RE (Compile Once, Run Everywhere)

- Requires `vmlinux.h` generated from running kernel's BTF (`/sys/kernel/btf/vmlinux`)
- Kernel must have `CONFIG_DEBUG_INFO_BTF=y`
- Program is portable across kernel versions without recompilation

## libxdp Multi-Program Support

Configured via `XDP_RUN_CONFIG`:
- **Priority**: 10 (runs early to decapsulate before other XDP programs)
- **Chain actions**: Only `XDP_PASS` chains to next program
- `XDP_DROP` terminates immediately (blocked packets don't continue)

Load multiple programs with: `xdp-loader load -m native eth0 tun_decap.bpf.o other_prog.o`

## Important Implementation Notes

### Protocol Support Limitations
- **GRE**: Only IPv4 inner packets supported (not IPv6)
- **IPIP**: Only protocol 4 (IPv4-in-IPv4), not protocol 41 (IPv6-in-IPv4)

### Docker Testing Environment
- Uses **SKB (generic) mode** for veth interfaces (not native mode)
- Requires xdp-tools >= 1.5.5 for kernel 6.14+ (fixes packet modification issue)
- Integration tests use tcpdump verification with unique payload markers

### BPF Compilation
- **Must use `-O2`**: Verifier requires optimized code
- **Must include `-g`**: Generates BTF debug info for CO-RE
- **Target**: `-target bpf -mcpu=v3` (kernel 5.1+, enables atomics/ALU32)

## Managing BPF Maps

```bash
# Mount BPF filesystem (required for pinned maps)
sudo mount -t bpf bpf /sys/fs/bpf

# Add IP to whitelist (example: 10.200.0.20 = 0a c8 00 14)
sudo bpftool map update pinned /sys/fs/bpf/tun_decap_whitelist \
    key hex 0a c8 00 14 value hex 01

# Remove IP from whitelist
sudo bpftool map delete pinned /sys/fs/bpf/tun_decap_whitelist \
    key hex 0a c8 00 14

# View whitelist
sudo bpftool map dump pinned /sys/fs/bpf/tun_decap_whitelist

# Runtime configuration (processing is ENABLED by default, no init needed)
# Disable all processing: set disabled=1
sudo bpftool map update pinned /sys/fs/bpf/tun_decap_config \
    key hex 00 00 00 00 value hex 01 00 00 00

# Disable only GRE: set disable_gre=1
sudo bpftool map update pinned /sys/fs/bpf/tun_decap_config \
    key hex 00 00 00 00 value hex 00 01 00 00

# Disable only IPIP: set disable_ipip=1
sudo bpftool map update pinned /sys/fs/bpf/tun_decap_config \
    key hex 00 00 00 00 value hex 00 00 01 00

# Re-enable everything: set all to 0
sudo bpftool map update pinned /sys/fs/bpf/tun_decap_config \
    key hex 00 00 00 00 value hex 00 00 00 00

# View current config
sudo bpftool map dump pinned /sys/fs/bpf/tun_decap_config

# View statistics (per-CPU, userspace must aggregate)
sudo bpftool map dump pinned /sys/fs/bpf/tun_decap_stats
```

## Loading/Unloading XDP Program

```bash
# Load with xdp-loader (recommended, supports multi-program)
sudo xdp-loader load -m native eth0 build/tun_decap.bpf.o

# Check status
sudo xdp-loader status eth0

# Unload
sudo xdp-loader unload eth0 --all

# Alternative: Load with ip link (single program only)
sudo ip link set dev eth0 xdp obj build/tun_decap.bpf.o sec xdp

# Unload with ip link
sudo ip link set dev eth0 xdp off

# Clean up pinned maps
sudo rm -f /sys/fs/bpf/tun_decap_*
```

## Common Development Patterns

### Adding New Tunnel Protocol
1. Add protocol number constant to `src/include/tun_decap.h`
2. Create handler function `handle_<protocol>()` in `src/bpf/tun_decap.bpf.c`
3. Add case to switch statement in `xdp_tun_decap()`
4. Add statistics counters to `enum stat_idx`
5. Add test cases to `src/test/test_decap.c` and integration tests

### Modifying Packet Processing
- Always check bounds before dereferencing: `if ((void *)(ptr + 1) > data_end)`
- After `bpf_xdp_adjust_head()`, refetch: `data = (void *)(long)ctx->data`
- Use `__always_inline` for helper functions (no BPF-to-BPF calls in old kernels)
- Keep stack usage minimal (512 byte limit)

### Debugging BPF Programs
```bash
# Check program loaded successfully
sudo bpftool prog show

# View program disassembly
make dump

# Check kernel logs for verifier errors
sudo dmesg | grep -i bpf

# Trace BPF program execution (requires kernel tracing)
sudo bpftool prog tracelog
```

## Dependencies

Build requirements:
- clang/LLVM (BPF backend)
- bpftool (skeleton generation, map management)
- libbpf-dev (BPF library)
- libxdp-dev (multi-program support, optional but recommended)

Runtime requirements:
- Linux kernel 5.17+ with `CONFIG_DEBUG_INFO_BTF=y`
- XDP-capable network interface (or use SKB mode)
