# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an XDP (eXpress Data Path) program for high-performance decapsulation of GRE and IPIP tunnel traffic. It operates in kernel space for line-rate packet processing with whitelist-based access control.

**Key Features:**
- Full IPv6 support: handles IPv4/IPv6 inner and outer headers
- GRE tunnel decapsulation (protocol 47)
- IPIP tunnel decapsulation (IPv4-in-IPv4, protocol 4)
- IPv6-in-IPv4 tunnel decapsulation (protocol 41)
- IPv6 outer header support (IPv6 GRE, IPv4/IPv6-in-IPv6)
- Per-CPU hash maps for lock-free whitelist lookups (IPv4 and IPv6)
- Separate whitelist maps for IPv4 and IPv6 addresses
- Comprehensive statistics tracking

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

# Build benchmark binary
make bench-build

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

### Benchmarks
```bash
# Run per-packet benchmarks with hardware counters (requires root)
sudo make bench

# With custom iteration count
sudo build/bench_decap --repeat 1000000 --warmup 1000

# Skip hardware counters (for VMs without PMU access)
sudo build/bench_decap --no-hwcounters

# Benchmarks wrapped in perf stat for aggregate hardware counter view
sudo make bench-perf

# Static BPF instruction count analysis (no root required)
make analyze

# Compare stats-enabled vs disabled instruction counts
make analyze STATS=0
make analyze STATS=1
```

The benchmark binary (`src/test/bench_decap.c`) uses `BPF_PROG_TEST_RUN` with `repeat=N` for kernel-measured per-packet latency, and `perf_event_open()` for hardware PMU counters (instructions, cycles, IPC, L1 cache misses). It covers 18 packet types across all code paths (decap, drop, passthrough).

### Profiling
```bash
# Full profiling: starts Docker, generates traffic, produces flame chart
sudo make profile

# Quick mode (containers already running)
sudo make profile-quick

# Custom traffic volume and sampling frequency
sudo scripts/profile.sh --count 5000 --freq 19999
```

Profiling outputs to `build/profile/`:
- `flamegraph.svg` - interactive flame chart (open in browser)
- `bpf-stats.txt` - BPF program runtime statistics (`run_time_ns`, `run_cnt`)
- `bpftool-profile.txt` - per-program hardware counter stats
- `perf.data` - raw perf data for further analysis

Requires: `perf`, `bpftool`, `docker`, and FlameGraph tools in `tools/flamegraph/`.

## Architecture

### Core Components

**Main XDP Program** (`src/bpf/tun_decap.bpf.c`):
- Entry point: `xdp_tun_decap()` - processes every incoming packet
- Returns `XDP_PASS` to chain to next program or `XDP_DROP` to block
- Configured for libxdp multi-program support with priority 10 (runs early)

**Packet Processing Flow**:
1. Lookup config and stats maps ONCE at entry (2 map lookups total for entire packet)
2. Parse Ethernet and IPv4/IPv6 headers
3. Check protocol: GRE (47), IPIP (4), or IPv6-in-IPv4 (41)
4. Verify source IP against whitelist (per-CPU hash map lookup)
5. Calculate decapsulation length (outer IP + tunnel header)
6. Call `decapsulate()` which uses **forward-copy technique**:
   - Copies MAC addresses forward to new position (before adjust)
   - Sets EtherType at new position
   - Calls `bpf_xdp_adjust_head()` to remove outer headers
   - No post-adjust pointer refetch or restore needed

**Performance Optimizations** (Katran-inspired):
- **Single-struct stats**: All 14 counters in one map entry = 1 lookup instead of N
- **Single config lookup**: Config checked once at entry, not per stat update
- **Forward-copy decap**: MAC copied forward before adjust, avoids stack save/restore

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

1. **IPv4 Whitelist** (`BPF_MAP_TYPE_PERCPU_HASH`):
   - Key: IPv4 address (32-bit, network byte order)
   - Value: `struct whitelist_value` (simple flag)
   - Lock-free per-CPU lookups for performance
   - Map name: `tun_decap_whitelist`

1b. **IPv6 Whitelist** (`BPF_MAP_TYPE_PERCPU_HASH`):
   - Key: IPv6 address (128-bit, struct ipv6_addr with 4x 32-bit words)
   - Value: `struct whitelist_value` (simple flag)
   - Separate map for efficient key management
   - Map name: `tun_decap_whitelist_v6`

2. **Statistics** (`BPF_MAP_TYPE_PERCPU_ARRAY`):
   - **Single entry** containing `struct tun_decap_stats` with all 14 counters
   - ONE `bpf_map_lookup_elem` per packet, then direct field increments
   - Per-CPU counters (fields of `struct tun_decap_stats`):
     - `rx_total`: Total packets received
     - `rx_gre`, `rx_ipip`: GRE/IPIP packets received
     - `rx_ipv6_in_ipv4`: IPv6-in-IPv4 (protocol 41) packets
     - `rx_ipv6_outer`: IPv6 outer header packets
     - `rx_gre_ipv6_inner`, `rx_ipip_ipv6_inner`: IPv6 inner packet counters
     - `rx_ipv6_in_ipv6`: IPv6-in-IPv6 tunnel packets
     - `decap_success`, `decap_failed`: Decapsulation results
     - `drop_not_whitelisted`, `drop_malformed`, `drop_fragmented`: Drop reasons
     - `pass_non_tunnel`: Non-tunnel traffic passed through
   - Structure defined in `struct tun_decap_stats` (src/include/tun_decap.h:30)
   - Statistics collection is **enabled by default** but can be disabled via config map

3. **Config** (`BPF_MAP_TYPE_ARRAY`):
   - Runtime control to disable processing (processing is **enabled by default**)
   - Uses inverted logic: zero-initialized map = all processing enabled
   - Fields: `disabled`, `disable_gre`, `disable_ipip`, `disable_stats` (0=enabled, 1=disabled)
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
- `struct tun_decap_stats` - all 14 stat counters in a single struct
- `struct stat_field_info` / `stat_fields[]` - names, descriptions, offsets (userspace)
- `struct whitelist_value`, `struct ipv6_addr` - map key/value types
- `struct tun_decap_config` - runtime configuration
- Protocol numbers and constants

### Benchmark & Profiling Infrastructure

**Benchmark Binary** (`src/test/bench_decap.c`):
- Table-driven: 18 `bench_entry` structs covering all packet types and code paths
- Hardware counters via `perf_event_open()` syscall (cycles, instructions, cache misses)
- Kernel-measured latency via `bpf_test_run_opts.duration` (average ns/run)
- Code path classification (`enum bench_path`) auto-computes map lookup and helper call counts
- CPU pinning (`sched_setaffinity`) for stable measurements
- CLI: `--repeat N`, `--warmup N`, `--no-hwcounters`

**Code Path Operation Counts** (with ENABLE_STATS):

| Path | Config | Stats | Whitelist | adjust_head | Map lookups | Helpers |
|------|:------:|:-----:|:---------:|:-----------:|:-----------:|:-------:|
| Decap (whitelisted) | 1 | 1 | 1 | 1 | 3 | 4 |
| Drop (not whitelisted) | 1 | 1 | 1 | 0 | 3 | 3 |
| Drop (fragmented) | 1 | 1 | 0 | 0 | 2 | 2 |
| Drop (malformed) | 1 | 1 | 1 | 0 | 3 | 3 |
| Passthrough | 1 | 1 | 0 | 0 | 2 | 2 |

Without ENABLE_STATS: subtract 1 from map lookups and helpers (no stats lookup).

**Profiling Script** (`scripts/profile.sh`):
- Orchestrates perf record during Docker integration test traffic
- Enables `kernel.bpf_stats_enabled` and `net.core.bpf_jit_kallsyms` for BPF visibility
- Generates flame charts via vendored FlameGraph tools (`tools/flamegraph/`)
- Outputs to `build/profile/`

**Static Analysis** (`make analyze`):
- Dumps per-block BPF instruction counts from compiled object via `llvm-objdump`
- Shows total instruction count and section sizes
- All helpers are `__always_inline`, so output shows compiler-generated blocks within the single `xdp_tun_decap` function

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

### Protocol Support
- **GRE**: Supports both IPv4 and IPv6 inner packets
  - IPv4 outer + GRE + IPv4 inner ✓
  - IPv4 outer + GRE + IPv6 inner ✓
  - IPv6 outer + GRE + IPv4 inner ✓
  - IPv6 outer + GRE + IPv6 inner ✓
- **IPIP**: Supports all IP-in-IP combinations
  - IPv4-in-IPv4 (protocol 4) ✓
  - IPv6-in-IPv4 (protocol 41) ✓
  - IPv4-in-IPv6 (protocol 4) ✓
  - IPv6-in-IPv6 (protocol 41) ✓
- **Whitelist**: Supports both IPv4 and IPv6 source addresses
  - IPv4 whitelist: 32-bit addresses (per-CPU hash map)
  - IPv6 whitelist: 128-bit addresses (separate per-CPU hash map)
  - Independent management of IPv4 and IPv6 whitelists

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

# IPv6 Whitelist Management
# Add IPv6 address to whitelist (example: 2001:db8::1)
# IPv6 addresses are stored as 4x 32-bit words in network byte order
# 2001:db8::1 = 20010db8 00000000 00000000 00000001
sudo bpftool map update pinned /sys/fs/bpf/tun_decap_whitelist_v6 \
    key hex 20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01 \
    value hex 01

# Remove IPv6 address from whitelist
sudo bpftool map delete pinned /sys/fs/bpf/tun_decap_whitelist_v6 \
    key hex 20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01

# View IPv6 whitelist
sudo bpftool map dump pinned /sys/fs/bpf/tun_decap_whitelist_v6

# Example: Add 2001:db8::100:20 (common CDN/tunnel endpoint)
# 2001:db8::100:20 = 20010db8 00000000 00000100 00000020
sudo bpftool map update pinned /sys/fs/bpf/tun_decap_whitelist_v6 \
    key hex 20 01 0d b8 00 00 00 00 00 00 01 00 00 00 00 20 \
    value hex 01

# Runtime configuration (processing is ENABLED by default, no init needed)
# Config structure: [disabled, disable_gre, disable_ipip, disable_stats]

# Disable all processing: set disabled=1
sudo bpftool map update pinned /sys/fs/bpf/tun_decap_config \
    key hex 00 00 00 00 value hex 01 00 00 00

# Disable only GRE: set disable_gre=1
sudo bpftool map update pinned /sys/fs/bpf/tun_decap_config \
    key hex 00 00 00 00 value hex 00 01 00 00

# Disable only IPIP: set disable_ipip=1
sudo bpftool map update pinned /sys/fs/bpf/tun_decap_config \
    key hex 00 00 00 00 value hex 00 00 01 00

# Disable statistics collection: set disable_stats=1
sudo bpftool map update pinned /sys/fs/bpf/tun_decap_config \
    key hex 00 00 00 00 value hex 00 00 00 01

# Re-enable everything: set all to 0
sudo bpftool map update pinned /sys/fs/bpf/tun_decap_config \
    key hex 00 00 00 00 value hex 00 00 00 00

# View current config
sudo bpftool map dump pinned /sys/fs/bpf/tun_decap_config

# View statistics (per-CPU struct, userspace must aggregate fields across CPUs)
# Stats map has 1 entry (key=0) containing struct tun_decap_stats per CPU
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

# Clean up pinned maps (removes IPv4 whitelist, IPv6 whitelist, stats, and config)
sudo rm -f /sys/fs/bpf/tun_decap_*
```

## Common Development Patterns

### Adding New Tunnel Protocol
1. Add protocol number constant to `src/include/tun_decap.h`
2. Add counter field(s) to `struct tun_decap_stats` in `src/include/tun_decap.h`
3. Add entry to `stat_fields[]` array and update `STAT_NUM_COUNTERS`
4. Create handler function `handle_<protocol>()` in `src/bpf/tun_decap.bpf.c`
   - Accept `struct tun_decap_stats *stats` parameter
   - Use `if (stats) stats->field++` pattern for counter updates
5. Add case to switch statement in `xdp_tun_decap()`
6. Add test cases to `src/test/test_decap.c` and integration tests
7. Add benchmark entry to `bench_entries[]` in `src/test/bench_decap.c`
   - Define test packet (or add to `test_packets.h` if shared with tests)
   - Set appropriate `enum bench_path` for operation count classification
   - Add whitelist setup if needed (whitelisted IPs are configured in `main()`)

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
- clang/LLVM (BPF backend, also provides `llvm-objdump` for `make analyze`)
- bpftool (skeleton generation, map management)
- libbpf-dev (BPF library)
- libxdp-dev (multi-program support, optional but recommended)

Runtime requirements:
- Linux kernel 5.17+ with `CONFIG_DEBUG_INFO_BTF=y`
- XDP-capable network interface (or use SKB mode)

Benchmark/profiling requirements:
- perf (for `make bench-perf` and `make profile`)
- Docker (for `make profile` integration test profiling)
- Perl (for FlameGraph scripts in `tools/flamegraph/`)
