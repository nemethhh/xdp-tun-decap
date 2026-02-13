# Plan: Add Profiling, Hardware Counters & Flame Charts to XDP Test Suite

## Context

The XDP tunnel decapsulation program has unit tests (`BPF_PROG_TEST_RUN`) and integration tests (Docker + tcpdump), but no performance measurement or profiling. The goal is to add:
1. **Benchmark mode** for unit tests — per-packet-type latency, hardware counters (instructions, cycles, cache misses), and operation counts
2. **Profiling with flame charts** for integration tests — perf-based profiling during real traffic

**BPF memory model note:** BPF programs have no dynamic memory allocation (no malloc/free). Memory is: stack (512B max), map values (kernel-managed), and packet buffer (XDP). The meaningful metrics are hardware counters (instructions, cycles, cache behavior) and map/helper operation counts per code path.

---

## Part A: Unit Test Benchmarks (`make bench`)

### New file: `src/test/bench_decap.c`

A separate benchmark binary (not a flag on the existing test binary). Table-driven design.

**Core approach**: Use `perf_event_open()` syscall to read hardware PMU counters directly around each `bpf_prog_test_run_opts()` call. This gives **per-packet-type** breakdowns without external tools.

#### Data structure

```c
struct bench_entry {
    const char *name;
    void *pkt;
    size_t pkt_len;
    /* Whitelist setup */
    int needs_ipv4_whitelist;
    __u32 ipv4_whitelist_ip;
    int needs_ipv6_whitelist;
    __u32 ipv6_whitelist_ip[4];
    /* Static analysis: known operation counts per path */
    int map_lookups;      /* bpf_map_lookup_elem calls */
    int helper_calls;     /* total BPF helper calls (map lookups + adjust_head) */
};
```

~17 entries covering: GRE (basic, key, checksum, IPv6 inner), IPIP, IPv6-in-IPv4, IPv6 outer combos, passthrough (TCP/UDP/IPv6), drops (blocked, fragmented, truncated).

#### Hardware counter measurement

Use `perf_event_open()` to create counters for:
- `PERF_COUNT_HW_CPU_CYCLES` — cycles per packet
- `PERF_COUNT_HW_INSTRUCTIONS` — instructions per packet
- `PERF_COUNT_HW_CACHE_REFERENCES` — L1 cache accesses per packet
- `PERF_COUNT_HW_CACHE_MISSES` — L1 cache misses per packet

Read counters before/after `bpf_prog_test_run_opts(repeat=N)`, divide delta by N.

```c
struct perf_counters {
    int fd_cycles;
    int fd_instructions;
    int fd_cache_refs;
    int fd_cache_misses;
};

/* Read all counters, run benchmark, read again, compute delta/repeat */
```

#### Output format

```
XDP Tunnel Decap Benchmarks (repeat=100000, warmup=1000)

Packet Type                       Verdict  ns/pkt   Mpps  insns/pkt  cycles/pkt  IPC   L1-miss/pkt  map-lookups  helpers
---                               -------  ------   ----  ---------  ----------  ---   -----------  -----------  -------
GRE IPv4 (whitelisted)            PASS         47  21.28        142         156  0.91         0.12            3        4
GRE IPv4 (blocked)                DROP         38  26.32         98         126  0.78         0.08            3        3
IPIP IPv4 (whitelisted)           PASS         42  23.81        118         140  0.84         0.10            3        4
TCP passthrough                   PASS         18  55.56         45          60  0.75         0.02            1        1
...

Summary:
  Fastest: TCP passthrough (18 ns, 55.56 Mpps)
  Slowest: IPv6 outer + GRE + IPv4 (55 ns, 18.18 Mpps)
  Best IPC: GRE IPv4 whitelisted (0.91)
```

**Columns explained:**
- `ns/pkt`: from `opts.duration` (kernel-measured average)
- `Mpps`: `1000.0 / ns_per_pkt` (millions of packets per second)
- `insns/pkt`: hardware instructions retired per packet
- `cycles/pkt`: CPU cycles per packet
- `IPC`: instructions per cycle
- `L1-miss/pkt`: L1 data cache misses per packet
- `map-lookups`: statically known `bpf_map_lookup_elem` calls on this path
- `helpers`: total BPF helper calls (map lookups + `bpf_xdp_adjust_head`)

**Static operation counts per path** (from code analysis of `tun_decap.bpf.c`):

| Path | Config lookup | Stats lookup | Whitelist lookup | adjust_head | Total map | Total helpers |
|------|:---:|:---:|:---:|:---:|:---:|:---:|
| GRE whitelisted (decap) | 1 | 1 | 1 | 1 | 3 | 4 |
| GRE blocked (drop) | 1 | 1 | 1 | 0 | 3 | 3 |
| IPIP whitelisted (decap) | 1 | 1 | 1 | 1 | 3 | 4 |
| IPv6 outer GRE (decap) | 1 | 1 | 1 | 1 | 3 | 4 |
| Non-tunnel passthrough | 1 | 1 | 0 | 0 | 2 | 2 |
| Non-IP passthrough | 1 | 1 | 0 | 0 | 2 | 2 |

*(When stats disabled: subtract 1 from map lookups and helpers)*

#### CLI arguments

- `--repeat N` (default: 100000)
- `--warmup N` (default: 1000)
- `--no-hwcounters` — skip perf_event_open, only report ns/pkt (for environments without PMU access)

### Makefile additions

```makefile
BENCH_BIN := $(BUILD_DIR)/bench_decap

bench-build: $(BENCH_BIN)        # compile benchmark binary
bench: $(BENCH_BIN)              # run benchmarks with hardware counters (sudo)
bench-perf: $(BENCH_BIN)         # additionally wrap in `perf stat` for aggregate view
```

---

## Part B: Integration Test Profiling (`make profile`)

### New file: `scripts/profile.sh`

Shell script that orchestrates profiling during integration test traffic:

1. **Start Docker containers** (reuse existing `docker-compose.yml`)
2. **Load XDP program** and configure whitelist (same as `run-integration-tests.sh`)
3. **Enable BPF stats**: `sysctl -w kernel.bpf_stats_enabled=1`
4. **Enable BPF JIT symbols**: `sysctl -w net.core.bpf_jit_kallsyms=1`
5. **Run `bpftool prog profile`** in background during traffic (cycles, instructions, l1d_loads, llc_misses)
6. **Start `perf record`** in background: `perf record -F 9999 -a -g -o build/profile/perf.data`
7. **Generate high-volume traffic** via Docker (1000+ packets per type using `generate-packets.py --count 1000`)
8. **Stop perf and bpftool**
9. **Generate flame chart**: `perf script | stackcollapse-perf.pl | flamegraph.pl > flamegraph.svg`
10. **Collect BPF stats**: `bpftool prog show` (shows `run_time_ns`, `run_cnt`)
11. **Cleanup**: disable bpf_stats, tear down containers

Output artifacts in `build/profile/`:
- `flamegraph.svg` — interactive flame chart (open in browser)
- `bpf-stats.txt` — BPF program runtime and hardware counter stats
- `bpftool-profile.txt` — per-program cycles, instructions, cache metrics
- `perf.data` — raw perf data for deeper analysis

### FlameGraph tools: `tools/flamegraph/`

Vendor two Perl scripts from Brendan Gregg's FlameGraph repo (CDDL license, ~20KB total):
- `stackcollapse-perf.pl`
- `flamegraph.pl`

Stable utilities. Vendoring avoids network dependency.

### Makefile additions

```makefile
profile: all                     # full profiling (starts Docker, generates traffic, flame chart)
profile-quick:                   # profiling with containers already running
```

---

## Part C: Static Analysis Target (`make analyze`)

Add a Makefile target that dumps per-function BPF instruction counts from the compiled object:

```makefile
analyze: $(BPF_OBJ)
	@echo "=== Per-Function BPF Instruction Counts ==="
	@llvm-objdump -d $< | awk '/^[0-9a-f]+ <.*>:/{name=$$2; count=0; next} /^[[:space:]]+[0-9a-f]+:/{count++} /^$$/{if(name) printf "  %-40s %d instructions\n", name, count; name=""}'
	@echo ""
	@echo "=== Program Size ==="
	@llvm-objdump -h $< | grep -E "xdp|\.text"
```

This shows instruction counts for `xdp_tun_decap`, `handle_gre`, `handle_ipip`, `decapsulate`, etc. (though with `__always_inline` most will be inlined into the main function — the output will show the merged result).

---

## Files to Create

| File | Purpose |
|------|---------|
| `src/test/bench_decap.c` | Benchmark binary with `perf_event_open()` hardware counters |
| `scripts/profile.sh` | Integration profiling orchestration |
| `tools/flamegraph/stackcollapse-perf.pl` | Vendored FlameGraph tool |
| `tools/flamegraph/flamegraph.pl` | Vendored FlameGraph tool |

## Files to Modify

| File | Changes |
|------|---------|
| `Makefile` | Add `bench-build`, `bench`, `bench-perf`, `profile`, `profile-quick`, `analyze` targets; update `help` |

## Key Implementation Details

- **`perf_event_open()`**: Used directly in bench binary for per-packet-type hardware counters. No external tools needed. Falls back gracefully if PMU unavailable (`--no-hwcounters`).
- **`opts.duration`**: Kernel returns average ns per invocation when `repeat > 1`. Ground truth for latency.
- **Map/helper counts**: Statically known from code analysis, embedded in `bench_entry` table. Updated manually when code paths change.
- **`bpf_stats_enabled`**: Adds ~20ns overhead but gives `run_time_ns`/`run_cnt` via `bpftool prog show`.
- **`bpf_jit_kallsyms=1`**: Required for BPF function names in perf flame charts.
- **Perf runs on host**: BPF programs execute in kernel context regardless of Docker.
- **No changes to existing tests**: Profiling is entirely opt-in via new targets.

## Verification

1. `make bench-build` — compiles without errors
2. `sudo make bench` — produces table with ns/pkt, instructions/pkt, cycles/pkt, cache misses, IPC, operation counts
3. `sudo make bench-perf` — same + aggregate `perf stat` hardware counter summary
4. `make analyze` — shows per-function BPF instruction counts from static analysis
5. `sudo make profile` — starts Docker, generates traffic, produces `build/profile/flamegraph.svg`
6. Open `build/profile/flamegraph.svg` in browser — verify interactive flame chart shows BPF/XDP stacks
