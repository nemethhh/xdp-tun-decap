# Performance Improvement Plan for xdp-tun-decap

## Context

Benchmark results (stats=off, repeat=100K) reveal two major anomalies:
1. **Blocked (whitelist miss) paths are ~75% more expensive** than whitelisted paths (354 insns/183 cycles vs 203 insns/117 cycles) despite doing less work. The extra ~150 CPU instructions come from the kernel `htab_map_lookup_elem` helper taking longer on hash misses.
2. **Every packet pays a `bpf_map_lookup_elem` call for config** (~20-40 cycles) even though config rarely changes.

The optimizations below are ordered from most to least impactful. Each can be implemented and benchmarked independently.

---

## 1. Replace Config Map with BPF Global Variable (~20-40 cycles/pkt, ALL paths)

**Why:** `get_config()` calls `bpf_map_lookup_elem` on every packet (line 660). This is a kernel helper call with register save/restore, argument marshalling, and array bounds checking overhead. BPF global variables (kernel 5.2+, well within 5.17+ requirement) compile to direct memory loads -- no helper call.

**Changes:**

`src/bpf/tun_decap.bpf.c`:
- Remove the `tun_decap_config` map definition (lines 135-141)
- Remove `get_config()` function (lines 148-152)
- Add volatile global: `volatile struct tun_decap_config cfg_global = {};`
- Replace `cfg = get_config()` + `cfg && cfg->field` checks with direct `cfg_global.field` reads
- Remove `struct tun_decap_config *cfg` local variable

`src/test/bench_decap.c` (line 590-601):
- Replace `bpf_map__fd(skel->maps.tun_decap_config)` + `bpf_map_update_elem()` with direct `skel->bss->cfg_global` access

`src/test/test_decap.c` (lines 1147-1160):
- Same skeleton `.bss` access pattern

`src/include/tun_decap.h`:
- Remove `CONFIG_MAX_ENTRIES` (line 99) and `MAP_PIN_PATH_CONFIG` (line 74)

`map_manager/xdp_tun_decap_manager.py`:
- Config commands need migration to read/write the `.bss` map (pinned as `tun_decap_b.bss` or similar). This is a larger change -- can be done separately or the config map can be kept as a **secondary** interface that syncs to the global on load.

`Makefile`: Update `compute_ops()` -- config lookup count drops from 1 to 0.

**Risk:** Low. Global variables are well-supported in BPF. The map_manager migration is the main complexity.

---

## 2. Hoist Whitelist + Deduplicate Fragmentation Check (~10-20 insns saved, smaller program)

**Why:** The whitelist check is duplicated in 5 inline handler functions (lines 300, 386, 436, 490, 570). The fragmentation check is duplicated 3x in the IPv4 protocol switch (lines 718, 732, 747). Since all handlers are `__always_inline`, the compiler emits multiple copies. Hoisting to the main function before dispatching to handlers:
- Reduces total BPF program size (better I-cache in production)
- Makes the drop path shorter -- no handler preamble code for blocked traffic
- Deduplicates frag check from 3 copies to 1

**Changes:**

`src/bpf/tun_decap.bpf.c` -- restructure IPv4 tunnel handling (lines 706-759):
```c
case IPPROTO_GRE:
case IPPROTO_IPIP:
case IPPROTO_IPV6: {
    /* Common: frag check (once, not 3x) */
    if (iph->frag_off & bpf_htons(0x3FFF)) {
        if (stats) stats->drop_fragmented++;
        return XDP_DROP;
    }
    /* Common: whitelist check (once, not 3x) */
    if (!is_whitelisted(iph->saddr)) {
        if (stats) stats->drop_not_whitelisted++;
        return XDP_DROP;
    }
    /* Dispatch to protocol handler (whitelist already verified) */
    if (iph->protocol == IPPROTO_GRE) {
        if (cfg_global.disable_gre) { ... }
        return handle_gre(ctx, iph, ip_hdr_len, data_end, stats);
    } else if (iph->protocol == IPPROTO_IPIP) { ... }
    else { /* IPPROTO_IPV6 */ ... }
}
```

Same pattern for IPv6 paths: hoist `is_whitelisted_v6()` before dispatching to `handle_gre_ipv6` / `handle_ipip_ipv6`.

Remove whitelist checks from each handler function. Remove frag checks from each case.

**Stats semantics note:** Protocol counters (`rx_gre`, `rx_ipip`, etc.) will only increment for whitelisted packets. This is arguably better (you care about processed packets, not blocked ones). Document in commit.

**Risk:** Low. Simpler control flow helps the verifier.

---

## 3. Switch Whitelist from PERCPU_HASH to HASH (~0-5 cycles/pkt, simpler userspace)

**Why:** The whitelist is read-only from BPF side (existence check). `BPF_MAP_TYPE_HASH` reads are already RCU-protected (lock-free). PERCPU_HASH wastes `(num_cpus - 1) * value_size` per entry and forces userspace to manage per-CPU value arrays.

**Changes:**

`src/bpf/tun_decap.bpf.c` (lines 86, 105): Change `BPF_MAP_TYPE_PERCPU_HASH` to `BPF_MAP_TYPE_HASH`

`src/test/test_decap.c` (lines 93-103, 114-129): Simplify `whitelist_add()` -- single value instead of `ncpus` array
```c
static int whitelist_add(int map_fd, __u32 ip_be) {
    struct whitelist_value val = { .allowed = 1 };
    return bpf_map_update_elem(map_fd, &ip_be, &val, BPF_ANY);
}
```

`src/test/bench_decap.c` (lines 172-195): Same simplification

`tests/run-integration-tests.sh` (lines 252-261): The `bpftool map update` commands stay the same (bpftool auto-handles map type)

`map_manager/xdp_tun_decap_manager.py`: Simplify value handling (no per-CPU arrays)

**Risk:** Low. The only concern is if a hot update path needs per-CPU values (it doesn't -- whitelist is read-only from BPF).

---

## 4. Add likely/unlikely Branch Hints (~0-5 cycles/pkt in production)

**Why:** Helps the compiler arrange code so common paths are fall-through (no branch taken). The benchmark repeats the same packet 100K times so the CPU branch predictor learns the pattern, but production workloads with mixed traffic benefit more.

**Changes:**

`src/bpf/tun_decap.bpf.c`: Add macros and annotate key branches:
```c
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
```

Key annotations:
- `unlikely(cfg_global.disabled)` -- rarely disabled
- `unlikely((void *)(eth + 1) > data_end)` -- truncated packets are rare
- `unlikely(!is_whitelisted(...))` -- most tunnel traffic is whitelisted
- `unlikely(frag_off & 0x3FFF)` -- fragments are rare
- `unlikely(ret < 0)` in decapsulate -- adjust_head rarely fails

**Risk:** None. Pure optimization hints.

---

## 5. Use __builtin_memcpy for IPv6 Key (~2-4 insns on IPv6 paths)

**Why:** The word-by-word IPv6 address copy (lines 199-202) generates 4x load + 4x store. `__builtin_memcpy` with `-mcpu=v3` can use 2x 64-bit load + 2x 64-bit store.

**Change** in `is_whitelisted_v6()`:
```c
__builtin_memcpy(&key, ip6_addr, sizeof(key));
```

**Risk:** None. `__builtin_memcpy` is standard BPF practice (already used in `decapsulate()` at lines 252-254).

---

## 6. (Optional, Advanced) Inline Whitelist for Small Deployments

**Why:** For typical deployments with 1-16 tunnel peers, a linear scan over a BPF global array eliminates the hash lookup helper call entirely. A miss with 8 entries costs ~40 instructions vs ~200 for a hash miss. This is a compile-time option.

**Complexity:** Medium. Requires bounded loops that pass the verifier, userspace sync between inline array and hash map, and a new `INLINE_WL=1` build flag. Recommend deferring this until optimizations 1-5 are measured.

---

## Implementation Order

1. **Opt 1** (global config) -- standalone, biggest impact
2. **Opt 4 + 5** (branch hints + memcpy) -- trivial, can batch together
3. **Opt 2** (hoist whitelist/frag) -- structural change, benefits from Opt 1 being done first
4. **Opt 3** (PERCPU_HASH to HASH) -- userspace-impacting, do after structural changes settle
5. **Opt 6** (inline whitelist) -- optional, measure first

## Verification

After each optimization:
```bash
make clean && make all           # Rebuild BPF program
make analyze                     # Check instruction count change
sudo make test                   # Run unit tests
sudo make bench                  # Run benchmarks, compare ns/pkt, insns, cycles
cd tests && ./run-tests.sh       # Integration tests (especially for Opt 3)
```

Key metrics to track:
- `insns` and `cycles` columns (more reliable than ns/pkt for BPF program performance)
- `make analyze` output (total BPF instruction count)
- All 18 benchmark entries should match expected verdicts
