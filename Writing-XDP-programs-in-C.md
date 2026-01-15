# Writing XDP programs in C for Linux kernel 5.10+

XDP (eXpress Data Path) enables packet processing at **14+ million packets per second per CPU core** by hooking into the network driver before socket buffer allocation. This guide covers the complete XDP development stack for modern Linux kernels, from architecture fundamentals through high-performance optimization techniques.

## XDP processes packets at the earliest possible kernel hook point

XDP programs execute in the NIC driver's receive path immediately after DMA completion, bypassing the entire traditional networking stack. When a packet arrives, the driver runs your BPF program before allocating an sk_buff, eliminating memory allocation overhead and enabling line-rate packet processing on commodity hardware.

The **xdp_md** context structure provides packet access:

```c
struct xdp_md {
    __u32 data;             // Packet start pointer
    __u32 data_end;         // Packet end pointer  
    __u32 data_meta;        // Metadata area (before data)
    __u32 ingress_ifindex;  // Incoming interface index
    __u32 rx_queue_index;   // Receive queue index
    __u32 egress_ifindex;   // Redirect target (post-redirect)
};
```

Every XDP program returns one of five action codes that determine the packet's fate:

| Action | Effect | Use Case |
|--------|--------|----------|
| **XDP_PASS** | Forward to normal network stack | Default processing, L4+ handling |
| **XDP_DROP** | Silently discard packet | DDoS mitigation, firewall rules |
| **XDP_TX** | Transmit back out same interface | Load balancing, NAT, reflection |
| **XDP_REDIRECT** | Send to another NIC/CPU/socket | Multi-NIC forwarding, AF_XDP |
| **XDP_ABORTED** | Drop with exception trace | Error handling, debugging |

### Three XDP modes offer different performance tradeoffs

**Native XDP** runs directly in the network driver, providing maximum performance but requiring driver support. Intel (i40e, ice, ixgbe), Mellanox (mlx4, mlx5), Broadcom (bnxt), virtio_net, and most modern drivers support native mode.

**Generic XDP** operates after sk_buff allocation, working with any device but sacrificing the performance benefits. Use this for development and testing, or consider tc/BPF as an alternative with similar performance.

**Offloaded XDP** executes entirely on SmartNIC hardware (currently only Netronome NFP), achieving wire-speed processing with zero CPU consumption but limited BPF feature support.

```bash
# Load in native mode (driver required)
ip link set dev eth0 xdpdrv obj prog.o sec xdp

# Load in generic mode (universal compatibility)
ip link set dev eth0 xdpgeneric obj prog.o sec xdp
```

### Kernel 5.10 unlocks multi-program attachment

Kernel 5.10 introduced full **incremental multi-program attachment** via BPF trampolines, enabling libxdp's dispatcher mechanism. Earlier kernels (5.6-5.9) support multiple programs only when attached simultaneously. Post-5.10 kernels added multi-buffer support for jumbo frames, XDP metadata kfuncs for RX timestamps and RSS hashes, and cross-fragment packet access helpers.

## libxdp simplifies XDP program management and enables program chaining

libxdp builds on libbpf to provide multi-program dispatch, AF_XDP socket helpers (moved from libbpf 1.0+), and automatic program ordering. Install via package manager or build from source:

```bash
# Fedora/RHEL
sudo dnf install libxdp libxdp-devel xdp-tools

# Debian/Ubuntu  
sudo apt install libxdp1 libxdp-dev xdp-tools

# Build from source
git clone --recurse-submodules https://github.com/xdp-project/xdp-tools.git
cd xdp-tools && ./configure && make && sudo make install
```

The libxdp API centers on `struct xdp_program` for individual programs and `struct xdp_multiprog` for managing the dispatcher:

```c
#include <xdp/libxdp.h>
#include <net/if.h>

int main(void) {
    struct xdp_program *prog;
    int ifindex = if_nametoindex("eth0");
    
    // Load and attach XDP program
    prog = xdp_program__open_file("xdp_filter.o", "xdp", NULL);
    if (libxdp_get_error(prog))
        return 1;
        
    if (xdp_program__attach(prog, ifindex, XDP_MODE_SKB, 0))
        return 1;
    
    // Access underlying libbpf object for maps
    struct bpf_object *obj = xdp_program__bpf_obj(prog);
    int map_fd = bpf_object__find_map_fd_by_name(obj, "stats_map");
    
    // Cleanup
    xdp_program__detach(prog, ifindex, XDP_MODE_SKB, 0);
    xdp_program__close(prog);
    return 0;
}
```

Compile userspace with: `gcc -o loader loader.c -lbpf -lxdp`

### When to choose libxdp over raw libbpf

Use **libxdp** when loading multiple XDP programs on one interface, using AF_XDP sockets (mandatory for libbpf ≥1.0), or needing automatic program ordering. Use **raw libbpf** for single-program deployments, non-XDP BPF program types, or when minimizing dependencies.

## The xdp_dispatcher enables up to 10 chained programs per interface

libxdp's multi-program support uses BPF **freplace** (function replacement) to chain programs through a dispatcher. The dispatcher contains 10 stub functions that get dynamically replaced with your actual XDP programs via `BPF_PROG_TYPE_EXT`.

Programs execute in **priority order** (lower values first, default: 50) and chain to subsequent programs based on **chain call actions**—a bitmask specifying which return codes continue execution versus immediately returning.

Define program metadata in your BPF code:

```c
#include <bpf/bpf_helpers.h>
#include <xdp/xdp_helpers.h>

struct {
    __uint(priority, 10);      // Run early (lower = earlier)
    __uint(XDP_PASS, 1);       // Chain on XDP_PASS
    __uint(XDP_DROP, 1);       // Also chain on XDP_DROP
} XDP_RUN_CONFIG(xdp_filter_func);

SEC("xdp")
int xdp_filter_func(struct xdp_md *ctx) {
    // Filter logic - returning XDP_PASS chains to next program
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
```

The **xdp-loader** utility provides command-line program management:

```bash
# Load programs (automatically creates dispatcher)
xdp-loader load -m native eth0 prog1.o prog2.o

# Check status - shows dispatcher and all chained programs  
xdp-loader status eth0
# Output:
# eth0    xdp_dispatcher   native  50   d51e469e988d81da
#    =>   10   xdp_filter       55   57cd311f2e27366b  XDP_PASS XDP_DROP
#    =>   50   xdp_stats        60   abc123def456789   XDP_PASS

# Unload specific program or all
xdp-loader unload eth0 --id 55
xdp-loader unload eth0 --all
```

**Architecture constraint**: Full incremental attach requires **x86_64** with kernel 5.10+. On other architectures or older kernels, use `xdp_program__attach_multi()` to attach all programs simultaneously.

## BPF maps provide persistent state and inter-program communication

XDP programs use BPF maps for statistics, configuration, packet steering, and sharing data with userspace. Modern programs use **BTF-style definitions** in the `.maps` section:

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} flow_table SEC(".maps");
```

### Map types optimized for XDP workloads

**General-purpose maps**: `BPF_MAP_TYPE_HASH` for arbitrary key-value lookup, `BPF_MAP_TYPE_ARRAY` for indexed access with zero-initialization, `BPF_MAP_TYPE_LRU_HASH` for caches with automatic eviction.

**Per-CPU variants** (`BPF_MAP_TYPE_PERCPU_HASH`, `BPF_MAP_TYPE_PERCPU_ARRAY`) eliminate lock contention by providing separate storage per CPU—essential for counters and statistics:

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 5);
} stats SEC(".maps");

SEC("xdp")
int counter(struct xdp_md *ctx) {
    __u32 key = XDP_PASS;
    __u64 *count = bpf_map_lookup_elem(&stats, &key);
    if (count)
        *count += 1;  // No atomics needed - per-CPU isolation
    return XDP_PASS;
}
```

**XDP redirect maps**: `BPF_MAP_TYPE_DEVMAP` routes packets to other interfaces, `BPF_MAP_TYPE_CPUMAP` steers packets to different CPUs for software RSS, and `BPF_MAP_TYPE_XSKMAP` delivers frames to AF_XDP sockets for userspace processing.

### Pin maps for persistence and sharing

Pinning maps to the BPF filesystem (`/sys/fs/bpf/`) enables sharing between programs and persistence across reloads:

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);  // Auto-pin using map name
} shared_config SEC(".maps");
```

When a map with `LIBBPF_PIN_BY_NAME` is loaded and a pin already exists at the configured path, the loader reuses the existing map rather than creating a new one—enabling atomic program replacement while preserving state.

**Map-in-map** (`BPF_MAP_TYPE_ARRAY_OF_MAPS`, `BPF_MAP_TYPE_HASH_OF_MAPS`) supports dynamic configuration by storing map references inside an outer map. BPF programs can lookup the outer map to get inner map pointers, while userspace can swap inner maps at runtime for A/B testing or per-tenant configuration.

## The BPF verifier enforces safety through static analysis

The verifier performs two passes: first validating the control flow graph (DAG check, reachability, bounds), then simulating every instruction across all possible execution paths. It tracks register types (`PTR_TO_CTX`, `PTR_TO_PACKET`, `PTR_TO_MAP_VALUE`, `SCALAR_VALUE`) and validates memory accesses against tracked bounds.

### Key limits for XDP programs

| Constraint | Value | Notes |
|------------|-------|-------|
| Instructions (privileged) | **1,000,000** | Kernel 5.2+ with CAP_BPF |
| Instructions (unprivileged) | **4,096** | All kernels |
| Stack size | **512 bytes** | Per function frame |
| Tail call depth | **33** | MAX_TAIL_CALL_CNT |
| BPF-to-BPF call depth | **8** | Nested function calls |

### Bounded loops work since kernel 5.3

The verifier simulates all loop iterations, so each iteration counts toward the complexity limit. A 100-iteration loop with 20 instructions contributes ~2000 toward the limit. For complex loops, use the `bpf_loop()` helper (kernel 5.17+) or open-coded iterators (kernel 6.4+):

```c
// Bounded loop - verifier simulates all iterations
for (int i = 0; i < 10 && i < max; i++) {
    // Processing - must have provable termination
}

// bpf_loop helper - more verifier-friendly for larger counts
long bpf_loop(__u32 nr_loops, void *callback_fn, void *ctx, __u64 flags);
```

### Common verifier errors and solutions

**"invalid access to packet"**: Add bounds check before access—`if (data + sizeof(struct ethhdr) > data_end) return XDP_PASS;`

**"BPF stack limit exceeded"**: Use per-CPU maps instead of large stack allocations.

**"math between pkt pointer and unbounded register"**: Mask variable offsets—`offset &= 0xFFF;`

**"R0 not initialized"**: Ensure all code paths set a return value.

### Helper functions available to XDP programs

Core XDP helpers include `bpf_xdp_adjust_head()` and `bpf_xdp_adjust_tail()` for packet resizing, `bpf_redirect()` and `bpf_redirect_map()` for steering, and `bpf_fib_lookup()` for routing table queries. Map helpers (`bpf_map_lookup_elem`, `bpf_map_update_elem`, `bpf_map_delete_elem`) work universally. Utility helpers provide timing (`bpf_ktime_get_ns`), randomness (`bpf_get_prandom_u32`), CPU identification (`bpf_get_smp_processor_id`), and tail calls (`bpf_tail_call`).

XDP programs **cannot** use sk_buff helpers, floating-point operations, unbounded loops (pre-5.3), standard library functions, or arbitrary kernel memory access.

## BPF Type Format (BTF) enables debugging and CO-RE

BTF is a compact metadata format encoding type information for BPF programs, maps, and the kernel itself. It enables map pretty-printing, better verifier error messages, source-annotated JIT dumps, and most critically—Compile Once, Run Everywhere (CO-RE) portability.

### Generating BTF for XDP programs

LLVM generates `.BTF` and `.BTF.ext` sections automatically when compiling with `-g` for the BPF target:

```bash
# Clang generates BTF directly for BPF target
clang -O2 -g -target bpf -c xdp_prog.c -o xdp_prog.o

# Verify BTF sections exist
readelf -S xdp_prog.o | grep BTF
# Output:
# [ 8] .BTF              PROGBITS  ...
# [ 9] .BTF.ext          PROGBITS  ...
```

The **`-g` flag is mandatory** for BTF generation. Without it, CO-RE relocations won't work and debugging capabilities are severely limited.

### Kernel BTF requirements

For XDP programs to leverage BTF fully, the kernel must be built with:

```
CONFIG_DEBUG_INFO_BTF=y
CONFIG_DEBUG_INFO_BTF_MODULES=y  # For module BTF
```

Kernel BTF generation requires **pahole ≥ 1.16** from the dwarves package. Pahole converts DWARF debug information to BTF format during kernel compilation.

```bash
# Check if kernel has BTF
ls -la /sys/kernel/btf/vmlinux

# Generate vmlinux.h header containing all kernel types
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

### Using vmlinux.h for CO-RE programs

The `vmlinux.h` header provides all kernel type definitions needed for CO-RE XDP programs:

```c
#include "vmlinux.h"           // All kernel types
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h> // CO-RE helpers

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    // CO-RE-safe access to kernel structures
    struct task_struct *task = (void *)bpf_get_current_task();
    pid_t pid = BPF_CORE_READ(task, pid);
    return XDP_PASS;
}
```

The `__attribute__((preserve_access_index))` in vmlinux.h triggers CO-RE relocation recording. When the program loads on a different kernel version, libbpf adjusts struct offsets automatically using both BTFs.

### BTF development workflow

1. **Generate vmlinux.h** from target kernel's BTF:
   ```bash
   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
   ```

2. **Compile BPF program** with BTF generation:
   ```bash
   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c prog.bpf.c -o prog.bpf.o
   ```

3. **Generate skeleton** for easy loading:
   ```bash
   bpftool gen skeleton prog.bpf.o > prog.skel.h
   ```

4. **Compile userspace loader** linking against libbpf:
   ```bash
   gcc -O2 -g prog.c -lbpf -lelf -lz -o prog
   ```

### BTF for maps enables pretty-printing

When maps include BTF type information, bpftool displays values with field names:

```c
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);   // BTF-aware key type
    __type(value, __u64);
    __uint(max_entries, 1024);
} flow_stats SEC(".maps");
```

```bash
# With BTF, bpftool shows structured output
bpftool map dump name flow_stats
# Output:
# key: struct flow_key {
#     src_ip: 167772161,
#     dst_ip: 167772162,
#     src_port: 443,
#     dst_port: 54321
# }  value: 1542
```

### Handling kernels without BTF

For older kernels lacking embedded BTF, use external BTF files from the BTFHub project:

```c
struct bpf_object_open_opts opts = {
    .sz = sizeof(opts),
    .btf_custom_path = "/path/to/external.btf",
};
struct bpf_object *obj = bpf_object__open_file("prog.o", &opts);
```

BTFHub provides pre-generated BTF files for most distribution kernels, enabling CO-RE programs to run on kernels that weren't compiled with `CONFIG_DEBUG_INFO_BTF=y`.

## LLVM builtins accelerate XDP packet processing

Clang provides compiler builtins that generate optimized BPF instructions for common operations. Using these builtins correctly is essential for high-performance XDP programs.

### Memory operations with __builtin_memcpy and __builtin_memset

The BPF target handles memory operations specially. `__builtin_memcpy` works only when the size is a **compile-time constant**; variable-length copies require `bpf_probe_read_kernel()` or manual loops. For XDP packet manipulation, use inline memcpy with known sizes:

```c
// CORRECT - compile-time constant size
__builtin_memcpy(&new_eth, eth, sizeof(struct ethhdr));

// INCORRECT - will fail if size is runtime variable
__builtin_memcpy(dst, src, runtime_size);  // Error: unsupported
```

Cilium's approach explicitly avoids `__builtin_memcpy` for performance-critical paths, implementing custom memory operations that guarantee aligned access:

```c
// High-performance aligned memcpy pattern
static __always_inline void __bpf_memcpy(void *d, const void *s, __u64 len) {
    switch (len) {
    case 8:  *(__u64 *)d = *(__u64 *)s; break;
    case 4:  *(__u32 *)d = *(__u32 *)s; break;
    case 2:  *(__u16 *)d = *(__u16 *)s; break;
    case 1:  *(__u8 *)d = *(__u8 *)s; break;
    default:
        // Handle larger sizes with 8-byte strides
        for (__u64 i = 0; i < len; i += 8)
            *((__u64 *)d + i/8) = *((__u64 *)s + i/8);
    }
}
```

### Byte swapping with __builtin_bswap

Network byte order conversions use architecture-optimized swap instructions:

```c
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#define bpf_ntohll(x) __builtin_bswap64(x)

// Usage in packet parsing
if (eth->h_proto == bpf_htons(ETH_P_IP)) {
    // Process IPv4
}
```

These compile to single BPF byte swap instructions (`BPF_END | BPF_TO_BE` or `BPF_END | BPF_TO_LE`).

### Branch prediction with __builtin_expect

Guide the compiler's code layout for better instruction cache utilization:

```c
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data;
    // Bounds check failure is unlikely in normal traffic
    if (unlikely((void *)(eth + 1) > data_end))
        return XDP_PASS;
    
    // Most packets are IPv4 - optimize for common case
    if (likely(eth->h_proto == bpf_htons(ETH_P_IP))) {
        // Fast path - IPv4 processing
    }
    return XDP_PASS;
}
```

The compiler places the likely branch inline and jumps to unlikely paths, improving instruction prefetch efficiency.

### Atomic operations with __sync builtins

BPF supports atomic instructions through GCC-compatible sync builtins. **Full atomic support requires `-mcpu=v3`** (or LLVM 20+ where v3 is default):

```c
// Atomic counter increment (lock-free)
__sync_fetch_and_add(&counter, 1);

// Available atomics (kernel 5.12+ with -mcpu=v3):
__sync_fetch_and_add(ptr, val)   // Add and return old value
__sync_fetch_and_sub(ptr, val)   // Subtract (implemented as add with negation)
__sync_fetch_and_or(ptr, val)    // Bitwise OR
__sync_fetch_and_and(ptr, val)   // Bitwise AND  
__sync_fetch_and_xor(ptr, val)   // Bitwise XOR
__sync_lock_test_and_set(ptr, val)  // Atomic exchange
__sync_val_compare_and_swap(ptr, old, new)  // Compare-and-swap
```

**Critical compiler flag**: Without `-mcpu=v3`, only `__sync_fetch_and_add` without fetch semantics works. Attempting other atomics on v1/v2 causes compilation failures:

```bash
# Enable full atomic support
clang -O2 -g -target bpf -mcpu=v3 -c prog.c -o prog.o

# Alternative: enable atomics on older CPU version
clang -O2 -g -target bpf -mcpu=v2 -Xclang -target-feature -Xclang +alu32 -c prog.c -o prog.o
```

### Recommended compilation flags for XDP

```bash
clang \
    -O2 \                          # Required optimization level
    -g \                           # Generate BTF debug info
    -Wall -Wextra \                # Enable warnings
    -target bpf \                  # BPF target (guarantees 64-bit pointers)
    -mcpu=v3 \                     # Enable atomics and ALU32
    -D__TARGET_ARCH_x86 \          # Architecture define for vmlinux.h
    -c prog.c -o prog.o
```

## High-performance XDP requires careful optimization

### Per-CPU maps eliminate contention

Per-CPU variants provide separate storage per CPU, eliminating cache-line bouncing and synchronization overhead. Each CPU's value is accessed automatically by `bpf_map_lookup_elem()`; userspace aggregates all CPUs' values:

```c
int ncpus = libbpf_num_possible_cpus();
__u64 values[ncpus];
bpf_map_lookup_elem(fd, &key, values);
__u64 total = 0;
for (int i = 0; i < ncpus; i++)
    total += values[i];
```

When per-CPU maps aren't suitable, use atomic operations via `__sync_fetch_and_add()` (requires `-mcpu=v3` for full atomic support).

### CPUMAP enables software RSS

`BPF_MAP_TYPE_CPUMAP` redirects packets to specified CPUs, spawning dedicated kernel threads that perform sk_buff allocation on the target CPU. This offloads allocation overhead and enables custom load-balancing:

```c
struct {
    __uint(type, BPF_MAP_TYPE_CPUMAP);
    __type(key, __u32);
    __type(value, struct bpf_cpumap_val);
    __uint(max_entries, 64);
} cpu_map SEC(".maps");

SEC("xdp")
int xdp_redirect_cpu(struct xdp_md *ctx) {
    __u32 cpu = hash_packet(ctx) % num_cpus;
    return bpf_redirect_map(&cpu_map, cpu, 0);
}
```

### AF_XDP achieves near-DPDK performance

AF_XDP provides kernel bypass for userspace packet processing through shared UMEM memory and four ring buffers (FILL, RX, TX, COMPLETION). With zero-copy mode and proper tuning, AF_XDP achieves **39 Mpps receive, 68 Mpps transmit**:

```c
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 64);
} xsks_map SEC(".maps");

SEC("xdp")
int xsk_redirect(struct xdp_md *ctx) {
    __u32 index = ctx->rx_queue_index;
    if (bpf_map_lookup_elem(&xsks_map, &index))
        return bpf_redirect_map(&xsks_map, index, 0);
    return XDP_PASS;
}
```

Enable busy polling for optimal latency:
```bash
echo 2 > /sys/class/net/eth0/napi_defer_hard_irqs
echo 200000 > /sys/class/net/eth0/gro_flush_timeout
```

### Compiler flags and inlining

Always use `__always_inline` for helper functions—BPF-to-BPF calls have overhead and older kernels don't support them:

```c
static __always_inline int parse_eth(void *data, void *data_end, 
                                     struct ethhdr **eth) {
    *eth = data;
    if ((void *)(*eth + 1) > data_end)
        return -1;
    return 0;
}
```

Compile with: `clang -O2 -g -Wall -target bpf -mcpu=v3 -c prog.c -o prog.o`

### BPF CPU versions and feature availability

The `-mcpu` flag controls which BPF instruction set features are available:

| CPU Version | Features | Kernel Requirement |
|-------------|----------|-------------------|
| **v1** | Basic BPF, no ALU32 | 3.18+ |
| **v2** | ALU32 (32-bit subregisters) | 4.14+ |
| **v3** | v2 + atomics, jump32 | 5.1+ (atomics: 5.12+) |
| **v4** | v3 + signed division, `bpf_addr_space_cast` | 6.6+ |
| **probe** | Auto-detect from running kernel | — |

LLVM 20+ defaults to `-mcpu=v3`. For older LLVM versions, explicitly specify `-mcpu=v3` for atomic operations support.

## Safe packet parsing requires explicit bounds checking

The verifier tracks all packet accesses against `data_end`. Every dereference must be preceded by a bounds check:

```c
SEC("xdp")
int xdp_parser(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
        
    // IPv4 header (variable length via IHL field)
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(*ip))
        return XDP_PASS;
    if ((void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;
        
    // TCP header (variable length via doff field)
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;
        
    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;
        
    int tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < sizeof(*tcp))
        return XDP_PASS;
    if ((void *)tcp + tcp_hdr_len > data_end)
        return XDP_PASS;
    
    // Safe to access all headers
    __u16 dst_port = bpf_ntohs(tcp->dest);
    return (dst_port == 80) ? XDP_DROP : XDP_PASS;
}
```

### Header cursor pattern improves readability

Track parsing position through a cursor structure updated by each parsing function:

```c
struct hdr_cursor {
    void *pos;
};

static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct ethhdr **ethhdr) {
    struct ethhdr *eth = nh->pos;
    if ((void *)(eth + 1) > data_end)
        return -1;
    nh->pos = eth + 1;
    *ethhdr = eth;
    return eth->h_proto;
}
```

### Tail calls versus BPF-to-BPF functions

Use **BPF-to-BPF function calls** for code reuse within a single program when you need return values. Maximum depth is 8 calls with 512 bytes stack per function.

Use **tail calls** to chain separate programs, bypass instruction limits, or build modular pipelines. Maximum 33 tail calls; no return to caller; stack is reused. Tail calls enable runtime program selection via `BPF_MAP_TYPE_PROG_ARRAY`.

## Testing and debugging with bpftool and xdp-tools

**bpftool** provides comprehensive BPF inspection:

```bash
# List programs and show XDP attachment
bpftool prog list
bpftool net list

# Dump bytecode and JIT
bpftool prog dump xlated id 42
bpftool prog dump jited id 42

# Map operations
bpftool map dump id 5
bpftool map update id 5 key 1 0 0 0 value 100 0 0 0

# Trace bpf_trace_printk output
bpftool prog tracelog

# Test with synthetic packet
bpftool prog run id 42 data_in packet.bin repeat 1000
```

**xdp-tools** utilities simplify XDP workflows:

```bash
# Capture packets at XDP layer (tcpdump-like)
xdp-dump -i eth0 --rx-capture entry,exit -w capture.pcap

# Monitor XDP exceptions and redirects
xdp-monitor --iface eth0

# Quick packet filtering
xdp-filter load eth0
xdp-filter ip block 192.168.1.100
```

### Development workflow

1. Compile: `clang -O2 -g -Wall -target bpf -c prog.c -o prog.o`
2. Verify: `bpftool prog load prog.o /sys/fs/bpf/prog -d`
3. Test: `bpftool prog run pinned /sys/fs/bpf/prog data_in test.bin`
4. Deploy: `xdp-loader load -m skb veth1 prog.o`
5. Monitor: `xdp-dump -i veth1 & bpftool prog tracelog`
6. Inspect: `bpftool map dump name stats_map`

## Complete XDP program skeleton with libxdp

```c
// xdp_example.c - Complete XDP program with statistics
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <xdp/xdp_helpers.h>

// Program metadata for libxdp dispatcher
struct {
    __uint(priority, 20);
    __uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(xdp_filter);

// Per-CPU statistics map
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 5);
} stats_map SEC(".maps");

// Configuration map (pinned for sharing)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u16);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocked_ports SEC(".maps");

static __always_inline void update_stats(__u32 action) {
    __u64 *count = bpf_map_lookup_elem(&stats_map, &action);
    if (count)
        (*count)++;
}

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 action = XDP_PASS;
    
    // Parse Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        goto out;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        goto out;
    
    // Parse IPv4
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        goto out;
    
    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(*ip) || (void *)ip + ip_hdr_len > data_end)
        goto out;
    
    if (ip->protocol != IPPROTO_TCP)
        goto out;
    
    // Parse TCP
    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        goto out;
    
    // Check if destination port is blocked
    __u32 port_key = bpf_ntohs(tcp->dest);
    if (bpf_map_lookup_elem(&blocked_ports, &port_key)) {
        action = XDP_DROP;
    }

out:
    update_stats(action);
    return action;
}

char LICENSE[] SEC("license") = "GPL";
```

Compile and load:
```bash
clang -O2 -g -Wall -target bpf -I/usr/include -c xdp_example.c -o xdp_example.o
xdp-loader load -m native eth0 xdp_example.o
```

## XDP multi-buffer enables jumbo frame processing

Traditional XDP requires packets fit in a single contiguous memory page, limiting MTU to approximately 3500 bytes. Multi-buffer XDP (kernel 5.18+) lifts this restriction by allowing packets to span multiple memory fragments.

### Enabling multi-buffer support

Programs must explicitly declare multi-buffer support via the `xdp.frags` section name:

```c
SEC("xdp.frags")
int xdp_multibuf_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // data/data_end only cover the FIRST fragment
    // Use helpers to access additional fragments
    
    // Get total packet length across all fragments
    __u32 total_len = bpf_xdp_get_buff_len(ctx);
    
    // Check if packet spans multiple buffers
    if (total_len > (data_end - data)) {
        // Multi-buffer packet - need helpers for full access
    }
    
    return XDP_PASS;
}
```

### Multi-buffer helpers

```c
// Get total length including all fragments
int bpf_xdp_get_buff_len(struct xdp_md *ctx);

// Load data from arbitrary offset (handles fragment boundaries)
int bpf_xdp_load_bytes(struct xdp_md *ctx, __u32 offset, 
                       void *buf, __u32 len);

// Store data at arbitrary offset
int bpf_xdp_store_bytes(struct xdp_md *ctx, __u32 offset,
                        void *buf, __u32 len);
```

### AF_XDP multi-buffer for jumbo frames

For AF_XDP sockets, enable multi-buffer with `XDP_USE_SG` during bind:

```c
struct sockaddr_xdp sxdp = {
    .sxdp_family = AF_XDP,
    .sxdp_ifindex = ifindex,
    .sxdp_queue_id = queue_id,
    .sxdp_flags = XDP_USE_SG,  // Enable scatter-gather
};
bind(xsk_fd, (struct sockaddr *)&sxdp, sizeof(sxdp));
```

Multi-buffer packets use the `XDP_PKT_CONTD` flag in descriptors to chain fragments. When set, the next descriptor continues the same packet.

## XDP metadata kfuncs expose hardware offload data

Kernel 6.3+ provides kfuncs for accessing NIC-provided metadata like RX timestamps and RSS hashes. This enables precise packet timing for PTP applications and hardware-accelerated flow distribution.

### Available metadata kfuncs

```c
// Get hardware RX timestamp (nanoseconds)
int bpf_xdp_metadata_rx_timestamp(const struct xdp_md *ctx, u64 *timestamp);

// Get hardware RSS hash
int bpf_xdp_metadata_rx_hash(const struct xdp_md *ctx, u32 *hash,
                             enum xdp_rss_hash_type *rss_type);

// Get VLAN tag (if hardware stripped)
int bpf_xdp_metadata_rx_vlan_tag(const struct xdp_md *ctx,
                                 __be16 *vlan_proto, u16 *vlan_tci);
```

### Using metadata for AF_XDP

Store metadata in the `data_meta` area for userspace consumption:

```c
struct xdp_hints_rx {
    __u64 timestamp;
    __u32 hash;
};

SEC("xdp")
int xdp_metadata_prog(struct xdp_md *ctx) {
    struct xdp_hints_rx *meta;
    int ret;
    
    // Allocate metadata space
    ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
    if (ret < 0)
        return XDP_PASS;
    
    meta = (void *)(long)ctx->data_meta;
    if ((void *)(meta + 1) > (void *)(long)ctx->data)
        return XDP_PASS;
    
    // Populate with hardware metadata (returns -EOPNOTSUPP if unsupported)
    bpf_xdp_metadata_rx_timestamp(ctx, &meta->timestamp);
    bpf_xdp_metadata_rx_hash(ctx, &meta->hash, NULL);
    
    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
}
```

Query supported metadata via netlink `NETDEV_A_DEV_XDP_RX_METADATA_FEATURES`.

## Testing XDP programs with BPF_PROG_TEST_RUN

The `BPF_PROG_RUN` syscall (formerly `BPF_PROG_TEST_RUN`) enables unit testing XDP programs without attaching to real interfaces.

### Basic test run

```c
#include <bpf/bpf.h>

char pkt[] = {
    // Ethernet header
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // dst MAC
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // src MAC
    0x08, 0x00,                          // EtherType: IPv4
    // IPv4 header...
};

struct xdp_md ctx = {
    .data = 0,
    .data_end = sizeof(pkt),
    .ingress_ifindex = 1,
};

LIBBPF_OPTS(bpf_test_run_opts, opts,
    .data_in = pkt,
    .data_size_in = sizeof(pkt),
    .ctx_in = &ctx,
    .ctx_size_in = sizeof(ctx),
    .repeat = 1000,  // Run 1000 times for benchmarking
);

int prog_fd = bpf_program__fd(prog);
int err = bpf_prog_test_run_opts(prog_fd, &opts);

printf("Return value: %d\n", opts.retval);      // XDP_PASS, XDP_DROP, etc.
printf("Duration: %llu ns\n", opts.duration);   // Execution time
```

### Live packet injection mode

Kernel 5.18+ supports `BPF_F_TEST_XDP_LIVE_FRAMES` for actual packet transmission:

```c
LIBBPF_OPTS(bpf_test_run_opts, opts,
    .data_in = pkt,
    .data_size_in = sizeof(pkt),
    .flags = BPF_F_TEST_XDP_LIVE_FRAMES,
    .batch_size = 64,     // Packets per batch (max 256)
    .repeat = 100000,     // Total packets
);

// XDP_TX/XDP_REDIRECT actions actually transmit packets
bpf_prog_test_run_opts(prog_fd, &opts);
```

This enables building high-performance traffic generators—up to 9 Mpps per core.

### Using bpftool for testing

```bash
# Create test packet file
echo -n -e '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00' > pkt.bin

# Run XDP program with packet
bpftool prog run pinned /sys/fs/bpf/xdp_prog \
    data_in pkt.bin \
    repeat 1000

# Output shows return value and timing
```

## Production use cases demonstrate XDP's capabilities

### DDoS mitigation

XDP excels at volumetric attack mitigation by dropping malicious traffic before kernel processing:

```c
struct rate_limit {
    __u64 last_update;
    __u32 packet_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);                    // Source IP
    __type(value, struct rate_limit);
    __uint(max_entries, 100000);
} rate_map SEC(".maps");

#define THRESHOLD 1000          // Max packets per window
#define WINDOW_NS 1000000000    // 1 second window

SEC("xdp")
int xdp_ddos_filter(struct xdp_md *ctx) {
    // Parse to get source IP...
    __u32 src_ip = ip->saddr;
    
    struct rate_limit *rl = bpf_map_lookup_elem(&rate_map, &src_ip);
    __u64 now = bpf_ktime_get_ns();
    
    if (!rl) {
        struct rate_limit new_rl = { .last_update = now, .packet_count = 1 };
        bpf_map_update_elem(&rate_map, &src_ip, &new_rl, BPF_ANY);
        return XDP_PASS;
    }
    
    if (now - rl->last_update > WINDOW_NS) {
        rl->last_update = now;
        rl->packet_count = 1;
    } else {
        rl->packet_count++;
        if (rl->packet_count > THRESHOLD)
            return XDP_DROP;
    }
    
    return XDP_PASS;
}
```

Production deployments (Facebook, Cloudflare) drop **26+ million packets per second per core**.

### Layer 4 load balancing with XDP_TX

```c
struct backend {
    __u32 ip;
    unsigned char mac[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct backend);
    __uint(max_entries, 64);
} backends SEC(".maps");

SEC("xdp")
int xdp_lb(struct xdp_md *ctx) {
    // Parse headers...
    
    // Select backend (round-robin, hash, etc.)
    __u32 idx = bpf_get_prandom_u32() % num_backends;
    struct backend *be = bpf_map_lookup_elem(&backends, &idx);
    if (!be)
        return XDP_PASS;
    
    // Rewrite destination IP and MAC
    ip->daddr = be->ip;
    __builtin_memcpy(eth->h_dest, be->mac, 6);
    
    // Recalculate IP checksum
    ip->check = 0;
    ip->check = iph_csum(ip);
    
    // Transmit out same interface
    return XDP_TX;
}
```

### Packet sampling for monitoring

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("xdp")
int xdp_sampler(struct xdp_md *ctx) {
    // Sample 1 in 1000 packets
    if ((bpf_get_prandom_u32() & 0x3FF) == 0) {
        void *data = (void *)(long)ctx->data;
        __u64 size = (__u64)(ctx->data_end - ctx->data);
        
        // Send first 128 bytes to userspace
        if (size > 128) size = 128;
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                              data, size);
    }
    return XDP_PASS;
}
```

## Common pitfalls and troubleshooting

### Driver compatibility issues

Not all drivers support native XDP. Check support:
```bash
ethtool -i eth0 | grep driver
# Check xdp-project.net for driver support status
```

Common driver issues:
- **LRO enabled**: Disable with `ethtool -K eth0 lro off`
- **Checksum offload conflicts**: May need `ethtool -K eth0 tx-checksum-ip-generic off`
- **MTU too large**: Reduce MTU or use multi-buffer XDP

### Verifier rejection patterns

| Error | Cause | Solution |
|-------|-------|----------|
| "invalid access to packet" | Missing bounds check | Add `if (ptr + size > data_end)` |
| "unreachable insn" | Dead code after return | Remove unreachable code |
| "back-edge from insn X to Y" | Unbounded loop | Use bounded loop or `bpf_loop()` |
| "stack limit exceeded" | >512 bytes on stack | Use per-CPU maps |
| "R0 not initialized" | Missing return path | Ensure all paths return |

### Performance debugging

```bash
# Check XDP statistics
ip -s link show eth0

# Monitor XDP exceptions
perf stat -e 'xdp:*' -a sleep 10

# Trace redirect failures  
cat /sys/kernel/debug/tracing/events/xdp/xdp_redirect_err/enable
echo 1 > /sys/kernel/debug/tracing/events/xdp/xdp_redirect_err/enable
cat /sys/kernel/debug/tracing/trace_pipe

# Check program run statistics
bpftool prog show id <ID>
# Shows run_time_ns and run_cnt
```

### Memory and resource limits

Increase limits if programs fail to load:
```bash
# Raise locked memory limit
ulimit -l unlimited

# Or set per-user limit
echo "* soft memlock unlimited" >> /etc/security/limits.conf
echo "* hard memlock unlimited" >> /etc/security/limits.conf
```

## Conclusion

XDP programming on kernel 5.10+ combines **libxdp's multi-program dispatch** with mature tooling for production deployments. The key architectural insight is that XDP's performance comes from bypassing sk_buff allocation entirely—your program runs in the driver before any kernel networking code touches the packet.

For maximum performance, use **per-CPU maps** for all statistics, **native mode** on supported drivers, and **AF_XDP** when packets must reach userspace. The verifier's strict bounds checking requirements actually simplify development once internalized: every packet access needs an explicit comparison against `data_end`, and the verifier tracks these comparisons to validate all subsequent accesses.

The combination of **xdp-loader** for deployment, **xdp-dump** for debugging, and **bpftool** for inspection provides a complete development workflow. Start with generic mode for testing, graduate to native mode for production, and consider AF_XDP with zero-copy for applications requiring userspace packet processing at tens of millions of packets per second.