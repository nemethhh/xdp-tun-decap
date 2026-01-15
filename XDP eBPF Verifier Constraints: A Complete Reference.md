# XDP eBPF Verifier Constraints: A Complete Reference

The Linux kernel's eBPF verifier acts as a strict gatekeeper, performing exhaustive static analysis to guarantee that every XDP program terminates safely and never corrupts kernel memory. Understanding its constraints is essential for developers—particularly those using Aya (Rust)—since verification failures often produce cryptic errors that require deep knowledge to resolve. This guide covers **all major verification rules**, from instruction limits to pointer arithmetic, with practical patterns that pass verification reliably.

## Instruction limits have evolved dramatically since kernel 5.2

The verifier enforces two distinct limits that are frequently confused. **BPF_MAXINSNS (4,096 instructions)** applies to unprivileged programs, while **BPF_COMPLEXITY_LIMIT_INSNS (1,000,000 instructions)** applies to privileged programs with `CAP_BPF` or `CAP_SYS_ADMIN`. The critical distinction: *program instruction count* refers to actual bytecode instructions, while *verifier complexity* measures total instructions explored across all execution paths.

A 100-instruction program with many branches can exhaust complexity limits while having few actual instructions. The verifier simulates every path, and branches multiply exponentially—three independent conditionals create 8 paths to verify.

| Limit | Value | Applies To | Kernel |
|-------|-------|------------|--------|
| BPF_MAXINSNS | 4,096 | Unprivileged users | All |
| BPF_COMPLEXITY_LIMIT_INSNS | 1,000,000 | Privileged users | 5.2+ |
| BPF_COMPLEXITY_LIMIT_STATES | 64 per instruction | All programs | All |
| BPF_COMPLEXITY_LIMIT_JMP_SEQ | 8,192 | Branch state limit | All |

Before kernel 5.2, the complexity limit was 131,072 instructions. The jump to 1 million enabled significantly more sophisticated programs, but **bounded loops (kernel 5.3+)** and **bpf_loop() (kernel 5.17+)** remain the most effective tools for iteration-heavy code.

## Memory access requires explicit bounds verification

The verifier tracks every register's type and value range using `struct bpf_reg_state`. For scalars, it maintains unsigned bounds (`umin_value`, `umax_value`), signed bounds (`smin_value`, `smax_value`), and tristate numbers for bit-level precision. Reading a single byte sets the register to `tnum (0x0; 0xff)`—top 56 bits known zero, low 8 bits unknown.

### Direct packet access demands the data/data_end pattern

Every XDP program must validate packet bounds before any access:

```c
void *data = (void *)(long)ctx->data;
void *data_end = (void *)(long)ctx->data_end;

if (data + sizeof(struct ethhdr) > data_end)
    return XDP_PASS;  // Required exit path

struct ethhdr *eth = data;  // Now safe—verifier marks R3=pkt(off=0,r=14)
```

The verifier's output `pkt(id=0,off=0,r=14)` indicates: no variable additions (`id=0`), no constant offset (`off=0`), and **14 bytes are safe to access** (`r=14`). Each new header requires a fresh bounds check—parsing Ethernet, then IP, then TCP means three separate validations.

**Critical rule**: After calling `bpf_xdp_adjust_head()`, `bpf_xdp_adjust_tail()`, or `bpf_xdp_adjust_meta()`, all previous bounds checks are invalidated. You must re-read `ctx->data` and `ctx->data_end` and perform new checks.

### Stack memory access follows strict initialization rules

Stack slots exist in range `[-512, 0)` from the frame pointer R10. The verifier tracks each 8-byte slot's state:

- **STACK_INVALID**: Uninitialized (reading causes rejection)
- **STACK_SPILL**: Contains a spilled register with preserved type
- **STACK_MISC**: Contains written data
- **STACK_ZERO**: Contains known zero

```c
// REJECTED: "invalid indirect read from stack off -8+0 size 8"
bpf_ld R0 = *(u32 *)(R10 - 4)  // No prior write
bpf_exit

// CORRECT: Initialize before reading
bpf_st *(u32 *)(R10 - 4) = 0   // Write first
bpf_ld R0 = *(u32 *)(R10 - 4)  // Now safe
```

### Map lookups require mandatory NULL checks

`bpf_map_lookup_elem()` returns `PTR_TO_MAP_VALUE_OR_NULL`. Dereferencing without checking triggers: **"R0 invalid mem access 'map_value_or_null'"**

```c
struct value *val = bpf_map_lookup_elem(&my_map, &key);
if (!val)                    // This check is MANDATORY
    return XDP_PASS;
val->counter++;              // Safe after NULL check
```

The verifier shares an `id` field among copies of the same pointer. Checking one copy validates all copies with the same id—this enables patterns where you store the lookup result in multiple variables.

## Control flow constraints prevent infinite execution

### Bounded loops work only when the verifier can prove termination

Kernel 5.3 introduced bounded loop support. The verifier simulates all iterations as a state collection, tracking scalar ranges through each branch:

```c
// Works—constant bound with clear semantics
for (int i = 0; i < 100; i++) {
    // Loop body
}

// May fail—16-bit packet field means 65,536 potential iterations
for (int i = 0; i < ip->tot_len; i++) {
    // Hits complexity limit
}
```

For large iteration counts, **bpf_loop() (kernel 5.17+)** is dramatically more efficient:

```c
long callback_fn(u32 index, void *ctx) {
    // Process item
    return 0;  // Continue (1 stops early)
}

bpf_loop(1000, callback_fn, NULL, 0);  // Max: 8,388,608 iterations
```

The verifier checks the callback only once regardless of iteration count—programs that took 30 seconds to verify with traditional loops verify in under 0.2 seconds with `bpf_loop()`.

### Tail calls split complexity across independent programs

Each tail call target is verified separately with its own complexity budget. **Maximum depth: 33 calls** (initial program plus 32 tail calls). The pattern enables spreading complex logic across programs:

```c
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(max_entries, 8);
} progs SEC(".maps");

// In XDP program:
bpf_tail_call(ctx, &progs, index);  // Never returns on success
return XDP_PASS;  // Fallback if tail call fails
```

**Stack impact**: When combining tail calls with BPF-to-BPF function calls, stack per program shrinks from **512 to 256 bytes**. This ensures maximum total stack (256 × 33 = 8KB) stays safe.

### Function call depth is limited to 8 levels

BPF-to-BPF function calls (kernel 4.16+) use fresh stack frames but cap nesting at 8 levels. **Global functions** (kernel 5.6+, declared without `static`) verify once regardless of call count—the verifier assumes nothing about arguments and verifies in isolation.

## Type safety tracks pointer operations precisely

The verifier distinguishes pointer types rigorously:

| Type | Allowed Operations |
|------|-------------------|
| PTR_TO_PACKET | Add/subtract scalars; bounds-check before deref |
| PTR_TO_MAP_VALUE | Deref after NULL check; access within value_size |
| PTR_TO_CTX | Read fields at known offsets |
| PTR_TO_STACK | Access in [-512, 0); init before read |
| CONST_PTR_TO_MAP | No arithmetic allowed |
| PTR_TO_PACKET_END | Comparison only; no arithmetic |

**Forbidden operations**: Pointer addition (PTR + PTR), multiplication, bit shifts. In unprivileged mode, all pointer arithmetic is rejected to prevent kernel address leaks.

Register spilling preserves type information:
```c
bpf_stx *(u64 *)(R10 - 8) = R6  // R6 contains PTR_TO_CTX
// ... use other registers ...
bpf_ldx R6 = *(u64 *)(R10 - 8)  // R6 restored as PTR_TO_CTX
```

## XDP helper functions have strict argument validation

XDP programs access a specific helper subset. The most critical for packet manipulation:

| Helper | Effect | Post-Call Requirement |
|--------|--------|----------------------|
| bpf_xdp_adjust_head | Moves data pointer by delta | Re-validate all packet pointers |
| bpf_xdp_adjust_tail | Adjusts data_end | Re-validate all packet pointers |
| bpf_redirect_map | Redirects to DEVMAP/CPUMAP/XSKMAP | Return XDP_REDIRECT |
| bpf_fib_lookup | FIB table lookup | Check return code |

Helper arguments are validated through ARG_PTR_TO_* types. For `bpf_map_lookup_elem`:
- R1 must be `CONST_PTR_TO_MAP`
- R2 must point to initialized stack memory of `map->key_size` bytes

Return value tracking converts types automatically—after `bpf_map_lookup_elem`, R0 becomes `PTR_TO_MAP_VALUE_OR_NULL` until a NULL check promotes it.

## Stack constraints require careful planning

The **512-byte limit** is absolute. With tail calls and BPF functions combined, this drops to **256 bytes**. Stack slots must be 8-byte aligned.

**Workaround for larger buffers**: Use per-CPU array maps as heap substitutes:

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, char[4096]);
} scratch SEC(".maps");

// In program:
u32 key = 0;
char *buf = bpf_map_lookup_elem(&scratch, &key);
if (buf) {
    // 4KB buffer available
}
```

## Map access patterns determine synchronization needs

### Spin locks protect complex updates

For multi-field updates requiring atomicity, use `bpf_spin_lock`:

```c
struct entry {
    struct bpf_spin_lock lock;  // Must be top-level field
    u64 packets;
    u64 bytes;
};

bpf_spin_lock(&val->lock);
val->packets++;
val->bytes += len;
bpf_spin_unlock(&val->lock);
```

**Restrictions while holding lock**: No helper calls, no function calls, no taking additional locks, and must unlock before returning. Maps require **BTF descriptions** to use spin locks.

### Per-CPU maps eliminate synchronization entirely

For counters and scratch buffers, `BPF_MAP_TYPE_PERCPU_ARRAY` and `BPF_MAP_TYPE_PERCPU_HASH` provide CPU-isolated storage:

```c
__u64 *counter = bpf_map_lookup_elem(&percpu_counter, &key);
if (counter)
    *counter += 1;  // No atomic needed—per-CPU isolation
```

For shared maps with simple updates, use atomics: `__sync_fetch_and_add(&val->counter, 1)`.

### XDP redirect maps enable efficient packet steering

| Map Type | Use Case |
|----------|----------|
| DEVMAP | Redirect to network interfaces |
| CPUMAP | Software RSS across CPUs |
| XSKMAP | Zero-copy to userspace via AF_XDP |

The redirect pattern requires calling `bpf_redirect_map()` and returning `XDP_REDIRECT`:

```c
return bpf_redirect_map(&devmap, key, XDP_PASS);  // XDP_PASS is fallback
```

## Aya-specific patterns for passing verification

### Always inline helper functions

```rust
#[inline(always)]  // Required—prevents separate function generation
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}
```

Use bpf-linker flags `--unroll-loops` for pre-5.3 kernels and `--ignore-inline-never` for older kernels without function call support.

### Prevent LLVM from generating unbounded loops

```rust
const MAX_ITERATIONS: u32 = 100;
for i in 0..MAX_ITERATIONS {
    if done { break; }
}
```

### Re-validate after packet adjustment

```rust
ctx.adjust_head(delta)?;
// ALL previous pointers are now invalid
let data = ctx.data();      // Must re-fetch
let data_end = ctx.data_end();
if data + size > data_end { // Must re-check
    return Err(());
}
```

## Common verifier errors and their solutions

| Error Message | Cause | Fix |
|---------------|-------|-----|
| "R0 invalid mem access 'map_value_or_null'" | Deref without NULL check | Add `if (!val) return;` |
| "invalid access to packet" | Missing bounds check | Add `if (data + N > data_end)` |
| "back-edge from insn X to Y" | Unbounded loop | Use bounded loop or bpf_loop() |
| "unreachable insn" | Dead code detected | Remove unreachable code paths |
| "invalid stack off=X" | Stack access out of bounds | Use negative offsets in [-512, 0) |
| "invalid indirect read from stack" | Reading uninitialized stack | Initialize before read/helper call |
| "math between pkt pointer and register" | Invalid pointer arithmetic | Use only add/subtract on pointers |

### Debug workflow for verification failures

1. Compile with debug info: `clang -O2 -g -target bpf`
2. Capture verifier log: `bpftool prog load prog.o /sys/fs/bpf/prog`
3. Correlate instruction numbers with source via `llvm-objdump -S`
4. Look for register states like `R0=map_value_or_null` indicating required checks

For Aya, enable verbose logging:
```rust
let bpf = EbpfLoader::new()
    .verifier_log_level(VerifierLogLevel::VERBOSE | VerifierLogLevel::STATS)
    .load_file("prog.o")?;
```
## LLVM Builtins Available in BPF(must be used where appropriate)
Builtin Purpose
__builtin_memcpy Copy memory blocks
__builtin_memset Fill memory with value
__builtin_memcmp Compare memory blocks
__builtin_memmove Copy (overlap-safe)
__builtin_bswap16/32/64 Byte-swap (endianness)

## Conclusion

The eBPF verifier enforces a comprehensive safety model that, once understood, becomes predictable. Key takeaways: **always bounds-check before packet access**, **always NULL-check map lookups**, **re-validate pointers after adjustment helpers**, and **use per-CPU maps or atomics for concurrency**. For iteration-heavy code, prefer `bpf_loop()` (5.17+) or open-coded iterators (6.4+) over traditional bounded loops. In Aya, mark helper functions `#[inline(always)]` and rely on the ptr_at pattern for safe packet parsing. When verification fails, the verifier log—while dense—contains precise information about which register violated which invariant at which instruction.
