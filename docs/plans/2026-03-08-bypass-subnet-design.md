# Bypass Subnet for Inner Destination

## Problem

When the XDP tunnel decapsulation program is attached to the same interface that terminates a kernel GRE tunnel, it decapsulates ALL GRE packets — including control plane traffic (BGP keepalives, ICMP health checks) that the kernel GRE tunnel needs to process intact. This breaks BIRD BGP sessions over GRE.

Observed on server `108.61.214.146`: GRE tunnel `gre-imperva` (remote `107.154.11.169`) carries both:
- Control plane traffic with inner dst `172.20.5.48/30` — must reach kernel GRE
- Clean forwarded traffic with inner dst `159.198.67.0/24` — should be decapsulated by XDP

## Solution

Add a bypass destination subnet to the existing `cfg_global` BPF global variable. Before decapsulating, peek at the inner IPv4 destination. If it matches the bypass subnet, return `XDP_PASS` without decapsulating.

## Changes

### `src/include/tun_decap.h`

Add two fields to `struct tun_decap_config`:

```c
__be32 bypass_dst_net;   /* Inner dst subnet to skip decap (0=disabled) */
__be32 bypass_dst_mask;  /* Subnet mask for bypass (network byte order) */
```

Zero-initialized = bypass disabled. Same pattern as existing disable flags.

### `src/bpf/tun_decap.bpf.c`

Add inline helper:

```c
static __always_inline int is_bypass_dst(__be32 daddr)
{
    return cfg_global.bypass_dst_net &&
           (daddr & cfg_global.bypass_dst_mask) == cfg_global.bypass_dst_net;
}
```

Call before `decapsulate()` in handlers with IPv4 inner packets:
- `handle_gre()` — when `inner_proto == ETH_P_IP`
- `handle_ipip()` — after inner header validation
- `handle_gre_ipv6()` — when `inner_proto == ETH_P_IP`
- `handle_ipip_ipv6()` — in `IPPROTO_IPIP` branch

On match: return `XDP_PASS` (packet reaches kernel GRE intact).

### Testing

- Existing tests pass unchanged (bypass zero-initialized = disabled)
- New BPF test: GRE packet with inner dst in bypass subnet → `XDP_PASS` without decap
- Live verification: attach XDP with bypass `172.20.5.48/30`, confirm BIRD BGP stays up

### Not in scope

- IPv6 bypass subnet
- Multiple bypass subnets
- Source-based bypass
- New dedicated stats counter (reuse `pass_non_tunnel`)

## Usage

```bash
# Load XDP program
ip link set dev enp1s0 xdp obj tun_decap.bpf.o sec xdp

# Set bypass for tunnel subnet 172.20.5.48/30 via .bss map
# bypass_dst_net  = 172.20.5.48 = ac 14 05 30
# bypass_dst_mask = 255.255.255.252 = ff ff ff fc
# Fields are at offset 4 and 8 in tun_decap_config struct
```
