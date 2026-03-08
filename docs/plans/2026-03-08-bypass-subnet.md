# Bypass Subnet Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a configurable bypass destination subnet to the XDP tunnel decapsulation program so packets with matching inner IPv4 destinations pass through to the kernel without decapsulation.

**Architecture:** Extend the existing `cfg_global` BPF global variable with `bypass_dst_net` and `bypass_dst_mask` fields. Add an `is_bypass_dst()` inline helper called in each handler before `decapsulate()`. Zero-initialized = bypass disabled.

**Tech Stack:** C, BPF/XDP, libbpf skeleton, BPF_PROG_TEST_RUN

---

### Task 1: Add bypass fields to config struct

**Files:**
- Modify: `src/include/tun_decap.h:80-85`

**Step 1: Add fields to `struct tun_decap_config`**

In `src/include/tun_decap.h`, add two fields after `disable_stats`:

```c
struct tun_decap_config {
	__u8 disabled;      /* Master disable switch (0=enabled, 1=disabled) */
	__u8 disable_gre;   /* Disable GRE processing (0=enabled, 1=disabled) */
	__u8 disable_ipip;  /* Disable IPIP processing (0=enabled, 1=disabled) */
	__u8 disable_stats; /* Disable statistics collection (0=enabled, 1=disabled) */
	__be32 bypass_dst_net;  /* Inner dst subnet to skip decap (0=disabled) */
	__be32 bypass_dst_mask; /* Subnet mask for bypass (network byte order) */
};
```

**Step 2: Verify it compiles**

Run: `make clean && make bpf`
Expected: Compiles without errors. Struct layout change is backward-compatible (new fields are zero-initialized).

**Step 3: Commit**

```
feat: add bypass_dst_net/mask fields to tun_decap_config
```

---

### Task 2: Add bypass helper and wire into handlers

**Files:**
- Modify: `src/bpf/tun_decap.bpf.c`

**Step 1: Add `is_bypass_dst()` helper**

Add after the `is_whitelisted_v6()` function (after line 198), before `decapsulate()`:

```c
/*
 * Check if inner IPv4 destination matches bypass subnet
 *
 * Used to skip decapsulation for packets destined to the kernel
 * GRE tunnel endpoint (e.g., BGP control plane traffic).
 *
 * @daddr: Inner IPv4 destination in network byte order
 * @return: 1 if bypass (skip decap), 0 otherwise
 */
static __always_inline int is_bypass_dst(__be32 daddr)
{
	return cfg_global.bypass_dst_net &&
	       (daddr & cfg_global.bypass_dst_mask) == cfg_global.bypass_dst_net;
}
```

**Step 2: Add bypass check in `handle_gre()` (IPv4 inner branch)**

In `handle_gre()`, after the inner IPv4 header bounds check (line 320) and before the `} else if (inner_proto == ETH_P_IPV6)` branch, add bypass check. Replace:

```c
	if (inner_proto == ETH_P_IP) {
		/* IPv4 inner packet */
		gre_len = gre_hdr_len(greh->flags);

		/* Verify inner IPv4 header exists */
		if (unlikely((void *)greh + gre_len + sizeof(struct iphdr) > data_end)) {
			if (stats)
				stats->drop_malformed++;
			return XDP_DROP;
		}
	} else if (inner_proto == ETH_P_IPV6) {
```

With:

```c
	if (inner_proto == ETH_P_IP) {
		/* IPv4 inner packet */
		gre_len = gre_hdr_len(greh->flags);

		/* Verify inner IPv4 header exists */
		if (unlikely((void *)greh + gre_len + sizeof(struct iphdr) > data_end)) {
			if (stats)
				stats->drop_malformed++;
			return XDP_DROP;
		}

		/* Check bypass: skip decap for kernel tunnel traffic */
		struct iphdr *inner_iph = (void *)greh + gre_len;
		if (is_bypass_dst(inner_iph->daddr)) {
			if (stats)
				stats->pass_non_tunnel++;
			return XDP_PASS;
		}
	} else if (inner_proto == ETH_P_IPV6) {
```

**Step 3: Add bypass check in `handle_ipip()`**

After the inner header validation (line 385), before the `return decapsulate(...)` call. Replace:

```c
	/* Validate inner IPv4 header */
	if (unlikely(inner_iph->version != 4 || inner_iph->ihl < 5)) {
		if (stats)
			stats->drop_malformed++;
		return XDP_DROP;
	}

	/* IPIP: only remove outer IP header (no tunnel header) */
	return decapsulate(ctx, outer_ip_len, ETH_P_IP, stats);
```

With:

```c
	/* Validate inner IPv4 header */
	if (unlikely(inner_iph->version != 4 || inner_iph->ihl < 5)) {
		if (stats)
			stats->drop_malformed++;
		return XDP_DROP;
	}

	/* Check bypass: skip decap for kernel tunnel traffic */
	if (is_bypass_dst(inner_iph->daddr)) {
		if (stats)
			stats->pass_non_tunnel++;
		return XDP_PASS;
	}

	/* IPIP: only remove outer IP header (no tunnel header) */
	return decapsulate(ctx, outer_ip_len, ETH_P_IP, stats);
```

**Step 4: Add bypass check in `handle_gre_ipv6()` (IPv4 inner branch)**

In `handle_gre_ipv6()`, after the inner IPv4 bounds check (line 491), same pattern as `handle_gre()`. Replace:

```c
	if (inner_proto == ETH_P_IP) {
		gre_len = gre_hdr_len(greh->flags);

		if (unlikely((void *)greh + gre_len + sizeof(struct iphdr) > data_end)) {
			if (stats)
				stats->drop_malformed++;
			return XDP_DROP;
		}
	} else if (inner_proto == ETH_P_IPV6) {
```

With:

```c
	if (inner_proto == ETH_P_IP) {
		gre_len = gre_hdr_len(greh->flags);

		if (unlikely((void *)greh + gre_len + sizeof(struct iphdr) > data_end)) {
			if (stats)
				stats->drop_malformed++;
			return XDP_DROP;
		}

		/* Check bypass: skip decap for kernel tunnel traffic */
		struct iphdr *inner_iph = (void *)greh + gre_len;
		if (is_bypass_dst(inner_iph->daddr)) {
			if (stats)
				stats->pass_non_tunnel++;
			return XDP_PASS;
		}
	} else if (inner_proto == ETH_P_IPV6) {
```

**Step 5: Add bypass check in `handle_ipip_ipv6()` (IPPROTO_IPIP branch)**

In the `IPPROTO_IPIP` branch of `handle_ipip_ipv6()`, after inner header validation (line 560). Replace:

```c
		if (unlikely(inner_iph->version != 4 || inner_iph->ihl < 5)) {
			if (stats)
				stats->drop_malformed++;
			return XDP_DROP;
		}

		inner_proto = ETH_P_IP;
```

With:

```c
		if (unlikely(inner_iph->version != 4 || inner_iph->ihl < 5)) {
			if (stats)
				stats->drop_malformed++;
			return XDP_DROP;
		}

		/* Check bypass: skip decap for kernel tunnel traffic */
		if (is_bypass_dst(inner_iph->daddr)) {
			if (stats)
				stats->pass_non_tunnel++;
			return XDP_PASS;
		}

		inner_proto = ETH_P_IP;
```

**Step 6: Verify it compiles**

Run: `make clean && make bpf`
Expected: Compiles without errors or warnings.

**Step 7: Commit**

```
feat: add is_bypass_dst() check before decapsulation in all handlers
```

---

### Task 3: Add bypass test packet

**Files:**
- Modify: `src/test/test_packets.h`

**Step 1: Add a GRE test packet with bypass-matching inner destination**

Add at the end of `test_packets.h` (before `#endif`). This is a copy of `pkt_gre_whitelisted` but with inner destination `172.20.5.49` (the tunnel endpoint IP — `0xac140531`):

```c
/*
 * GRE-encapsulated IPv4 packet with inner dst matching bypass subnet
 *
 * Same as pkt_gre_whitelisted but inner dest = 172.20.5.49 (0xac140531)
 * Used to test bypass_dst_net/mask feature.
 *
 * Structure:
 * [Ethernet: 14 bytes]
 * [Outer IPv4: 20 bytes, proto=47 (GRE), src=10.0.0.1]
 * [GRE: 4 bytes, no options, proto=0x0800 (IPv4)]
 * [Inner IPv4: 20 bytes, proto=6 (TCP), src=172.16.0.1, dst=172.20.5.49]
 * [TCP: 20 bytes]
 *
 * Total: 78 bytes
 */
static unsigned char pkt_gre_bypass_dst[] = {
    /* Ethernet header (14 bytes) */
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* Destination MAC */
    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, /* Source MAC */
    0x08, 0x00,                         /* EtherType: IPv4 */

    /* Outer IPv4 header (20 bytes) */
    0x45,                   /* Version=4, IHL=5 (20 bytes) */
    0x00,                   /* DSCP/ECN */
    0x00, 0x40,             /* Total length: 64 bytes */
    0x00, 0x01,             /* Identification */
    0x00, 0x00,             /* Flags + Fragment offset */
    0x40,                   /* TTL: 64 */
    0x2f,                   /* Protocol: 47 (GRE) */
    0x00, 0x00,             /* Header checksum (zeroed) */
    0x0a, 0x00, 0x00, 0x01, /* Source IP: 10.0.0.1 (whitelisted) */
    0xc0, 0xa8, 0x01, 0x01, /* Dest IP: 192.168.1.1 */

    /* GRE header (4 bytes, no optional fields) */
    0x00, 0x00, /* Flags: C=0, K=0, S=0, Ver=0 */
    0x08, 0x00, /* Protocol: IPv4 (0x0800) */

    /* Inner IPv4 header (20 bytes) */
    0x45,                   /* Version=4, IHL=5 */
    0x00,                   /* DSCP/ECN */
    0x00, 0x28,             /* Total length: 40 bytes */
    0x00, 0x02,             /* Identification */
    0x00, 0x00,             /* Flags + Fragment offset */
    0x40,                   /* TTL: 64 */
    0x06,                   /* Protocol: 6 (TCP) */
    0x00, 0x00,             /* Header checksum */
    0xac, 0x10, 0x00, 0x01, /* Source IP: 172.16.0.1 */
    0xac, 0x14, 0x05, 0x31, /* Dest IP: 172.20.5.49 (bypass target) */

    /* TCP header (20 bytes) */
    0x00, 0x50,             /* Source port: 80 */
    0x00, 0x51,             /* Dest port: 81 */
    0x00, 0x00, 0x00, 0x01, /* Sequence number */
    0x00, 0x00, 0x00, 0x00, /* Acknowledgment number */
    0x50, 0x02,             /* Data offset=5, SYN flag */
    0xff, 0xff,             /* Window size */
    0x00, 0x00,             /* Checksum */
    0x00, 0x00,             /* Urgent pointer */
};

#define PKT_GRE_BYPASS_DST_LEN sizeof(pkt_gre_bypass_dst)
```

**Step 2: Commit**

```
test: add GRE test packet with bypass destination
```

---

### Task 4: Add bypass BPF test

**Files:**
- Modify: `src/test/test_decap.c`

**Step 1: Write the test function**

Add before `main()` (around line 1130):

```c
/*
 * Test: GRE packet with inner dst matching bypass subnet should NOT be decapsulated
 */
static void test_gre_bypass_dst(struct tun_decap_bpf *skel)
{
	const char *name = "GRE bypass (inner dst matches bypass subnet)";
	int prog_fd = bpf_program__fd(skel->progs.xdp_tun_decap);
	__u32 retval;
	unsigned char data_out[256];
	size_t data_out_len = sizeof(data_out);
	int err;

#ifdef ENABLE_WHITELIST
	int wl_fd = bpf_map__fd(skel->maps.tun_decap_whitelist);
	whitelist_add(wl_fd, TEST_IP_WHITELISTED_1);
#endif

	/* Set bypass subnet: 172.20.5.48/30 */
	/* 172.20.5.48 = 0xac140530, mask /30 = 0xfffffffc */
	skel->bss->cfg_global.bypass_dst_net = htonl(0xac140530);
	skel->bss->cfg_global.bypass_dst_mask = htonl(0xfffffffc);

	/* Run test with packet whose inner dst is 172.20.5.49 */
	err = run_xdp_test(prog_fd, pkt_gre_bypass_dst, PKT_GRE_BYPASS_DST_LEN, &retval, data_out,
	                   &data_out_len);
	if (err < 0) {
		TEST_FAIL(name, "bpf_prog_test_run failed");
		goto cleanup;
	}

	/* Verify XDP_PASS (not decapsulated) */
	if (retval != XDP_PASS) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected XDP_PASS(%d), got %d", XDP_PASS, retval);
		TEST_FAIL(name, buf);
		goto cleanup;
	}

	/* Verify packet was NOT decapsulated - length should be unchanged */
	if (data_out_len != PKT_GRE_BYPASS_DST_LEN) {
		char buf[96];
		snprintf(buf, sizeof(buf), "Expected len=%zu (no decap), got %zu",
		         (size_t)PKT_GRE_BYPASS_DST_LEN, data_out_len);
		TEST_FAIL(name, buf);
		goto cleanup;
	}

	TEST_PASS(name);

cleanup:
	/* Reset bypass config for other tests */
	skel->bss->cfg_global.bypass_dst_net = 0;
	skel->bss->cfg_global.bypass_dst_mask = 0;
}
```

**Step 2: Wire test into `main()`**

Add after the fragment drop tests block (after line 1201):

```c
	/* Bypass destination tests */
	test_gre_bypass_dst(skel);
```

**Step 3: Build and run tests**

Run: `make clean && make all && sudo make test`
Expected: All existing tests pass, new `test_gre_bypass_dst` passes.

**Step 4: Commit**

```
test: add BPF test for bypass destination subnet
```

---

### Task 5: Initialize bypass config in test setup

**Files:**
- Modify: `src/test/test_decap.c:1165-1170`

**Step 1: Add bypass field initialization alongside existing config init**

After line 1170, add:

```c
	skel->bss->cfg_global.bypass_dst_net = 0;
	skel->bss->cfg_global.bypass_dst_mask = 0;
```

**Step 2: Run full test suite to verify nothing broke**

Run: `sudo make test`
Expected: All tests pass.

**Step 3: Commit**

```
chore: initialize bypass config fields in test setup
```

---

### Task 6: Update CLAUDE.md documentation

**Files:**
- Modify: `CLAUDE.md`

**Step 1: Add bypass config to the "Managing BPF Maps" section**

Add after the existing config examples (after the "View current config" line):

```bash
# Set bypass destination subnet (skip decap for matching inner dst)
# Example: bypass 172.20.5.48/30 (GRE tunnel endpoint subnet)
# bypass_dst_net  = 172.20.5.48 = ac 14 05 30
# bypass_dst_mask = /30          = ff ff ff fc
# Fields are at byte offsets 4-7 and 8-11 in tun_decap_config
# Update via skeleton .bss or bpftool on .bss map
```

**Step 2: Add bypass mention to the config struct docs**

In the "Config" map description section, add:
- `bypass_dst_net`: Inner IPv4 destination subnet to skip decap (0=disabled)
- `bypass_dst_mask`: Subnet mask for bypass (network byte order)

**Step 3: Commit**

```
docs: document bypass destination subnet config
```

---

### Task 7: Build and deploy to server for live test

**Step 1: Build the BPF object with WHITELIST=0 STATS=0**

Run: `make clean && make all WHITELIST=0 STATS=0`

**Step 2: Copy to server**

Run: `scp -J none build/tun_decap.bpf.o root@108.61.214.146:/root/tun_decap-wl0-stats0-bypass.bpf.o`

**Step 3: Test on server**

SSH to server and:

```bash
# Load XDP program
ip link set dev enp1s0 xdp obj /root/tun_decap-wl0-stats0-bypass.bpf.o sec xdp

# Set bypass for tunnel subnet via .bss map
# First find the .bss map ID:
bpftool map show | grep bss

# Update bypass_dst_net (offset 4) and bypass_dst_mask (offset 8)
# using bpftool map update on the .bss map
# 172.20.5.48 = ac 14 05 30, /30 mask = ff ff ff fc

# Verify BIRD BGP session stays established
birdc show protocols imperva

# Monitor for ~5 minutes to confirm stability
watch -n 30 'birdc show protocols imperva'

# If issue persists, detach immediately:
ip link set dev enp1s0 xdp off
```

**Step 4: Commit any fixes needed from live testing**

---

Plan complete and saved to `docs/plans/2026-03-08-bypass-subnet.md`. Two execution options:

**1. Subagent-Driven (this session)** — I dispatch fresh subagent per task, review between tasks, fast iteration

**2. Parallel Session (separate)** — Open new session with executing-plans, batch execution with checkpoints

Which approach?