// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * tun_decap.bpf.c - XDP tunnel decapsulation program
 *
 * Decapsulates GRE (protocol 47) and IPIP (protocol 4) tunnel traffic.
 * Uses whitelist-based access control to filter tunnel sources.
 *
 * Features:
 * - libxdp multi-program support with XDP_RUN_CONFIG
 * - RCU-protected hash map whitelists for lock-free lookups
 * - Per-CPU statistics counters (single-struct for minimal map lookups)
 * - Global config variable (no map lookup per packet)
 * - CO-RE support for kernel portability
 *
 * Target: Linux kernel 5.17+
 */

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* Branch prediction hints */
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

/*
 * libxdp XDP_RUN_CONFIG for multi-program support
 *
 * This struct is read by libxdp to configure the dispatcher:
 * - priority: Lower values run earlier (10 = early)
 * - chain_call_actions: Bitmask of XDP actions that chain to next program
 *   - Bit 2 (XDP_PASS): chain on pass
 *   - Bit 1 (XDP_DROP): don't chain on drop
 */
#ifdef HAVE_XDP_HELPERS
#include <xdp/xdp_helpers.h>
#else
/* Manual definition compatible with libxdp */
struct xdp_run_config {
	__u32 prog_id; /* Unused in .o file, set by loader */
	__u32 priority;
	__u32 flags;              /* Reserved */
	__u32 chain_call_actions; /* Bitmask: bit N = chain on action N */
};
#define XDP_RUN_CONFIG(name) struct xdp_run_config _xdp_run_config_##name SEC(".xdp_run_config") =
#endif

#include "gre.h"
#include "parsing.h"
#include "tun_decap.h"

/*
 * libxdp multi-program dispatcher configuration
 *
 * Priority 10: Run early to decapsulate before other programs
 * Chain call actions bitmask:
 *   - XDP_ABORTED (0) = 0x01 - don't chain
 *   - XDP_DROP    (1) = 0x02 - don't chain
 *   - XDP_PASS    (2) = 0x04 - chain (decapsulated/non-tunnel continues)
 *   - XDP_TX      (3) = 0x08 - don't chain
 *   - XDP_REDIRECT(4) = 0x10 - don't chain
 */
#ifndef HAVE_XDP_HELPERS
XDP_RUN_CONFIG(xdp_tun_decap){
    .prog_id = 0,
    .priority = XDP_PRIORITY, /* 10 */
    .flags = 0,
    .chain_call_actions = (1U << XDP_PASS), /* 0x04 - chain only on XDP_PASS */
};
#else
/* Use macro from xdp_helpers.h */
struct {
	__uint(priority, XDP_PRIORITY);
	__uint(XDP_PASS, 1);
	__uint(XDP_DROP, 0);
} XDP_RUN_CONFIG(xdp_tun_decap);
#endif

#ifdef ENABLE_WHITELIST
/*
 * Whitelist map for lock-free lookups (IPv4)
 *
 * Key: IPv4 address in network byte order
 * Value: Simple flag (struct whitelist_value)
 *
 * Using HASH (not PERCPU_HASH) because:
 * - Lookups are read-only from BPF and already RCU-protected (lock-free)
 * - Saves (num_cpus - 1) * value_size memory per entry
 * - Simpler userspace management (single value, not per-CPU array)
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, WHITELIST_MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct whitelist_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} tun_decap_whitelist SEC(".maps");

/*
 * Whitelist map for IPv6 addresses
 *
 * Key: IPv6 address (struct ipv6_addr - 16 bytes)
 * Value: Simple flag (struct whitelist_value)
 *
 * Separate map from IPv4 for:
 * - Efficient key size (no need to pad IPv4 to 16 bytes)
 * - Clear separation of address families
 * - Independent capacity management
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, WHITELIST_MAX_ENTRIES);
	__type(key, struct ipv6_addr);
	__type(value, struct whitelist_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} tun_decap_whitelist_v6 SEC(".maps");
#endif /* ENABLE_WHITELIST */

#ifdef ENABLE_STATS
/*
 * Per-CPU statistics - single struct per entry
 *
 * All counters in one map entry = ONE bpf_map_lookup_elem per packet,
 * then direct field increments (no helper calls). This is the single
 * biggest performance optimization vs per-counter array entries.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct tun_decap_stats);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} tun_decap_stats SEC(".maps");
#endif

/*
 * Runtime configuration as BPF global variable
 *
 * Direct memory loads instead of bpf_map_lookup_elem() per packet.
 * Accessible from userspace via skeleton .bss or pinned .bss map.
 * volatile: prevents compiler from caching across packets.
 *
 * Zero-initialized = all processing enabled (no init needed).
 */
volatile struct tun_decap_config cfg_global = {};

#ifdef ENABLE_STATS
/*
 * Get per-CPU statistics struct (called once per packet)
 *
 * Single lookup provides access to all counters via direct
 * field increments - no additional map lookups needed.
 *
 * @return: Pointer to stats struct or NULL
 */
static __always_inline struct tun_decap_stats *get_stats(void)
{
	__u32 key = 0;
	return bpf_map_lookup_elem(&tun_decap_stats, &key);
}
#endif

#ifdef ENABLE_WHITELIST
/*
 * Check if IPv4 source IP is in whitelist
 *
 * @ip_addr: IPv4 address in network byte order
 * @return: 1 if whitelisted, 0 otherwise
 */
static __always_inline int is_whitelisted(__be32 ip_addr)
{
	__u32 key = ip_addr; /* Network byte order */
	struct whitelist_value *val;

	val = bpf_map_lookup_elem(&tun_decap_whitelist, &key);
	return val != NULL;
}

/*
 * Check if IPv6 source address is in whitelist
 *
 * @ip6_addr: Pointer to IPv6 address (struct in6_addr from ipv6hdr)
 * @return: 1 if whitelisted, 0 otherwise
 */
static __always_inline int is_whitelisted_v6(const struct in6_addr *ip6_addr)
{
	struct ipv6_addr key;
	struct whitelist_value *val;

	/* Use __builtin_memcpy for efficient 128-bit copy
	 * With -mcpu=v3, this generates 2x 64-bit load + 2x 64-bit store
	 * instead of 4x 32-bit load + 4x 32-bit store */
	__builtin_memcpy(&key, ip6_addr, sizeof(key));

	val = bpf_map_lookup_elem(&tun_decap_whitelist_v6, &key);
	return val != NULL;
}
#endif /* ENABLE_WHITELIST */

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

/*
 * Check if inner IPv6 destination matches bypass prefix
 *
 * @daddr: Pointer to inner IPv6 destination address (struct in6_addr)
 * @return: 1 if bypass (skip decap), 0 otherwise
 */
static __always_inline int is_bypass_dst_v6(const struct in6_addr *daddr)
{
	volatile struct ipv6_addr *net = &cfg_global.bypass_dst6_net;
	volatile struct ipv6_addr *mask = &cfg_global.bypass_dst6_mask;
	const __u32 *d = (const __u32 *)daddr;

	/* Quick check: bypass disabled if net is all zeros */
	if (!(net->addr[0] | net->addr[1] | net->addr[2] | net->addr[3]))
		return 0;

	return ((d[0] & mask->addr[0]) == net->addr[0]) &&
	       ((d[1] & mask->addr[1]) == net->addr[1]) &&
	       ((d[2] & mask->addr[2]) == net->addr[2]) &&
	       ((d[3] & mask->addr[3]) == net->addr[3]);
}

/*
 * Perform decapsulation by removing outer headers
 *
 * Uses forward-copy technique (Katran-style):
 * 1. Copy MAC addresses forward to new position (before adjust)
 * 2. Set EtherType at new position
 * 3. Call bpf_xdp_adjust_head() to remove tunnel headers
 *
 * This avoids stack temporaries and the post-adjust bounds check
 * + restore that the save/restore approach requires.
 *
 * @ctx: XDP context
 * @decap_len: Number of bytes to remove (outer IP + tunnel header)
 * @inner_proto: Inner protocol type (ETH_P_IP or ETH_P_IPV6)
 * @stats: Pre-fetched stats pointer (may be NULL if stats disabled)
 * @return: XDP action (XDP_PASS on success, XDP_DROP on failure)
 */
static __always_inline int decapsulate(struct xdp_md *ctx, int decap_len, __u16 inner_proto,
                                       struct tun_decap_stats *stats)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct ethhdr *new_eth;
	int ret;

	/* Bounds check: need access to current ETH header and the new position */
	if (unlikely((void *)(eth + 1) > data_end)) {
		if (stats)
			stats->decap_failed++;
		return XDP_DROP;
	}

	/* Bounds check: verify new ETH position is within packet */
	new_eth = (void *)eth + decap_len;
	if (unlikely((void *)(new_eth + 1) > data_end)) {
		if (stats)
			stats->decap_failed++;
		return XDP_DROP;
	}

	/* Forward-copy: write MAC addresses and EtherType to new position
	 * before adjusting head. After adjust, this becomes the ETH header. */
	// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
	__builtin_memcpy(new_eth->h_dest, eth->h_dest, 6);
	// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
	__builtin_memcpy(new_eth->h_source, eth->h_source, 6);
	new_eth->h_proto = bpf_htons(inner_proto);

	/*
	 * Adjust head to remove outer IP + tunnel headers
	 * Positive delta = shrink headroom (remove bytes from front)
	 */
	ret = bpf_xdp_adjust_head(ctx, decap_len);
	if (unlikely(ret < 0)) {
		if (stats)
			stats->decap_failed++;
		return XDP_DROP;
	}

	if (stats)
		stats->decap_success++;
	return XDP_PASS;
}

/*
 * Handle GRE encapsulated packets
 *
 * GRE packet structure:
 * [Ethernet][Outer IP][GRE Header][Inner IP][Payload]
 *
 * Supports both IPv4 and IPv6 inner packets.
 * Called AFTER whitelist and fragmentation checks have passed.
 *
 * @ctx: XDP context
 * @outer_iph: Pointer to outer IP header
 * @outer_ip_len: Outer IP header length in bytes
 * @data_end: Packet end pointer
 * @stats: Pre-fetched stats pointer (may be NULL)
 * @return: XDP action
 */
static __always_inline int handle_gre(struct xdp_md *ctx, struct iphdr *outer_iph, int outer_ip_len,
                                      void *data_end, struct tun_decap_stats *stats)
{
	struct gre_base_hdr *greh;
	int gre_len;
	int decap_len;
	__u16 inner_proto;

	if (stats)
		stats->rx_gre++;

	/* Parse GRE header */
	greh = (void *)outer_iph + outer_ip_len;
	if (unlikely((void *)(greh + 1) > data_end)) {
		if (stats)
			stats->drop_malformed++;
		return XDP_DROP;
	}

	/* Validate GRE header (version must be 0) */
	if (unlikely(gre_validate_flags(greh->flags) < 0)) {
		if (stats)
			stats->drop_malformed++;
		return XDP_DROP;
	}

	/* Check inner protocol type */
	inner_proto = bpf_ntohs(greh->protocol);

	/* Only decapsulate IPv4 or IPv6 payloads */
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
		/* IPv6 inner packet */
		gre_len = gre_hdr_len(greh->flags);

		/* Verify inner IPv6 header exists */
		if (unlikely((void *)greh + gre_len + sizeof(struct ipv6hdr) > data_end)) {
			if (stats)
				stats->drop_malformed++;
			return XDP_DROP;
		}

		/* Check bypass: skip decap for kernel tunnel traffic */
		struct ipv6hdr *inner_ip6h = (void *)greh + gre_len;
		if (is_bypass_dst_v6(&inner_ip6h->daddr)) {
			if (stats)
				stats->pass_non_tunnel++;
			return XDP_PASS;
		}

		if (stats)
			stats->rx_gre_ipv6_inner++;
	} else {
		/* Not IPv4 or IPv6 payload, pass to next program */
		if (stats)
			stats->pass_non_tunnel++;
		return XDP_PASS;
	}

	/* Total headers to remove: outer IP + GRE */
	decap_len = outer_ip_len + gre_len;

	return decapsulate(ctx, decap_len, inner_proto, stats);
}

/*
 * Handle IPIP encapsulated packets (IPv4-in-IPv4)
 *
 * IPIP packet structure:
 * [Ethernet][Outer IPv4][Inner IPv4][Payload]
 *
 * IPIP has no tunnel header - just IP-in-IP encapsulation.
 * Called AFTER whitelist and fragmentation checks have passed.
 *
 * @ctx: XDP context
 * @outer_iph: Pointer to outer IP header
 * @outer_ip_len: Outer IP header length in bytes
 * @data_end: Packet end pointer
 * @stats: Pre-fetched stats pointer (may be NULL)
 * @return: XDP action
 */
static __always_inline int handle_ipip(struct xdp_md *ctx, struct iphdr *outer_iph,
                                       int outer_ip_len, void *data_end,
                                       struct tun_decap_stats *stats)
{
	struct iphdr *inner_iph;

	if (stats)
		stats->rx_ipip++;

	/* Verify inner IP header exists */
	inner_iph = (void *)outer_iph + outer_ip_len;
	if (unlikely((void *)(inner_iph + 1) > data_end)) {
		if (stats)
			stats->drop_malformed++;
		return XDP_DROP;
	}

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
}

/*
 * Handle IPv6-in-IPv4 encapsulated packets (protocol 41)
 *
 * Packet structure:
 * [Ethernet][Outer IPv4][Inner IPv6][Payload]
 *
 * No tunnel header - just IPv6 directly encapsulated in IPv4.
 * Called AFTER whitelist and fragmentation checks have passed.
 *
 * @ctx: XDP context
 * @outer_iph: Pointer to outer IPv4 header
 * @outer_ip_len: Outer IP header length in bytes
 * @data_end: Packet end pointer
 * @stats: Pre-fetched stats pointer (may be NULL)
 * @return: XDP action
 */
static __always_inline int handle_ipv6_in_ipv4(struct xdp_md *ctx, struct iphdr *outer_iph,
                                               int outer_ip_len, void *data_end,
                                               struct tun_decap_stats *stats)
{
	struct ipv6hdr *inner_ip6h;

	if (stats)
		stats->rx_ipv6_in_ipv4++;

	/* Verify inner IPv6 header exists */
	inner_ip6h = (void *)outer_iph + outer_ip_len;
	if (unlikely((void *)(inner_ip6h + 1) > data_end)) {
		if (stats)
			stats->drop_malformed++;
		return XDP_DROP;
	}

	/* Validate inner IPv6 header version */
	if (unlikely(inner_ip6h->version != 6)) {
		if (stats)
			stats->drop_malformed++;
		return XDP_DROP;
	}

	/* Check bypass: skip decap for kernel tunnel traffic */
	if (is_bypass_dst_v6(&inner_ip6h->daddr)) {
		if (stats)
			stats->pass_non_tunnel++;
		return XDP_PASS;
	}

	if (stats)
		stats->rx_ipip_ipv6_inner++;

	/* Remove outer IPv4 header (no tunnel header) */
	return decapsulate(ctx, outer_ip_len, ETH_P_IPV6, stats);
}

/*
 * Handle GRE encapsulated packets with IPv6 outer header
 *
 * Packet structure:
 * [Ethernet][Outer IPv6][GRE Header][Inner IP][Payload]
 *
 * Called AFTER whitelist check has passed.
 *
 * @ctx: XDP context
 * @outer_ip6h: Pointer to outer IPv6 header
 * @data_end: Packet end pointer
 * @stats: Pre-fetched stats pointer (may be NULL)
 * @return: XDP action
 */
static __always_inline int handle_gre_ipv6(struct xdp_md *ctx, struct ipv6hdr *outer_ip6h,
                                           void *data_end, struct tun_decap_stats *stats)
{
	struct gre_base_hdr *greh;
	int gre_len;
	int decap_len;
	__u16 inner_proto;

	if (stats) {
		stats->rx_gre++;
		stats->rx_ipv6_outer++;
	}

	/* Parse GRE header (follows IPv6 header, which is fixed 40 bytes) */
	greh = (void *)(outer_ip6h + 1);
	if (unlikely((void *)(greh + 1) > data_end)) {
		if (stats)
			stats->drop_malformed++;
		return XDP_DROP;
	}

	/* Validate GRE header */
	if (unlikely(gre_validate_flags(greh->flags) < 0)) {
		if (stats)
			stats->drop_malformed++;
		return XDP_DROP;
	}

	/* Check inner protocol type */
	inner_proto = bpf_ntohs(greh->protocol);

	/* Only decapsulate IPv4 or IPv6 payloads */
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
		gre_len = gre_hdr_len(greh->flags);

		if (unlikely((void *)greh + gre_len + sizeof(struct ipv6hdr) > data_end)) {
			if (stats)
				stats->drop_malformed++;
			return XDP_DROP;
		}

		/* Check bypass: skip decap for kernel tunnel traffic */
		struct ipv6hdr *inner_ip6h = (void *)greh + gre_len;
		if (is_bypass_dst_v6(&inner_ip6h->daddr)) {
			if (stats)
				stats->pass_non_tunnel++;
			return XDP_PASS;
		}

		if (stats)
			stats->rx_gre_ipv6_inner++;
	} else {
		if (stats)
			stats->pass_non_tunnel++;
		return XDP_PASS;
	}

	/* Total headers to remove: IPv6 header (40 bytes) + GRE */
	decap_len = sizeof(struct ipv6hdr) + gre_len;

	return decapsulate(ctx, decap_len, inner_proto, stats);
}

/*
 * Handle IP-in-IPv6 encapsulated packets
 *
 * Packet structure:
 * [Ethernet][Outer IPv6][Inner IP][Payload]
 *
 * Called AFTER whitelist check has passed.
 *
 * @ctx: XDP context
 * @outer_ip6h: Pointer to outer IPv6 header
 * @next_hdr: IPv6 next header protocol
 * @data_end: Packet end pointer
 * @stats: Pre-fetched stats pointer (may be NULL)
 * @return: XDP action
 */
static __always_inline int handle_ipip_ipv6(struct xdp_md *ctx, struct ipv6hdr *outer_ip6h,
                                            __u8 next_hdr, void *data_end,
                                            struct tun_decap_stats *stats)
{
	void *inner;
	__u16 inner_proto;

	if (stats)
		stats->rx_ipv6_outer++;

	inner = (void *)(outer_ip6h + 1);

	/* Determine inner protocol based on IPv6 next header */
	if (next_hdr == IPPROTO_IPIP) {
		/* IPv4-in-IPv6 */
		struct iphdr *inner_iph = inner;

		if (stats)
			stats->rx_ipip++;

		if (unlikely((void *)(inner_iph + 1) > data_end)) {
			if (stats)
				stats->drop_malformed++;
			return XDP_DROP;
		}

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
	} else if (next_hdr == IPPROTO_IPV6) {
		/* IPv6-in-IPv6 */
		struct ipv6hdr *inner_ip6h = inner;

		if (stats) {
			stats->rx_ipv6_in_ipv6++;
			stats->rx_ipip_ipv6_inner++;
		}

		if (unlikely((void *)(inner_ip6h + 1) > data_end)) {
			if (stats)
				stats->drop_malformed++;
			return XDP_DROP;
		}

		if (unlikely(inner_ip6h->version != 6)) {
			if (stats)
				stats->drop_malformed++;
			return XDP_DROP;
		}

		/* Check bypass: skip decap for kernel tunnel traffic */
		if (is_bypass_dst_v6(&inner_ip6h->daddr)) {
			if (stats)
				stats->pass_non_tunnel++;
			return XDP_PASS;
		}

		inner_proto = ETH_P_IPV6;
	} else {
		/* Unsupported protocol */
		if (stats)
			stats->pass_non_tunnel++;
		return XDP_PASS;
	}

	/* Remove outer IPv6 header (40 bytes) */
	return decapsulate(ctx, sizeof(struct ipv6hdr), inner_proto, stats);
}

/*
 * Main XDP program entry point
 *
 * Packet flow:
 * 1. Check global config (direct memory load, no map lookup)
 * 2. Lookup stats ONCE (1 map lookup if stats enabled)
 * 3. Parse Ethernet + IP headers
 * 4. For tunnel protocols:
 *    a. Check fragments (once, not per-handler)
 *    b. Verify whitelist (once, not per-handler, 1 map lookup)
 *    c. Check protocol-specific disable flags
 * 5. Dispatch to protocol handler for decapsulation
 * 6. Return XDP_PASS to chain to next program
 */
SEC("xdp")
int xdp_tun_decap(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth;
	struct iphdr *iph;
	struct tun_decap_stats *stats = NULL;
	int ip_hdr_len;

	/* Check if processing is disabled (direct memory load, no helper call) */
	if (unlikely(cfg_global.disabled))
		return XDP_PASS;

#ifdef ENABLE_STATS
	/*
	 * Single stats lookup for the entire packet path.
	 * All subsequent counter updates are direct field increments
	 * with no additional map lookups.
	 * Returns NULL if stats are disabled via config.
	 */
	if (likely(!cfg_global.disable_stats))
		stats = get_stats();

	/* Update total packet counter */
	if (stats)
		stats->rx_total++;
#endif

	/* Parse Ethernet header */
	eth = data;
	if (unlikely((void *)(eth + 1) > data_end))
		return XDP_PASS;

	/* Check EtherType for IPv4 or IPv6 */
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		/* IPv4 outer header */

		/* Parse IPv4 header */
		iph = (void *)(eth + 1);
		if (unlikely((void *)(iph + 1) > data_end))
			return XDP_PASS;

		/* Calculate IP header length from IHL field */
		ip_hdr_len = iph->ihl * 4;

		/* Validate IP header length */
		if (unlikely(ip_hdr_len < (int)sizeof(*iph)))
			return XDP_PASS;

		/* Bounds check for full IP header */
		if (unlikely((void *)iph + ip_hdr_len > data_end))
			return XDP_PASS;

		/* Check for tunnel protocols */
		switch (iph->protocol) {
		case IPPROTO_GRE:
		case IPPROTO_IPIP:
		case IPPROTO_IPV6: {
			/*
			 * Common checks for all IPv4-outer tunnel protocols:
			 * 1. Fragment check (once, not per-handler)
			 * 2. Whitelist check (once, not per-handler)
			 *
			 * This deduplicates what was previously 3 separate
			 * frag checks and 3 separate whitelist lookups.
			 */
			if (unlikely(iph->frag_off & bpf_htons(0x3FFF))) {
				if (stats)
					stats->drop_fragmented++;
				return XDP_DROP;
			}

#ifdef ENABLE_WHITELIST
			if (unlikely(!is_whitelisted(iph->saddr))) {
				if (stats)
					stats->drop_not_whitelisted++;
				return XDP_DROP;
			}
#endif

			/* Dispatch to protocol-specific handler */
			if (iph->protocol == IPPROTO_GRE) {
				if (unlikely(cfg_global.disable_gre)) {
					if (stats)
						stats->pass_non_tunnel++;
					return XDP_PASS;
				}
				return handle_gre(ctx, iph, ip_hdr_len, data_end, stats);
			} else if (iph->protocol == IPPROTO_IPIP) {
				if (unlikely(cfg_global.disable_ipip)) {
					if (stats)
						stats->pass_non_tunnel++;
					return XDP_PASS;
				}
				return handle_ipip(ctx, iph, ip_hdr_len, data_end, stats);
			} else {
				/* IPPROTO_IPV6 (protocol 41) */
				if (unlikely(cfg_global.disable_ipip)) {
					if (stats)
						stats->pass_non_tunnel++;
					return XDP_PASS;
				}
				return handle_ipv6_in_ipv4(ctx, iph, ip_hdr_len, data_end, stats);
			}
		}

		default:
			/* Non-tunnel traffic, pass to next program in chain */
			if (stats)
				stats->pass_non_tunnel++;
			return XDP_PASS;
		}

	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		/* IPv6 outer header */
		struct ipv6hdr *ip6h;

		/* Parse IPv6 header */
		ip6h = (void *)(eth + 1);
		if (unlikely((void *)(ip6h + 1) > data_end))
			return XDP_PASS;

		/* Validate IPv6 version */
		if (unlikely(ip6h->version != 6))
			return XDP_PASS;

		/* Drop fragmented IPv6 packets - can't decapsulate without
		 * reassembly. Fragment extension header = next header 44. */
		if (unlikely(ip6h->nexthdr == IPPROTO_FRAGMENT)) {
			if (stats)
				stats->drop_fragmented++;
			return XDP_DROP;
		}

		/* Check for tunnel protocols in IPv6 next header */
		switch (ip6h->nexthdr) {
		case IPPROTO_GRE:
		case IPPROTO_IPIP:
		case IPPROTO_IPV6: {
			/*
			 * Common whitelist check for all IPv6-outer tunnels.
			 * Hoisted from individual handlers to avoid duplicate
			 * hash lookups when inlined.
			 */
#ifdef ENABLE_WHITELIST
			if (unlikely(!is_whitelisted_v6(&ip6h->saddr))) {
				if (stats)
					stats->drop_not_whitelisted++;
				return XDP_DROP;
			}
#endif

			if (ip6h->nexthdr == IPPROTO_GRE) {
				if (unlikely(cfg_global.disable_gre)) {
					if (stats)
						stats->pass_non_tunnel++;
					return XDP_PASS;
				}
				return handle_gre_ipv6(ctx, ip6h, data_end, stats);
			} else {
				/* IPPROTO_IPIP or IPPROTO_IPV6 */
				if (unlikely(cfg_global.disable_ipip)) {
					if (stats)
						stats->pass_non_tunnel++;
					return XDP_PASS;
				}
				return handle_ipip_ipv6(ctx, ip6h, ip6h->nexthdr, data_end, stats);
			}
		}

		default:
			/* Non-tunnel traffic, pass to next program in chain */
			if (stats)
				stats->pass_non_tunnel++;
			return XDP_PASS;
		}

	} else {
		/* Non-IP traffic, pass to next program */
		return XDP_PASS;
	}
}

char LICENSE[] SEC("license") = "GPL";
