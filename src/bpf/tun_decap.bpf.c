// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * tun_decap.bpf.c - XDP tunnel decapsulation program
 *
 * Decapsulates GRE (protocol 47) and IPIP (protocol 4) tunnel traffic.
 * Uses whitelist-based access control to filter tunnel sources.
 *
 * Features:
 * - libxdp multi-program support with XDP_RUN_CONFIG
 * - Per-CPU whitelist for lock-free lookups
 * - Per-CPU statistics counters (single-struct for minimal map lookups)
 * - CO-RE support for kernel portability
 *
 * Target: Linux kernel 5.17+
 */

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

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

/*
 * Per-CPU whitelist map for lock-free lookups (IPv4)
 *
 * Key: IPv4 address in network byte order
 * Value: Simple flag (struct whitelist_value)
 *
 * Using PERCPU_HASH for:
 * - O(1) lookup time
 * - True per-CPU isolation (no locks)
 * - Optimal for small, frequently accessed whitelists
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, WHITELIST_MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct whitelist_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} tun_decap_whitelist SEC(".maps");

/*
 * Per-CPU whitelist map for IPv6 addresses
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
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, WHITELIST_MAX_ENTRIES);
	__type(key, struct ipv6_addr);
	__type(value, struct whitelist_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} tun_decap_whitelist_v6 SEC(".maps");

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

/*
 * Runtime configuration map
 *
 * Allows userspace to enable/disable functionality
 * without reloading the program.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, CONFIG_MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct tun_decap_config);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} tun_decap_config SEC(".maps");

/*
 * Get runtime configuration (called once per packet)
 *
 * @return: Pointer to config or NULL if not found
 */
static __always_inline struct tun_decap_config *get_config(void)
{
	__u32 key = 0;
	return bpf_map_lookup_elem(&tun_decap_config, &key);
}

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

	/* Copy IPv6 address to our key structure
	 * struct in6_addr has union with __u32 s6_addr32[4]
	 * We access via __u32 array for efficient copy */
	key.addr[0] = ip6_addr->in6_u.u6_addr32[0];
	key.addr[1] = ip6_addr->in6_u.u6_addr32[1];
	key.addr[2] = ip6_addr->in6_u.u6_addr32[2];
	key.addr[3] = ip6_addr->in6_u.u6_addr32[3];

	val = bpf_map_lookup_elem(&tun_decap_whitelist_v6, &key);
	return val != NULL;
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
	if ((void *)(eth + 1) > data_end) {
		if (stats)
			stats->decap_failed++;
		return XDP_DROP;
	}

	/* Bounds check: verify new ETH position is within packet */
	new_eth = (void *)eth + decap_len;
	if ((void *)(new_eth + 1) > data_end) {
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
	if (ret < 0) {
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

	/* Check whitelist before processing */
	if (!is_whitelisted(outer_iph->saddr)) {
		if (stats)
			stats->drop_not_whitelisted++;
		return XDP_DROP;
	}

	/* Parse GRE header */
	greh = (void *)outer_iph + outer_ip_len;
	if ((void *)(greh + 1) > data_end) {
		if (stats)
			stats->drop_malformed++;
		return XDP_DROP;
	}

	/* Validate GRE header (version must be 0) */
	if (gre_validate_flags(greh->flags) < 0) {
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
		if ((void *)greh + gre_len + sizeof(struct iphdr) > data_end) {
			if (stats)
				stats->drop_malformed++;
			return XDP_DROP;
		}
	} else if (inner_proto == ETH_P_IPV6) {
		/* IPv6 inner packet */
		gre_len = gre_hdr_len(greh->flags);

		/* Verify inner IPv6 header exists */
		if ((void *)greh + gre_len + sizeof(struct ipv6hdr) > data_end) {
			if (stats)
				stats->drop_malformed++;
			return XDP_DROP;
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

	/* Check whitelist before processing */
	if (!is_whitelisted(outer_iph->saddr)) {
		if (stats)
			stats->drop_not_whitelisted++;
		return XDP_DROP;
	}

	/* Verify inner IP header exists */
	inner_iph = (void *)outer_iph + outer_ip_len;
	if ((void *)(inner_iph + 1) > data_end) {
		if (stats)
			stats->drop_malformed++;
		return XDP_DROP;
	}

	/* Validate inner IPv4 header */
	if (inner_iph->version != 4 || inner_iph->ihl < 5) {
		if (stats)
			stats->drop_malformed++;
		return XDP_DROP;
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

	/* Check whitelist before processing */
	if (!is_whitelisted(outer_iph->saddr)) {
		if (stats)
			stats->drop_not_whitelisted++;
		return XDP_DROP;
	}

	/* Verify inner IPv6 header exists */
	inner_ip6h = (void *)outer_iph + outer_ip_len;
	if ((void *)(inner_ip6h + 1) > data_end) {
		if (stats)
			stats->drop_malformed++;
		return XDP_DROP;
	}

	/* Validate inner IPv6 header version */
	if (inner_ip6h->version != 6) {
		if (stats)
			stats->drop_malformed++;
		return XDP_DROP;
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

	/* Check IPv6 whitelist before processing */
	if (!is_whitelisted_v6(&outer_ip6h->saddr)) {
		if (stats)
			stats->drop_not_whitelisted++;
		return XDP_DROP;
	}

	/* Parse GRE header (follows IPv6 header, which is fixed 40 bytes) */
	greh = (void *)(outer_ip6h + 1);
	if ((void *)(greh + 1) > data_end) {
		if (stats)
			stats->drop_malformed++;
		return XDP_DROP;
	}

	/* Validate GRE header */
	if (gre_validate_flags(greh->flags) < 0) {
		if (stats)
			stats->drop_malformed++;
		return XDP_DROP;
	}

	/* Check inner protocol type */
	inner_proto = bpf_ntohs(greh->protocol);

	/* Only decapsulate IPv4 or IPv6 payloads */
	if (inner_proto == ETH_P_IP) {
		gre_len = gre_hdr_len(greh->flags);

		if ((void *)greh + gre_len + sizeof(struct iphdr) > data_end) {
			if (stats)
				stats->drop_malformed++;
			return XDP_DROP;
		}
	} else if (inner_proto == ETH_P_IPV6) {
		gre_len = gre_hdr_len(greh->flags);

		if ((void *)greh + gre_len + sizeof(struct ipv6hdr) > data_end) {
			if (stats)
				stats->drop_malformed++;
			return XDP_DROP;
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

	/* Check IPv6 whitelist before processing */
	if (!is_whitelisted_v6(&outer_ip6h->saddr)) {
		if (stats)
			stats->drop_not_whitelisted++;
		return XDP_DROP;
	}

	inner = (void *)(outer_ip6h + 1);

	/* Determine inner protocol based on IPv6 next header */
	if (next_hdr == IPPROTO_IPIP) {
		/* IPv4-in-IPv6 */
		struct iphdr *inner_iph = inner;

		if (stats)
			stats->rx_ipip++;

		if ((void *)(inner_iph + 1) > data_end) {
			if (stats)
				stats->drop_malformed++;
			return XDP_DROP;
		}

		if (inner_iph->version != 4 || inner_iph->ihl < 5) {
			if (stats)
				stats->drop_malformed++;
			return XDP_DROP;
		}

		inner_proto = ETH_P_IP;
	} else if (next_hdr == IPPROTO_IPV6) {
		/* IPv6-in-IPv6 */
		struct ipv6hdr *inner_ip6h = inner;

		if (stats) {
			stats->rx_ipv6_in_ipv6++;
			stats->rx_ipip_ipv6_inner++;
		}

		if ((void *)(inner_ip6h + 1) > data_end) {
			if (stats)
				stats->drop_malformed++;
			return XDP_DROP;
		}

		if (inner_ip6h->version != 6) {
			if (stats)
				stats->drop_malformed++;
			return XDP_DROP;
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
 * 1. Lookup config and stats ONCE at the top (2 map lookups total)
 * 2. Parse Ethernet header
 * 3. Parse IP header (IPv4 or IPv6)
 * 4. Check for tunnel protocols
 *    - IPv4: GRE (47), IPIP (4), IPv6-in-IPv4 (41)
 *    - IPv6: GRE (47), IPv4-in-IPv6 (4), IPv6-in-IPv6 (41)
 * 5. For tunnels: verify whitelist, decapsulate
 * 6. Return XDP_PASS to chain to next program
 */
SEC("xdp")
int xdp_tun_decap(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth;
	struct iphdr *iph;
	struct tun_decap_config *cfg;
	struct tun_decap_stats *stats;
	int ip_hdr_len;

	/*
	 * Single config lookup for the entire packet path.
	 * Previously this was called once here + once per update_stat().
	 */
	cfg = get_config();

	/* Check if processing is disabled */
	if (cfg && cfg->disabled)
		return XDP_PASS;

	/*
	 * Single stats lookup for the entire packet path.
	 * All subsequent counter updates are direct field increments
	 * with no additional map lookups.
	 * Returns NULL if stats are disabled via config.
	 */
	stats = NULL;
	if (!cfg || !cfg->disable_stats)
		stats = get_stats();

	/* Update total packet counter */
	if (stats)
		stats->rx_total++;

	/* Parse Ethernet header */
	eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	/* Check EtherType for IPv4 or IPv6 */
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		/* IPv4 outer header */

		/* Parse IPv4 header */
		iph = (void *)(eth + 1);
		if ((void *)(iph + 1) > data_end)
			return XDP_PASS;

		/* Calculate IP header length from IHL field */
		ip_hdr_len = iph->ihl * 4;

		/* Validate IP header length */
		if (ip_hdr_len < (int)sizeof(*iph))
			return XDP_PASS;

		/* Bounds check for full IP header */
		if ((void *)iph + ip_hdr_len > data_end)
			return XDP_PASS;

		/* Check for tunnel protocols */
		switch (iph->protocol) {
		case IPPROTO_GRE:
			/* Check if GRE processing is disabled */
			if (cfg && cfg->disable_gre) {
				if (stats)
					stats->pass_non_tunnel++;
				return XDP_PASS;
			}
			/* Drop fragmented tunnel packets - can't decapsulate
			 * without reassembly. Mask 0x3FFF covers MF flag and
			 * fragment offset. */
			if (iph->frag_off & bpf_htons(0x3FFF)) {
				if (stats)
					stats->drop_fragmented++;
				return XDP_DROP;
			}
			return handle_gre(ctx, iph, ip_hdr_len, data_end, stats);

		case IPPROTO_IPIP:
			/* Check if IPIP processing is disabled */
			if (cfg && cfg->disable_ipip) {
				if (stats)
					stats->pass_non_tunnel++;
				return XDP_PASS;
			}
			if (iph->frag_off & bpf_htons(0x3FFF)) {
				if (stats)
					stats->drop_fragmented++;
				return XDP_DROP;
			}
			return handle_ipip(ctx, iph, ip_hdr_len, data_end, stats);

		case IPPROTO_IPV6:
			/* IPv6-in-IPv4 (protocol 41) */
			/* Check if IPIP processing is disabled (covers IPv6-in-IPv4) */
			if (cfg && cfg->disable_ipip) {
				if (stats)
					stats->pass_non_tunnel++;
				return XDP_PASS;
			}
			if (iph->frag_off & bpf_htons(0x3FFF)) {
				if (stats)
					stats->drop_fragmented++;
				return XDP_DROP;
			}
			return handle_ipv6_in_ipv4(ctx, iph, ip_hdr_len, data_end, stats);

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
		if ((void *)(ip6h + 1) > data_end)
			return XDP_PASS;

		/* Validate IPv6 version */
		if (ip6h->version != 6)
			return XDP_PASS;

		/* Drop fragmented IPv6 packets - can't decapsulate without
		 * reassembly. Fragment extension header = next header 44. */
		if (ip6h->nexthdr == IPPROTO_FRAGMENT) {
			if (stats)
				stats->drop_fragmented++;
			return XDP_DROP;
		}

		/* Check for tunnel protocols in IPv6 next header */
		switch (ip6h->nexthdr) {
		case IPPROTO_GRE:
			/* Check if GRE processing is disabled */
			if (cfg && cfg->disable_gre) {
				if (stats)
					stats->pass_non_tunnel++;
				return XDP_PASS;
			}
			return handle_gre_ipv6(ctx, ip6h, data_end, stats);

		case IPPROTO_IPIP:
		case IPPROTO_IPV6:
			/* IPv4-in-IPv6 or IPv6-in-IPv6 */
			/* Check if IPIP processing is disabled */
			if (cfg && cfg->disable_ipip) {
				if (stats)
					stats->pass_non_tunnel++;
				return XDP_PASS;
			}
			return handle_ipip_ipv6(ctx, ip6h, ip6h->nexthdr, data_end, stats);

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
