/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * tun_decap.h - Shared definitions for XDP tunnel decapsulation
 *
 * This header is shared between BPF programs and userspace tools.
 * It defines the map key/value structures and statistics indices.
 */

#ifndef __TUN_DECAP_H
#define __TUN_DECAP_H

/* Use kernel types in BPF context, standard types in userspace */
#ifdef __BPF__
#include "vmlinux.h"
#else
/* In userspace, use linux/types.h if available, otherwise define types */
#ifndef __KERNEL__
#include <linux/types.h>
#endif
#endif

/*
 * Statistics structure - all counters in a single map entry
 *
 * Using a single struct instead of per-counter array entries
 * reduces BPF map lookups from N (one per stat update) to 1.
 * Each stat update becomes a direct memory write instead of
 * a bpf_map_lookup_elem() call (~15-50ns savings per lookup).
 */
struct tun_decap_stats {
	__u64 rx_total;           /* Total packets received */
	__u64 rx_gre;             /* GRE packets received */
	__u64 rx_ipip;            /* IPIP packets received */
	__u64 rx_ipv6_in_ipv4;    /* IPv6-in-IPv4 packets received */
	__u64 rx_ipv6_outer;      /* IPv6 outer header packets received */
	__u64 rx_gre_ipv6_inner;  /* GRE with IPv6 inner packet */
	__u64 rx_ipip_ipv6_inner; /* IPIP with IPv6 inner packet */
	__u64 rx_ipv6_in_ipv6;    /* IPv6-in-IPv6 tunnel packets received */
	__u64 decap_success;      /* Successfully decapsulated packets */
	__u64 decap_failed;       /* Decapsulation failures (adjust_head error) */
	__u64 drop_not_whitelisted; /* Dropped: source IP not in whitelist */
	__u64 drop_malformed;     /* Dropped: malformed tunnel packet */
	__u64 drop_fragmented;    /* Dropped: fragmented outer packet */
	__u64 pass_non_tunnel;    /* Passed: non-tunnel traffic to next prog */
};

/* Number of counters in tun_decap_stats (for userspace iteration) */
#define STAT_NUM_COUNTERS 14

/*
 * Whitelist value structure
 * Simple flag indicating IP is whitelisted
 * Using __u8 to minimize memory footprint in per-CPU map
 */
struct whitelist_value {
	__u8 allowed; /* 1 = whitelisted, 0 = not (for future use) */
};

/*
 * IPv6 address structure for whitelist key
 * 16 bytes to match struct in6_addr
 */
struct ipv6_addr {
	__u32 addr[4]; /* IPv6 address as 4x 32-bit words */
};

/*
 * Map names for pinning
 * Maps are pinned to /sys/fs/bpf/<name> for userspace access
 */
#define MAP_PIN_PATH_WHITELIST    "/sys/fs/bpf/tun_decap_whitelist"
#define MAP_PIN_PATH_WHITELIST_V6 "/sys/fs/bpf/tun_decap_whitelist_v6"
#define MAP_PIN_PATH_STATS        "/sys/fs/bpf/tun_decap_stats"
/*
 * Configuration structure for runtime control
 *
 * NOTE: Fields are "disable" flags so that default zero-initialization
 * means processing is ENABLED. Set to 1 to disable.
 */
struct tun_decap_config {
	__u8 disabled;      /* Master disable switch (0=enabled, 1=disabled) */
	__u8 disable_gre;   /* Disable GRE processing (0=enabled, 1=disabled) */
	__u8 disable_ipip;  /* Disable IPIP processing (0=enabled, 1=disabled) */
	__u8 disable_stats; /* Disable statistics collection (0=enabled, 1=disabled) */
	__be32 bypass_dst_net;  /* Inner dst subnet to skip decap (0=disabled) */
	__be32 bypass_dst_mask; /* Subnet mask for bypass (network byte order) */
};

/*
 * Program metadata
 */
#define PROG_NAME    "xdp_tun_decap"
#define PROG_VERSION "1.0.0"

/*
 * Map size limits
 */
#define WHITELIST_MAX_ENTRIES 1024

/*
 * XDP dispatcher priority
 * Lower value = runs earlier in the chain
 * We run early to decapsulate before other programs see the packet
 */
#define XDP_PRIORITY 10

/*
 * Protocol numbers
 */
#ifndef IPPROTO_IPIP
#define IPPROTO_IPIP 4
#endif

#ifndef IPPROTO_IPV6
#define IPPROTO_IPV6 41
#endif

#ifndef IPPROTO_GRE
#define IPPROTO_GRE 47
#endif

#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT 44
#endif

/*
 * Ethernet protocol types
 */
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

/*
 * Helper structures for statistics names (userspace)
 */
#ifndef __BPF__

struct stat_field_info {
	const char *name;
	const char *description;
	size_t offset; /* offset within tun_decap_stats struct */
};

#define STAT_FIELD(field, desc) \
	{ #field, desc, __builtin_offsetof(struct tun_decap_stats, field) }

static const struct stat_field_info stat_fields[] __attribute__((unused)) = {
    STAT_FIELD(rx_total, "Total packets received"),
    STAT_FIELD(rx_gre, "GRE tunnel packets received"),
    STAT_FIELD(rx_ipip, "IPIP tunnel packets received"),
    STAT_FIELD(rx_ipv6_in_ipv4, "IPv6-in-IPv4 tunnel packets received"),
    STAT_FIELD(rx_ipv6_outer, "Packets with IPv6 outer header"),
    STAT_FIELD(rx_gre_ipv6_inner, "GRE with IPv6 inner packet"),
    STAT_FIELD(rx_ipip_ipv6_inner, "IPIP with IPv6 inner packet"),
    STAT_FIELD(rx_ipv6_in_ipv6, "IPv6-in-IPv6 tunnel packets received"),
    STAT_FIELD(decap_success, "Packets successfully decapsulated"),
    STAT_FIELD(decap_failed, "Decapsulation failures"),
    STAT_FIELD(drop_not_whitelisted, "Dropped (source not whitelisted)"),
    STAT_FIELD(drop_malformed, "Dropped (malformed packet)"),
    STAT_FIELD(drop_fragmented, "Dropped (fragmented outer packet)"),
    STAT_FIELD(pass_non_tunnel, "Non-tunnel traffic passed"),
};

#endif /* __BPF__ */

#endif /* __TUN_DECAP_H */
