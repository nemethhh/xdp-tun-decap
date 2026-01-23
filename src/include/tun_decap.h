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
 * Statistics counter indices
 * Used with the per-CPU stats array map
 */
enum stat_idx {
	STAT_RX_TOTAL = 0,         /* Total packets received */
	STAT_RX_GRE,               /* GRE packets received */
	STAT_RX_IPIP,              /* IPIP packets received */
	STAT_RX_IPV6_IN_IPV4,      /* IPv6-in-IPv4 packets received */
	STAT_RX_IPV6_OUTER,        /* IPv6 outer header packets received */
	STAT_RX_GRE_IPV6_INNER,    /* GRE with IPv6 inner packet */
	STAT_RX_IPIP_IPV6_INNER,   /* IPIP with IPv6 inner packet */
	STAT_DECAP_SUCCESS,        /* Successfully decapsulated packets */
	STAT_DECAP_FAILED,         /* Decapsulation failures (adjust_head error) */
	STAT_DROP_NOT_WHITELISTED, /* Dropped: source IP not in whitelist */
	STAT_DROP_MALFORMED,       /* Dropped: malformed tunnel packet */
	STAT_PASS_NON_TUNNEL,      /* Passed: non-tunnel traffic to next prog */
	STAT_MAX                   /* Sentinel - must be last */
};

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
#define MAP_PIN_PATH_CONFIG       "/sys/fs/bpf/tun_decap_config"

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
#define CONFIG_MAX_ENTRIES    1

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
 * Helper macros for statistics names (userspace)
 */
#ifndef __BPF__
static const char *stat_names[] = {
    [STAT_RX_TOTAL] = "rx_total",
    [STAT_RX_GRE] = "rx_gre",
    [STAT_RX_IPIP] = "rx_ipip",
    [STAT_RX_IPV6_IN_IPV4] = "rx_ipv6_in_ipv4",
    [STAT_RX_IPV6_OUTER] = "rx_ipv6_outer",
    [STAT_RX_GRE_IPV6_INNER] = "rx_gre_ipv6_inner",
    [STAT_RX_IPIP_IPV6_INNER] = "rx_ipip_ipv6_inner",
    [STAT_DECAP_SUCCESS] = "decap_success",
    [STAT_DECAP_FAILED] = "decap_failed",
    [STAT_DROP_NOT_WHITELISTED] = "drop_not_whitelisted",
    [STAT_DROP_MALFORMED] = "drop_malformed",
    [STAT_PASS_NON_TUNNEL] = "pass_non_tunnel",
};

static const char *stat_descriptions[] = {
    [STAT_RX_TOTAL] = "Total packets received",
    [STAT_RX_GRE] = "GRE tunnel packets received",
    [STAT_RX_IPIP] = "IPIP tunnel packets received",
    [STAT_RX_IPV6_IN_IPV4] = "IPv6-in-IPv4 tunnel packets received",
    [STAT_RX_IPV6_OUTER] = "Packets with IPv6 outer header",
    [STAT_RX_GRE_IPV6_INNER] = "GRE with IPv6 inner packet",
    [STAT_RX_IPIP_IPV6_INNER] = "IPIP with IPv6 inner packet",
    [STAT_DECAP_SUCCESS] = "Packets successfully decapsulated",
    [STAT_DECAP_FAILED] = "Decapsulation failures",
    [STAT_DROP_NOT_WHITELISTED] = "Dropped (source not whitelisted)",
    [STAT_DROP_MALFORMED] = "Dropped (malformed packet)",
    [STAT_PASS_NON_TUNNEL] = "Non-tunnel traffic passed",
};
#endif /* __BPF__ */

#endif /* __TUN_DECAP_H */
