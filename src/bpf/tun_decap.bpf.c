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
 * - Per-CPU statistics counters
 * - CO-RE support for kernel portability
 *
 * Target: Linux kernel 5.17+
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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
    __u32 prog_id;              /* Unused in .o file, set by loader */
    __u32 priority;
    __u32 flags;                /* Reserved */
    __u32 chain_call_actions;   /* Bitmask: bit N = chain on action N */
};
#define XDP_RUN_CONFIG(name) \
    struct xdp_run_config _xdp_run_config_##name SEC(".xdp_run_config") =
#endif

#include "tun_decap.h"
#include "gre.h"
#include "parsing.h"

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
XDP_RUN_CONFIG(xdp_tun_decap) {
    .prog_id = 0,
    .priority = XDP_PRIORITY,  /* 10 */
    .flags = 0,
    .chain_call_actions = (1U << XDP_PASS),  /* 0x04 - chain only on XDP_PASS */
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
 * Per-CPU whitelist map for lock-free lookups
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
 * Per-CPU statistics array
 *
 * Lock-free counters for tracking packet processing.
 * Each CPU maintains its own counters; userspace aggregates.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
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
 * Update statistics counter
 *
 * Per-CPU array requires no locking.
 */
static __always_inline void update_stat(__u32 idx)
{
    __u64 *count = bpf_map_lookup_elem(&tun_decap_stats, &idx);
    if (count)
        (*count)++;
}

/*
 * Check if source IP is in whitelist
 *
 * @ip_addr: IPv4 address in network byte order
 * @return: 1 if whitelisted, 0 otherwise
 */
static __always_inline int is_whitelisted(__be32 ip_addr)
{
    __u32 key = ip_addr;  /* Network byte order */
    struct whitelist_value *val;

    val = bpf_map_lookup_elem(&tun_decap_whitelist, &key);
    return val != NULL;
}

/*
 * Get runtime configuration
 *
 * @return: Pointer to config or NULL if not found
 */
static __always_inline struct tun_decap_config *get_config(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&tun_decap_config, &key);
}

/*
 * Perform decapsulation by removing outer headers
 *
 * This function:
 * 1. Saves the original Ethernet header
 * 2. Calls bpf_xdp_adjust_head() to remove tunnel headers
 * 3. Restores the Ethernet header at the new position
 *
 * @ctx: XDP context
 * @decap_len: Number of bytes to remove (outer IP + tunnel header)
 * @return: XDP action (XDP_PASS on success, XDP_DROP on failure)
 */
static __always_inline int decapsulate(struct xdp_md *ctx, int decap_len)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct ethhdr eth_copy;
    int ret;

    /* Bounds check for Ethernet header */
    if ((void *)(eth + 1) > data_end) {
        update_stat(STAT_DECAP_FAILED);
        return XDP_DROP;
    }

    /* Save original Ethernet header to stack */
    __builtin_memcpy(&eth_copy, eth, sizeof(eth_copy));

    /*
     * Adjust head to remove outer IP + tunnel headers
     * Positive delta = shrink headroom (remove bytes from front)
     */
    ret = bpf_xdp_adjust_head(ctx, decap_len);
    if (ret < 0) {
        update_stat(STAT_DECAP_FAILED);
        return XDP_DROP;
    }

    /*
     * CRITICAL: After bpf_xdp_adjust_head(), all previous pointers
     * are invalidated. We must re-fetch data and data_end.
     */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    /* Get new Ethernet header position */
    eth = data;
    if ((void *)(eth + 1) > data_end) {
        update_stat(STAT_DECAP_FAILED);
        return XDP_DROP;
    }

    /* Restore Ethernet header at new position */
    __builtin_memcpy(eth, &eth_copy, sizeof(*eth));

    /* Update EtherType to reflect inner IPv4 packet */
    eth->h_proto = bpf_htons(ETH_P_IP);

    update_stat(STAT_DECAP_SUCCESS);
    return XDP_PASS;
}

/*
 * Handle GRE encapsulated packets
 *
 * GRE packet structure:
 * [Ethernet][Outer IP][GRE Header][Inner IP][Payload]
 *
 * @ctx: XDP context
 * @outer_iph: Pointer to outer IP header
 * @outer_ip_len: Outer IP header length in bytes
 * @data_end: Packet end pointer
 * @return: XDP action
 */
static __always_inline int handle_gre(struct xdp_md *ctx,
                                      struct iphdr *outer_iph,
                                      int outer_ip_len,
                                      void *data_end)
{
    struct gre_base_hdr *greh;
    int gre_len;
    int decap_len;

    update_stat(STAT_RX_GRE);

    /* Check whitelist before processing */
    if (!is_whitelisted(outer_iph->saddr)) {
        update_stat(STAT_DROP_NOT_WHITELISTED);
        return XDP_DROP;
    }

    /* Parse GRE header */
    greh = (void *)outer_iph + outer_ip_len;
    if ((void *)(greh + 1) > data_end) {
        update_stat(STAT_DROP_MALFORMED);
        return XDP_DROP;
    }

    /* Validate GRE header (version must be 0) */
    if (gre_validate_flags(greh->flags) < 0) {
        update_stat(STAT_DROP_MALFORMED);
        return XDP_DROP;
    }

    /* Only decapsulate IPv4-in-GRE */
    if (greh->protocol != bpf_htons(ETH_P_IP)) {
        /* Not IPv4 payload, pass to next program */
        update_stat(STAT_PASS_NON_TUNNEL);
        return XDP_PASS;
    }

    /* Calculate GRE header length (variable based on flags) */
    gre_len = gre_hdr_len(greh->flags);

    /* Verify inner IP header exists */
    if ((void *)greh + gre_len + sizeof(struct iphdr) > data_end) {
        update_stat(STAT_DROP_MALFORMED);
        return XDP_DROP;
    }

    /* Total headers to remove: outer IP + GRE */
    decap_len = outer_ip_len + gre_len;

    return decapsulate(ctx, decap_len);
}

/*
 * Handle IPIP encapsulated packets
 *
 * IPIP packet structure:
 * [Ethernet][Outer IP][Inner IP][Payload]
 *
 * IPIP has no tunnel header - just IP-in-IP encapsulation.
 *
 * @ctx: XDP context
 * @outer_iph: Pointer to outer IP header
 * @outer_ip_len: Outer IP header length in bytes
 * @data_end: Packet end pointer
 * @return: XDP action
 */
static __always_inline int handle_ipip(struct xdp_md *ctx,
                                       struct iphdr *outer_iph,
                                       int outer_ip_len,
                                       void *data_end)
{
    struct iphdr *inner_iph;

    update_stat(STAT_RX_IPIP);

    /* Check whitelist before processing */
    if (!is_whitelisted(outer_iph->saddr)) {
        update_stat(STAT_DROP_NOT_WHITELISTED);
        return XDP_DROP;
    }

    /* Verify inner IP header exists */
    inner_iph = (void *)outer_iph + outer_ip_len;
    if ((void *)(inner_iph + 1) > data_end) {
        update_stat(STAT_DROP_MALFORMED);
        return XDP_DROP;
    }

    /* Validate inner IP header looks reasonable */
    if (inner_iph->ihl < 5 || inner_iph->version != 4) {
        update_stat(STAT_DROP_MALFORMED);
        return XDP_DROP;
    }

    /* IPIP: only remove outer IP header (no tunnel header) */
    return decapsulate(ctx, outer_ip_len);
}

/*
 * Main XDP program entry point
 *
 * Packet flow:
 * 1. Parse Ethernet header
 * 2. Parse IPv4 header (skip non-IPv4)
 * 3. Check for tunnel protocols (GRE=47, IPIP=4)
 * 4. For tunnels: verify whitelist, decapsulate
 * 5. Return XDP_PASS to chain to next program
 */
SEC("xdp")
int xdp_tun_decap(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tun_decap_config *cfg;
    int ip_hdr_len;

    /* Update total packet counter */
    update_stat(STAT_RX_TOTAL);

    /* Check if processing is enabled */
    cfg = get_config();
    if (cfg && !cfg->enabled) {
        /* Processing disabled, pass to next program */
        return XDP_PASS;
    }

    /* Parse Ethernet header */
    eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only process IPv4 packets */
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        /* Non-IPv4, let subsequent programs handle */
        return XDP_PASS;
    }

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
        /* Check if GRE processing is enabled */
        if (cfg && !cfg->allow_gre) {
            update_stat(STAT_PASS_NON_TUNNEL);
            return XDP_PASS;
        }
        return handle_gre(ctx, iph, ip_hdr_len, data_end);

    case IPPROTO_IPIP:
        /* Check if IPIP processing is enabled */
        if (cfg && !cfg->allow_ipip) {
            update_stat(STAT_PASS_NON_TUNNEL);
            return XDP_PASS;
        }
        return handle_ipip(ctx, iph, ip_hdr_len, data_end);

    default:
        /* Non-tunnel traffic, pass to next program in chain */
        update_stat(STAT_PASS_NON_TUNNEL);
        return XDP_PASS;
    }
}

char LICENSE[] SEC("license") = "GPL";
