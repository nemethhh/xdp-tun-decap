/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * parsing.h - Packet parsing helpers for XDP programs
 *
 * These helpers provide safe, verifier-friendly packet access patterns.
 * All functions use explicit bounds checking required by the BPF verifier.
 */

#ifndef __PARSING_H
#define __PARSING_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
 * Header cursor for tracking parsing position
 * This pattern simplifies multi-layer packet parsing
 */
struct hdr_cursor {
    void *pos;      /* Current parsing position */
    void *end;      /* Packet end (data_end) */
};

/*
 * Initialize header cursor from XDP context
 *
 * @ctx: XDP context
 * @cursor: Cursor to initialize
 */
static __always_inline void cursor_init(struct xdp_md *ctx, struct hdr_cursor *cursor)
{
    cursor->pos = (void *)(long)ctx->data;
    cursor->end = (void *)(long)ctx->data_end;
}

/*
 * Check if there's enough space to read N bytes
 *
 * @cursor: Header cursor
 * @len: Number of bytes to check
 * @return: 1 if space available, 0 otherwise
 */
static __always_inline int cursor_check(struct hdr_cursor *cursor, int len)
{
    return cursor->pos + len <= cursor->end;
}

/*
 * Advance cursor position
 *
 * @cursor: Header cursor
 * @len: Number of bytes to advance
 */
static __always_inline void cursor_advance(struct hdr_cursor *cursor, int len)
{
    cursor->pos += len;
}

/*
 * Parse Ethernet header
 *
 * Validates bounds and advances cursor past Ethernet header.
 * Handles VLAN tags (802.1Q) if present.
 *
 * @cursor: Header cursor (updated on success)
 * @eth: Pointer to store Ethernet header pointer
 * @return: Protocol type (ETH_P_*) or -1 on error
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *cursor,
                                        struct ethhdr **eth)
{
    struct ethhdr *hdr = cursor->pos;

    /* Bounds check for Ethernet header */
    if ((void *)(hdr + 1) > cursor->end)
        return -1;

    *eth = hdr;
    cursor_advance(cursor, sizeof(*hdr));

    return bpf_ntohs(hdr->h_proto);
}

/*
 * Parse IPv4 header
 *
 * Validates bounds, header length, and advances cursor.
 * Handles variable-length IP headers (IHL field).
 *
 * @cursor: Header cursor (updated on success)
 * @iph: Pointer to store IPv4 header pointer
 * @return: IP header length in bytes, or -1 on error
 */
static __always_inline int parse_iphdr(struct hdr_cursor *cursor,
                                       struct iphdr **iph)
{
    struct iphdr *hdr = cursor->pos;
    int hdr_len;

    /* Bounds check for minimum IP header */
    if ((void *)(hdr + 1) > cursor->end)
        return -1;

    /* Calculate actual IP header length from IHL field */
    hdr_len = hdr->ihl * 4;

    /* Validate header length (minimum 20 bytes) */
    if (hdr_len < (int)sizeof(*hdr))
        return -1;

    /* Bounds check for full IP header including options */
    if (cursor->pos + hdr_len > cursor->end)
        return -1;

    *iph = hdr;
    cursor_advance(cursor, hdr_len);

    return hdr_len;
}

/*
 * Parse IPv4 header without advancing cursor
 *
 * Useful when you need to examine the header but keep
 * the cursor at the IP header position.
 *
 * @cursor: Header cursor (not modified)
 * @iph: Pointer to store IPv4 header pointer
 * @return: IP header length in bytes, or -1 on error
 */
static __always_inline int peek_iphdr(struct hdr_cursor *cursor,
                                      struct iphdr **iph)
{
    struct iphdr *hdr = cursor->pos;
    int hdr_len;

    if ((void *)(hdr + 1) > cursor->end)
        return -1;

    hdr_len = hdr->ihl * 4;

    if (hdr_len < (int)sizeof(*hdr))
        return -1;

    if (cursor->pos + hdr_len > cursor->end)
        return -1;

    *iph = hdr;
    return hdr_len;
}

/*
 * Parse IPv6 header
 *
 * Validates bounds and advances cursor past IPv6 header.
 * IPv6 header is fixed 40 bytes (unlike IPv4 with variable IHL).
 * Extension headers are not handled here - they follow the main header.
 *
 * @cursor: Header cursor (updated on success)
 * @ip6h: Pointer to store IPv6 header pointer
 * @return: IPv6 header length (40) on success, or -1 on error
 */
static __always_inline int parse_ipv6hdr(struct hdr_cursor *cursor,
                                         struct ipv6hdr **ip6h)
{
    struct ipv6hdr *hdr = cursor->pos;

    /* Bounds check for IPv6 header (fixed 40 bytes) */
    if ((void *)(hdr + 1) > cursor->end)
        return -1;

    /* Validate IPv6 version field */
    if (hdr->version != 6)
        return -1;

    *ip6h = hdr;
    cursor_advance(cursor, sizeof(*hdr));

    return sizeof(*hdr);
}

/*
 * Parse IPv6 header without advancing cursor
 *
 * Useful when you need to examine the header but keep
 * the cursor at the IPv6 header position.
 *
 * @cursor: Header cursor (not modified)
 * @ip6h: Pointer to store IPv6 header pointer
 * @return: IPv6 header length (40) on success, or -1 on error
 */
static __always_inline int peek_ipv6hdr(struct hdr_cursor *cursor,
                                        struct ipv6hdr **ip6h)
{
    struct ipv6hdr *hdr = cursor->pos;

    /* Bounds check for IPv6 header */
    if ((void *)(hdr + 1) > cursor->end)
        return -1;

    /* Validate IPv6 version field */
    if (hdr->version != 6)
        return -1;

    *ip6h = hdr;
    return sizeof(*hdr);
}

/*
 * Check pointer bounds safely
 *
 * This is the core pattern required by the BPF verifier.
 * Always use this before dereferencing pointers.
 *
 * @ptr: Pointer to check
 * @size: Size of access in bytes
 * @end: Packet end pointer
 * @return: 1 if access is safe, 0 otherwise
 */
static __always_inline int ptr_is_valid(void *ptr, int size, void *end)
{
    return (ptr + size <= end);
}

/*
 * Get pointer at offset with bounds check
 *
 * Returns a typed pointer at the given offset from data start,
 * or NULL if the access would be out of bounds.
 *
 * @data: Packet data start
 * @data_end: Packet data end
 * @offset: Byte offset from data start
 * @size: Size of the type to access
 * @return: Pointer to data or NULL if out of bounds
 */
static __always_inline void *ptr_at(void *data, void *data_end,
                                    __u32 offset, __u32 size)
{
    void *ptr = data + offset;

    if (ptr + size > data_end)
        return NULL;

    return ptr;
}

/*
 * Calculate remaining packet length
 *
 * @cursor: Header cursor
 * @return: Bytes remaining from cursor position to end
 */
static __always_inline __u32 cursor_remaining(struct hdr_cursor *cursor)
{
    if (cursor->pos >= cursor->end)
        return 0;
    return cursor->end - cursor->pos;
}

/*
 * Reinitialize cursor after bpf_xdp_adjust_head()
 *
 * CRITICAL: After calling bpf_xdp_adjust_head(), all previous
 * pointers and bounds checks are invalidated. You must re-read
 * ctx->data and ctx->data_end and perform new bounds checks.
 *
 * @ctx: XDP context (with updated data/data_end)
 * @cursor: Cursor to reinitialize
 */
static __always_inline void cursor_reinit(struct xdp_md *ctx,
                                          struct hdr_cursor *cursor)
{
    cursor->pos = (void *)(long)ctx->data;
    cursor->end = (void *)(long)ctx->data_end;
}

#endif /* __PARSING_H */
