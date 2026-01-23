/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * gre.h - GRE (Generic Routing Encapsulation) protocol definitions
 *
 * Implements RFC 2784 (GRE) and RFC 2890 (GRE Key and Sequence Number Extensions)
 *
 * GRE Header Format (RFC 2784):
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |C| |K|S| Reserved0       | Ver |         Protocol Type         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Checksum (optional)      |       Reserved1 (optional)    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Key (optional)                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Sequence Number (optional)                 |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * C (bit 0): Checksum Present
 * K (bit 2): Key Present
 * S (bit 3): Sequence Number Present
 * Ver (bits 13-15): Version (must be 0 for RFC 2784)
 */

#ifndef __GRE_H
#define __GRE_H

#include "vmlinux.h"
#include <bpf/bpf_endian.h>

/*
 * GRE base header structure
 * The kernel's vmlinux.h already defines gre_base_hdr, so we use that.
 * This comment documents the expected fields:
 *   __be16 flags;       - Flags and version
 *   __be16 protocol;    - Encapsulated protocol type (e.g., ETH_P_IP)
 */

/*
 * GRE flags bit definitions
 * These are in network byte order positions
 */
#define GRE_FLAG_CHECKSUM 0x8000 /* Bit 0: Checksum present */
#define GRE_FLAG_ROUTING  0x4000 /* Bit 1: Routing present (deprecated) */
#define GRE_FLAG_KEY      0x2000 /* Bit 2: Key present */
#define GRE_FLAG_SEQ      0x1000 /* Bit 3: Sequence number present */
#define GRE_FLAG_STRICT   0x0800 /* Bit 4: Strict source route (deprecated) */
#define GRE_FLAG_RECUR    0x0700 /* Bits 5-7: Recursion control (deprecated) */
#define GRE_FLAG_ACK      0x0080 /* Bit 8: Acknowledgment present (PPTP) */
#define GRE_FLAG_RESERVED 0x0078 /* Bits 9-12: Reserved */
#define GRE_FLAG_VERSION  0x0007 /* Bits 13-15: Version field */

/*
 * GRE version numbers
 */
#define GRE_VERSION_0 0 /* RFC 2784 standard GRE */
#define GRE_VERSION_1 1 /* PPTP enhanced GRE (RFC 2637) */

/*
 * GRE optional header components
 */
struct gre_checksum_hdr {
	__be16 checksum;  /* GRE checksum */
	__be16 reserved1; /* Must be zero */
} __attribute__((packed));

struct gre_key_hdr {
	__be32 key; /* 32-bit key for tunnel identification */
} __attribute__((packed));

struct gre_seq_hdr {
	__be32 seq; /* Sequence number */
} __attribute__((packed));

/*
 * Calculate GRE header length based on flags
 *
 * The GRE header has a variable length:
 * - Base header: 4 bytes (always present)
 * - Checksum + Reserved1: 4 bytes (if C bit set)
 * - Key: 4 bytes (if K bit set)
 * - Sequence: 4 bytes (if S bit set)
 *
 * @flags: GRE flags in network byte order
 * @return: Total GRE header length in bytes
 */
static __always_inline int gre_hdr_len(__be16 flags)
{
	int len = sizeof(struct gre_base_hdr); /* Base: 4 bytes */
	__u16 flags_host = bpf_ntohs(flags);

	/* Checksum field includes reserved1 field (4 bytes total) */
	if (flags_host & GRE_FLAG_CHECKSUM)
		len += sizeof(struct gre_checksum_hdr);

	/* Key field: 4 bytes */
	if (flags_host & GRE_FLAG_KEY)
		len += sizeof(struct gre_key_hdr);

	/* Sequence number: 4 bytes */
	if (flags_host & GRE_FLAG_SEQ)
		len += sizeof(struct gre_seq_hdr);

	return len;
}

/*
 * Validate GRE header flags
 *
 * Checks for RFC 2784 compliance:
 * - Version must be 0
 * - Deprecated fields should not be set
 *
 * @flags: GRE flags in network byte order
 * @return: 0 if valid, -1 if invalid
 */
static __always_inline int gre_validate_flags(__be16 flags)
{
	__u16 flags_host = bpf_ntohs(flags);

	/* Version must be 0 for standard GRE */
	if ((flags_host & GRE_FLAG_VERSION) != GRE_VERSION_0)
		return -1;

	/* Routing bit is deprecated and should not be set */
	if (flags_host & GRE_FLAG_ROUTING)
		return -1;

	return 0;
}

/*
 * Check if GRE packet has checksum
 *
 * @flags: GRE flags in network byte order
 * @return: 1 if checksum present, 0 otherwise
 */
static __always_inline int gre_has_checksum(__be16 flags)
{
	return !!(bpf_ntohs(flags) & GRE_FLAG_CHECKSUM);
}

/*
 * Check if GRE packet has key
 *
 * @flags: GRE flags in network byte order
 * @return: 1 if key present, 0 otherwise
 */
static __always_inline int gre_has_key(__be16 flags)
{
	return !!(bpf_ntohs(flags) & GRE_FLAG_KEY);
}

/*
 * Check if GRE packet has sequence number
 *
 * @flags: GRE flags in network byte order
 * @return: 1 if sequence number present, 0 otherwise
 */
static __always_inline int gre_has_seq(__be16 flags)
{
	return !!(bpf_ntohs(flags) & GRE_FLAG_SEQ);
}

/*
 * Get GRE key value from packet
 *
 * Must only be called after verifying gre_has_key() returns true
 * and after performing bounds checking.
 *
 * @greh: Pointer to GRE base header
 * @return: Key value in network byte order
 */
static __always_inline __be32 gre_get_key(struct gre_base_hdr *greh)
{
	void *key_pos = (void *)(greh + 1);

	/* Skip checksum field if present */
	if (gre_has_checksum(greh->flags))
		key_pos += sizeof(struct gre_checksum_hdr);

	return *(__be32 *)key_pos;
}

#endif /* __GRE_H */
