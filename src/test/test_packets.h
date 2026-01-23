/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * test_packets.h - Pre-crafted test packets for XDP unit testing
 *
 * These packets are used with BPF_PROG_TEST_RUN to verify
 * the tunnel decapsulation logic.
 *
 * Packet structures:
 * - GRE: [Eth 14][Outer IP 20][GRE 4+][Inner IP 20][TCP 20]
 * - IPIP: [Eth 14][Outer IP 20][Inner IP 20][TCP 20]
 * - Normal: [Eth 14][IP 20][TCP 20]
 */

#ifndef __TEST_PACKETS_H
#define __TEST_PACKETS_H

#include <stdint.h>

/*
 * Test IP addresses (in hex, network byte order)
 *
 * Whitelisted sources:
 *   10.0.0.1  = 0x0a000001
 *   10.0.0.2  = 0x0a000002
 *
 * Non-whitelisted source:
 *   11.0.0.1  = 0x0b000001
 *
 * Destinations:
 *   192.168.1.1 = 0xc0a80101
 *
 * Inner packet addresses:
 *   172.16.0.1 = 0xac100001
 *   172.16.0.2 = 0xac100002
 */

/*
 * GRE-encapsulated IPv4 packet from whitelisted source (10.0.0.1)
 *
 * Structure:
 * [Ethernet: 14 bytes]
 * [Outer IPv4: 20 bytes, proto=47 (GRE), src=10.0.0.1]
 * [GRE: 4 bytes, no options, proto=0x0800 (IPv4)]
 * [Inner IPv4: 20 bytes, proto=6 (TCP), src=172.16.0.1]
 * [TCP: 20 bytes]
 *
 * Total: 78 bytes
 * After decap: 54 bytes (outer IP + GRE removed = 24 bytes)
 */
static unsigned char pkt_gre_whitelisted[] = {
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
    0xac, 0x10, 0x00, 0x02, /* Dest IP: 172.16.0.2 */

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

#define PKT_GRE_WHITELISTED_LEN       sizeof(pkt_gre_whitelisted)
#define PKT_GRE_WHITELISTED_DECAP_LEN (PKT_GRE_WHITELISTED_LEN - 20 - 4)

/*
 * GRE-encapsulated packet from non-whitelisted source (11.0.0.1)
 *
 * Same structure as above but with src=11.0.0.1
 * Expected result: XDP_DROP
 */
static unsigned char pkt_gre_blocked[] = {
    /* Ethernet header (14 bytes) */
    0x00,
    0x11,
    0x22,
    0x33,
    0x44,
    0x55,
    0x66,
    0x77,
    0x88,
    0x99,
    0xaa,
    0xbb,
    0x08,
    0x00,

    /* Outer IPv4 header (20 bytes) */
    0x45,
    0x00,
    0x00,
    0x40,
    0x00,
    0x01,
    0x00,
    0x00,
    0x40,
    0x2f, /* Protocol: GRE */
    0x00,
    0x00,
    0x0b,
    0x00,
    0x00,
    0x01, /* Source IP: 11.0.0.1 (NOT whitelisted) */
    0xc0,
    0xa8,
    0x01,
    0x01,

    /* GRE header (4 bytes) */
    0x00,
    0x00,
    0x08,
    0x00,

    /* Inner IPv4 header (20 bytes) */
    0x45,
    0x00,
    0x00,
    0x28,
    0x00,
    0x02,
    0x00,
    0x00,
    0x40,
    0x06,
    0x00,
    0x00,
    0xac,
    0x10,
    0x00,
    0x01,
    0xac,
    0x10,
    0x00,
    0x02,

    /* TCP header (20 bytes) */
    0x00,
    0x50,
    0x00,
    0x51,
    0x00,
    0x00,
    0x00,
    0x01,
    0x00,
    0x00,
    0x00,
    0x00,
    0x50,
    0x02,
    0xff,
    0xff,
    0x00,
    0x00,
    0x00,
    0x00,
};

#define PKT_GRE_BLOCKED_LEN sizeof(pkt_gre_blocked)

/*
 * GRE packet with Key option from whitelisted source
 *
 * GRE header: 8 bytes (4 base + 4 key)
 * Flags: K=1 (0x2000)
 */
static unsigned char pkt_gre_with_key[] = {
    /* Ethernet header */
    0x00,
    0x11,
    0x22,
    0x33,
    0x44,
    0x55,
    0x66,
    0x77,
    0x88,
    0x99,
    0xaa,
    0xbb,
    0x08,
    0x00,

    /* Outer IPv4 header */
    0x45,
    0x00,
    0x00,
    0x44, /* Total length: 68 bytes */
    0x00,
    0x01,
    0x00,
    0x00,
    0x40,
    0x2f,
    0x00,
    0x00,
    0x0a,
    0x00,
    0x00,
    0x02, /* Source IP: 10.0.0.2 (whitelisted) */
    0xc0,
    0xa8,
    0x01,
    0x01,

    /* GRE header with Key (8 bytes) */
    0x20,
    0x00, /* Flags: K=1 (bit 2), Ver=0 */
    0x08,
    0x00, /* Protocol: IPv4 */
    0x00,
    0x00,
    0x00,
    0x01, /* Key: 1 */

    /* Inner IPv4 header */
    0x45,
    0x00,
    0x00,
    0x28,
    0x00,
    0x02,
    0x00,
    0x00,
    0x40,
    0x06,
    0x00,
    0x00,
    0xac,
    0x10,
    0x00,
    0x01,
    0xac,
    0x10,
    0x00,
    0x02,

    /* TCP header */
    0x00,
    0x50,
    0x00,
    0x51,
    0x00,
    0x00,
    0x00,
    0x01,
    0x00,
    0x00,
    0x00,
    0x00,
    0x50,
    0x02,
    0xff,
    0xff,
    0x00,
    0x00,
    0x00,
    0x00,
};

#define PKT_GRE_WITH_KEY_LEN       sizeof(pkt_gre_with_key)
#define PKT_GRE_WITH_KEY_DECAP_LEN (PKT_GRE_WITH_KEY_LEN - 20 - 8)

/*
 * IPIP-encapsulated IPv4 packet from whitelisted source (10.0.0.2)
 *
 * Structure:
 * [Ethernet: 14 bytes]
 * [Outer IPv4: 20 bytes, proto=4 (IPIP), src=10.0.0.2]
 * [Inner IPv4: 20 bytes, proto=6 (TCP)]
 * [TCP: 20 bytes]
 *
 * Total: 74 bytes
 * After decap: 54 bytes (outer IP removed = 20 bytes)
 */
static unsigned char pkt_ipip_whitelisted[] = {
    /* Ethernet header (14 bytes) */
    0x00,
    0x11,
    0x22,
    0x33,
    0x44,
    0x55,
    0x66,
    0x77,
    0x88,
    0x99,
    0xaa,
    0xbb,
    0x08,
    0x00,

    /* Outer IPv4 header (20 bytes) */
    0x45,
    0x00,
    0x00,
    0x3c, /* Total length: 60 bytes */
    0x00,
    0x01,
    0x00,
    0x00,
    0x40,
    0x04, /* Protocol: 4 (IPIP) */
    0x00,
    0x00,
    0x0a,
    0x00,
    0x00,
    0x02, /* Source IP: 10.0.0.2 (whitelisted) */
    0xc0,
    0xa8,
    0x01,
    0x01,

    /* Inner IPv4 header (20 bytes) */
    0x45,
    0x00,
    0x00,
    0x28,
    0x00,
    0x02,
    0x00,
    0x00,
    0x40,
    0x06, /* Protocol: TCP */
    0x00,
    0x00,
    0xac,
    0x10,
    0x00,
    0x01, /* Source: 172.16.0.1 */
    0xac,
    0x10,
    0x00,
    0x02, /* Dest: 172.16.0.2 */

    /* TCP header (20 bytes) */
    0x00,
    0x50,
    0x00,
    0x51,
    0x00,
    0x00,
    0x00,
    0x01,
    0x00,
    0x00,
    0x00,
    0x00,
    0x50,
    0x02,
    0xff,
    0xff,
    0x00,
    0x00,
    0x00,
    0x00,
};

#define PKT_IPIP_WHITELISTED_LEN       sizeof(pkt_ipip_whitelisted)
#define PKT_IPIP_WHITELISTED_DECAP_LEN (PKT_IPIP_WHITELISTED_LEN - 20)

/*
 * IPIP packet from non-whitelisted source
 */
static unsigned char pkt_ipip_blocked[] = {
    /* Ethernet header */
    0x00,
    0x11,
    0x22,
    0x33,
    0x44,
    0x55,
    0x66,
    0x77,
    0x88,
    0x99,
    0xaa,
    0xbb,
    0x08,
    0x00,

    /* Outer IPv4 header */
    0x45,
    0x00,
    0x00,
    0x3c,
    0x00,
    0x01,
    0x00,
    0x00,
    0x40,
    0x04, /* Protocol: IPIP */
    0x00,
    0x00,
    0x0b,
    0x00,
    0x00,
    0x01, /* Source IP: 11.0.0.1 (NOT whitelisted) */
    0xc0,
    0xa8,
    0x01,
    0x01,

    /* Inner IPv4 header */
    0x45,
    0x00,
    0x00,
    0x28,
    0x00,
    0x02,
    0x00,
    0x00,
    0x40,
    0x06,
    0x00,
    0x00,
    0xac,
    0x10,
    0x00,
    0x01,
    0xac,
    0x10,
    0x00,
    0x02,

    /* TCP header */
    0x00,
    0x50,
    0x00,
    0x51,
    0x00,
    0x00,
    0x00,
    0x01,
    0x00,
    0x00,
    0x00,
    0x00,
    0x50,
    0x02,
    0xff,
    0xff,
    0x00,
    0x00,
    0x00,
    0x00,
};

#define PKT_IPIP_BLOCKED_LEN sizeof(pkt_ipip_blocked)

/*
 * Normal TCP/IP packet (non-tunnel)
 *
 * Structure:
 * [Ethernet: 14 bytes]
 * [IPv4: 20 bytes, proto=6 (TCP)]
 * [TCP: 20 bytes]
 *
 * Expected result: XDP_PASS (unchanged)
 */
static unsigned char pkt_tcp_normal[] = {
    /* Ethernet header (14 bytes) */
    0x00,
    0x11,
    0x22,
    0x33,
    0x44,
    0x55,
    0x66,
    0x77,
    0x88,
    0x99,
    0xaa,
    0xbb,
    0x08,
    0x00,

    /* IPv4 header (20 bytes) */
    0x45,
    0x00,
    0x00,
    0x28, /* Total length: 40 bytes */
    0x00,
    0x01,
    0x00,
    0x00,
    0x40,
    0x06, /* Protocol: TCP */
    0x00,
    0x00,
    0xac,
    0x10,
    0x00,
    0x01, /* Source: 172.16.0.1 */
    0xac,
    0x10,
    0x00,
    0x02, /* Dest: 172.16.0.2 */

    /* TCP header (20 bytes) */
    0x00,
    0x50,
    0x00,
    0x51,
    0x00,
    0x00,
    0x00,
    0x01,
    0x00,
    0x00,
    0x00,
    0x00,
    0x50,
    0x02,
    0xff,
    0xff,
    0x00,
    0x00,
    0x00,
    0x00,
};

#define PKT_TCP_NORMAL_LEN sizeof(pkt_tcp_normal)

/*
 * UDP packet (non-tunnel)
 *
 * Expected result: XDP_PASS (unchanged)
 */
static unsigned char pkt_udp_normal[] = {
    /* Ethernet header */
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,

    /* IPv4 header */
    0x45, 0x00, 0x00, 0x1c,             /* Total length: 28 bytes */
    0x00, 0x01, 0x00, 0x00, 0x40, 0x11, /* Protocol: UDP */
    0x00, 0x00, 0xac, 0x10, 0x00, 0x01, 0xac, 0x10, 0x00, 0x02,

    /* UDP header (8 bytes) */
    0x00, 0x35, /* Source port: 53 (DNS) */
    0x00, 0x35, /* Dest port: 53 */
    0x00, 0x08, /* Length: 8 bytes */
    0x00, 0x00, /* Checksum */
};

#define PKT_UDP_NORMAL_LEN sizeof(pkt_udp_normal)

/*
 * IPv6 packet (should be passed through unchanged)
 */
static unsigned char pkt_ipv6[] = {
    /* Ethernet header */
    0x00,
    0x11,
    0x22,
    0x33,
    0x44,
    0x55,
    0x66,
    0x77,
    0x88,
    0x99,
    0xaa,
    0xbb,
    0x86,
    0xdd, /* EtherType: IPv6 */

    /* IPv6 header (40 bytes) */
    0x60,
    0x00,
    0x00,
    0x00, /* Version=6, Traffic class, Flow label */
    0x00,
    0x00, /* Payload length: 0 */
    0x3b, /* Next header: No next header */
    0x40, /* Hop limit: 64 */
    /* Source address (16 bytes) */
    0x20,
    0x01,
    0x0d,
    0xb8,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x01,
    /* Destination address (16 bytes) */
    0x20,
    0x01,
    0x0d,
    0xb8,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x02,
};

#define PKT_IPV6_LEN sizeof(pkt_ipv6)

/*
 * Malformed GRE packet (truncated)
 *
 * Missing inner IP header - should be dropped
 */
static unsigned char pkt_gre_truncated[] = {
    /* Ethernet header */
    0x00,
    0x11,
    0x22,
    0x33,
    0x44,
    0x55,
    0x66,
    0x77,
    0x88,
    0x99,
    0xaa,
    0xbb,
    0x08,
    0x00,

    /* Outer IPv4 header */
    0x45,
    0x00,
    0x00,
    0x1c, /* Total length: 28 (just outer IP + GRE base) */
    0x00,
    0x01,
    0x00,
    0x00,
    0x40,
    0x2f,
    0x00,
    0x00,
    0x0a,
    0x00,
    0x00,
    0x01, /* Whitelisted source */
    0xc0,
    0xa8,
    0x01,
    0x01,

    /* GRE header (4 bytes) - but no inner IP */
    0x00,
    0x00,
    0x08,
    0x00,
};

#define PKT_GRE_TRUNCATED_LEN sizeof(pkt_gre_truncated)

/*
 * GRE-encapsulated IPv6 packet from whitelisted source
 *
 * Structure:
 * [Ethernet: 14 bytes]
 * [Outer IPv4: 20 bytes, proto=47 (GRE), src=10.0.0.1]
 * [GRE: 4 bytes, proto=0x86DD (IPv6)]
 * [Inner IPv6: 40 bytes, next_hdr=58 (ICMPv6)]
 * [ICMPv6: 8 bytes]
 *
 * Total: 86 bytes
 * After decap: 62 bytes (outer IP + GRE removed = 24 bytes)
 */
static unsigned char pkt_gre_ipv6_inner[] = {
    /* Ethernet header (14 bytes) */
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08,
    0x00, /* EtherType: IPv4 */

    /* Outer IPv4 header (20 bytes) */
    0x45, 0x00, 0x00, 0x48,             /* Total length: 72 bytes */
    0x00, 0x01, 0x00, 0x00, 0x40, 0x2f, /* Protocol: 47 (GRE) */
    0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, /* Source IP: 10.0.0.1 (whitelisted) */
    0xc0, 0xa8, 0x01, 0x01,

    /* GRE header (4 bytes) */
    0x00, 0x00, 0x86, 0xdd, /* Protocol: IPv6 (0x86DD) */

    /* Inner IPv6 header (40 bytes) */
    0x60, 0x00, 0x00, 0x00, /* Version=6, Traffic class, Flow label */
    0x00, 0x08,             /* Payload length: 8 bytes */
    0x3a,                   /* Next header: 58 (ICMPv6) */
    0x40,                   /* Hop limit: 64 */
    /* Source address (16 bytes) */
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    /* Destination address (16 bytes) */
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,

    /* ICMPv6 Echo Request (8 bytes) */
    0x80,       /* Type: Echo Request */
    0x00,       /* Code */
    0x00, 0x00, /* Checksum */
    0x00, 0x01, /* Identifier */
    0x00, 0x01, /* Sequence number */
};

#define PKT_GRE_IPV6_INNER_LEN       sizeof(pkt_gre_ipv6_inner)
#define PKT_GRE_IPV6_INNER_DECAP_LEN (PKT_GRE_IPV6_INNER_LEN - 20 - 4)

/*
 * IPv6-in-IPv4 encapsulated packet (protocol 41)
 *
 * Structure:
 * [Ethernet: 14 bytes]
 * [Outer IPv4: 20 bytes, proto=41 (IPv6-in-IPv4), src=10.0.0.2]
 * [Inner IPv6: 40 bytes, next_hdr=58 (ICMPv6)]
 * [ICMPv6: 8 bytes]
 *
 * Total: 82 bytes
 * After decap: 62 bytes (outer IP removed = 20 bytes)
 */
static unsigned char pkt_ipv6_in_ipv4[] = {
    /* Ethernet header (14 bytes) */
    0x00,
    0x11,
    0x22,
    0x33,
    0x44,
    0x55,
    0x66,
    0x77,
    0x88,
    0x99,
    0xaa,
    0xbb,
    0x08,
    0x00, /* EtherType: IPv4 */

    /* Outer IPv4 header (20 bytes) */
    0x45,
    0x00,
    0x00,
    0x44, /* Total length: 68 bytes */
    0x00,
    0x01,
    0x00,
    0x00,
    0x40,
    0x29, /* Protocol: 41 (IPv6) */
    0x00,
    0x00,
    0x0a,
    0x00,
    0x00,
    0x02, /* Source IP: 10.0.0.2 (whitelisted) */
    0xc0,
    0xa8,
    0x01,
    0x01,

    /* Inner IPv6 header (40 bytes) */
    0x60,
    0x00,
    0x00,
    0x00,
    0x00,
    0x08, /* Payload length: 8 bytes */
    0x3a, /* Next header: ICMPv6 */
    0x40, /* Hop limit: 64 */
    /* Source address */
    0x20,
    0x01,
    0x0d,
    0xb8,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x01,
    /* Destination address */
    0x20,
    0x01,
    0x0d,
    0xb8,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x02,

    /* ICMPv6 Echo Request */
    0x80,
    0x00,
    0x00,
    0x00,
    0x00,
    0x01,
    0x00,
    0x01,
};

#define PKT_IPV6_IN_IPV4_LEN       sizeof(pkt_ipv6_in_ipv4)
#define PKT_IPV6_IN_IPV4_DECAP_LEN (PKT_IPV6_IN_IPV4_LEN - 20)

/*
 * GRE-encapsulated packet with IPv6 outer header
 *
 * Structure:
 * [Ethernet: 14 bytes]
 * [Outer IPv6: 40 bytes, next_hdr=47 (GRE), src=2001:db8::1]
 * [GRE: 4 bytes, proto=0x0800 (IPv4)]
 * [Inner IPv4: 20 bytes, proto=6 (TCP)]
 * [TCP: 20 bytes]
 *
 * Total: 98 bytes
 * After decap: 54 bytes (outer IPv6 + GRE removed = 44 bytes)
 */
static unsigned char pkt_ipv6_outer_gre_ipv4[] = {
    /* Ethernet header (14 bytes) */
    0x00,
    0x11,
    0x22,
    0x33,
    0x44,
    0x55,
    0x66,
    0x77,
    0x88,
    0x99,
    0xaa,
    0xbb,
    0x86,
    0xdd, /* EtherType: IPv6 */

    /* Outer IPv6 header (40 bytes) */
    0x60,
    0x00,
    0x00,
    0x00, /* Version=6, Traffic class, Flow label */
    0x00,
    0x2c, /* Payload length: 44 bytes */
    0x2f, /* Next header: 47 (GRE) */
    0x40, /* Hop limit: 64 */
    /* Source address: 2001:db8::1 */
    0x20,
    0x01,
    0x0d,
    0xb8,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x01,
    /* Destination address: 2001:db8::100 */
    0x20,
    0x01,
    0x0d,
    0xb8,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x01,
    0x00,

    /* GRE header (4 bytes) */
    0x00,
    0x00,
    0x08,
    0x00, /* Protocol: IPv4 */

    /* Inner IPv4 header (20 bytes) */
    0x45,
    0x00,
    0x00,
    0x28, /* Total length: 40 bytes */
    0x00,
    0x02,
    0x00,
    0x00,
    0x40,
    0x06, /* Protocol: TCP */
    0x00,
    0x00,
    0xac,
    0x10,
    0x00,
    0x01, /* Source: 172.16.0.1 */
    0xac,
    0x10,
    0x00,
    0x02, /* Dest: 172.16.0.2 */

    /* TCP header (20 bytes) */
    0x00,
    0x50,
    0x00,
    0x51,
    0x00,
    0x00,
    0x00,
    0x01,
    0x00,
    0x00,
    0x00,
    0x00,
    0x50,
    0x02,
    0xff,
    0xff,
    0x00,
    0x00,
    0x00,
    0x00,
};

#define PKT_IPV6_OUTER_GRE_IPV4_LEN       sizeof(pkt_ipv6_outer_gre_ipv4)
#define PKT_IPV6_OUTER_GRE_IPV4_DECAP_LEN (PKT_IPV6_OUTER_GRE_IPV4_LEN - 40 - 4)

/*
 * IPv4-in-IPv6 encapsulated packet
 *
 * Structure:
 * [Ethernet: 14 bytes]
 * [Outer IPv6: 40 bytes, next_hdr=4 (IPIP), src=2001:db8::2]
 * [Inner IPv4: 20 bytes, proto=6 (TCP)]
 * [TCP: 20 bytes]
 *
 * Total: 94 bytes
 * After decap: 54 bytes (outer IPv6 removed = 40 bytes)
 */
static unsigned char pkt_ipv4_in_ipv6[] = {
    /* Ethernet header (14 bytes) */
    0x00,
    0x11,
    0x22,
    0x33,
    0x44,
    0x55,
    0x66,
    0x77,
    0x88,
    0x99,
    0xaa,
    0xbb,
    0x86,
    0xdd, /* EtherType: IPv6 */

    /* Outer IPv6 header (40 bytes) */
    0x60,
    0x00,
    0x00,
    0x00,
    0x00,
    0x28, /* Payload length: 40 bytes */
    0x04, /* Next header: 4 (IPIP) */
    0x40, /* Hop limit: 64 */
    /* Source address: 2001:db8::2 */
    0x20,
    0x01,
    0x0d,
    0xb8,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x02,
    /* Destination address: 2001:db8::100 */
    0x20,
    0x01,
    0x0d,
    0xb8,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x01,
    0x00,

    /* Inner IPv4 header (20 bytes) */
    0x45,
    0x00,
    0x00,
    0x28,
    0x00,
    0x02,
    0x00,
    0x00,
    0x40,
    0x06, /* Protocol: TCP */
    0x00,
    0x00,
    0xac,
    0x10,
    0x00,
    0x01,
    0xac,
    0x10,
    0x00,
    0x02,

    /* TCP header (20 bytes) */
    0x00,
    0x50,
    0x00,
    0x51,
    0x00,
    0x00,
    0x00,
    0x01,
    0x00,
    0x00,
    0x00,
    0x00,
    0x50,
    0x02,
    0xff,
    0xff,
    0x00,
    0x00,
    0x00,
    0x00,
};

#define PKT_IPV4_IN_IPV6_LEN       sizeof(pkt_ipv4_in_ipv6)
#define PKT_IPV4_IN_IPV6_DECAP_LEN (PKT_IPV4_IN_IPV6_LEN - 40)

/*
 * IPv6-in-IPv6 encapsulated packet
 *
 * Structure:
 * [Ethernet: 14 bytes]
 * [Outer IPv6: 40 bytes, next_hdr=41 (IPv6), src=2001:db8::3]
 * [Inner IPv6: 40 bytes, next_hdr=58 (ICMPv6)]
 * [ICMPv6: 8 bytes]
 *
 * Total: 102 bytes
 * After decap: 62 bytes (outer IPv6 removed = 40 bytes)
 */
static unsigned char pkt_ipv6_in_ipv6[] = {
    /* Ethernet header (14 bytes) */
    0x00,
    0x11,
    0x22,
    0x33,
    0x44,
    0x55,
    0x66,
    0x77,
    0x88,
    0x99,
    0xaa,
    0xbb,
    0x86,
    0xdd, /* EtherType: IPv6 */

    /* Outer IPv6 header (40 bytes) */
    0x60,
    0x00,
    0x00,
    0x00,
    0x00,
    0x30, /* Payload length: 48 bytes */
    0x29, /* Next header: 41 (IPv6) */
    0x40, /* Hop limit: 64 */
    /* Source address: 2001:db8::3 */
    0x20,
    0x01,
    0x0d,
    0xb8,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x03,
    /* Destination address: 2001:db8::100 */
    0x20,
    0x01,
    0x0d,
    0xb8,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x01,
    0x00,

    /* Inner IPv6 header (40 bytes) */
    0x60,
    0x00,
    0x00,
    0x00,
    0x00,
    0x08, /* Payload length: 8 bytes */
    0x3a, /* Next header: ICMPv6 */
    0x40, /* Hop limit: 64 */
    /* Source address */
    0x20,
    0x01,
    0x0d,
    0xb8,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x0a,
    /* Destination address */
    0x20,
    0x01,
    0x0d,
    0xb8,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x0b,

    /* ICMPv6 Echo Request */
    0x80,
    0x00,
    0x00,
    0x00,
    0x00,
    0x01,
    0x00,
    0x01,
};

#define PKT_IPV6_IN_IPV6_LEN       sizeof(pkt_ipv6_in_ipv6)
#define PKT_IPV6_IN_IPV6_DECAP_LEN (PKT_IPV6_IN_IPV6_LEN - 40)

/*
 * Test IP addresses for whitelist
 */
#define TEST_IP_WHITELISTED_1 0x0100000a /* 10.0.0.1 in little-endian */
#define TEST_IP_WHITELISTED_2 0x0200000a /* 10.0.0.2 in little-endian */
#define TEST_IP_BLOCKED       0x0100000b /* 11.0.0.1 in little-endian */

/* Network byte order versions */
#define TEST_IP_WHITELISTED_1_BE 0x0a000001
#define TEST_IP_WHITELISTED_2_BE 0x0a000002
#define TEST_IP_BLOCKED_BE       0x0b000001

/*
 * Test IPv6 addresses for whitelist
 * 2001:db8::1 (whitelisted)
 * 2001:db8::2 (whitelisted)
 * 2001:db8::3 (whitelisted)
 * 2001:db8::99 (not whitelisted)
 *
 * NOTE: Values are in network byte order (big-endian) as stored in struct in6_addr.
 * On little-endian systems, each 32-bit word is byte-swapped when accessed via u6_addr32[].
 * Packet bytes 0x20 0x01 0x0d 0xb8 -> 0xb80d0120 on little-endian
 */
#define TEST_IPV6_WHITELISTED_1                                                                    \
	{                                                                                          \
		0xb80d0120, 0x00000000, 0x00000000, 0x01000000                                     \
	}
#define TEST_IPV6_WHITELISTED_2                                                                    \
	{                                                                                          \
		0xb80d0120, 0x00000000, 0x00000000, 0x02000000                                     \
	}
#define TEST_IPV6_WHITELISTED_3                                                                    \
	{                                                                                          \
		0xb80d0120, 0x00000000, 0x00000000, 0x03000000                                     \
	}
#define TEST_IPV6_BLOCKED                                                                          \
	{                                                                                          \
		0xb80d0120, 0x00000000, 0x00000000, 0x99000000                                     \
	}

#endif /* __TEST_PACKETS_H */
