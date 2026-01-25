/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * test_parsing_helpers.c - Unit tests for parsing helper functions
 *
 * These tests run in userspace without requiring BPF loading or root permissions.
 * They test the pure C helper functions from parsing.h using mock packet data.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

/* Test framework macros */
#define TEST_PASS(name) do { printf("  \033[32m✓\033[0m %s\n", name); passed++; } while(0)
#define TEST_FAIL(name, ...) do { printf("  \033[31m✗\033[0m %s: ", name); printf(__VA_ARGS__); printf("\n"); failed++; } while(0)
#define ASSERT(cond, ...) do { if (!(cond)) { TEST_FAIL(test_name, __VA_ARGS__); return; } } while(0)
#define ASSERT_EQ(a, b, ...) do { if ((a) != (b)) { TEST_FAIL(test_name, __VA_ARGS__); return; } } while(0)
#define ASSERT_NEQ(a, b, ...) do { if ((a) == (b)) { TEST_FAIL(test_name, __VA_ARGS__); return; } } while(0)
#define ASSERT_NULL(ptr, ...) do { if ((ptr) != NULL) { TEST_FAIL(test_name, __VA_ARGS__); return; } } while(0)
#define ASSERT_NOT_NULL(ptr, ...) do { if ((ptr) == NULL) { TEST_FAIL(test_name, __VA_ARGS__); return; } } while(0)

static int passed = 0;
static int failed = 0;

/* Mock XDP context for testing */
struct xdp_md {
	uint64_t data;
	uint64_t data_end;
	uint32_t data_meta;
	uint32_t ingress_ifindex;
	uint32_t rx_queue_index;
	uint32_t egress_ifindex;
};

/* Include parsing helpers (with BPF macros stubbed out) */
#define __always_inline inline
#define bpf_ntohs(x) ntohs(x)
#define bpf_htons(x) htons(x)
#define bpf_ntohl(x) ntohl(x)
#define bpf_htonl(x) htonl(x)

/* Header cursor structure (from parsing.h) */
struct hdr_cursor {
	void *pos;
	void *end;
};

/* Parsing helper functions (inlined from parsing.h) */
static inline void cursor_init(struct xdp_md *ctx, struct hdr_cursor *cursor)
{
	cursor->pos = (void *)(long)ctx->data;
	cursor->end = (void *)(long)ctx->data_end;
}

static inline int cursor_check(struct hdr_cursor *cursor, int len)
{
	return cursor->pos + len <= cursor->end;
}

static inline void cursor_advance(struct hdr_cursor *cursor, int len)
{
	cursor->pos += len;
}

static inline int parse_ethhdr(struct hdr_cursor *cursor, struct ethhdr **eth)
{
	struct ethhdr *hdr = cursor->pos;

	if ((void *)(hdr + 1) > cursor->end)
		return -1;

	*eth = hdr;
	cursor_advance(cursor, sizeof(*hdr));

	return bpf_ntohs(hdr->h_proto);
}

static inline int parse_iphdr(struct hdr_cursor *cursor, struct iphdr **iph)
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
	cursor_advance(cursor, hdr_len);

	return hdr_len;
}

static inline int peek_iphdr(struct hdr_cursor *cursor, struct iphdr **iph)
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

static inline int parse_ipv6hdr(struct hdr_cursor *cursor, struct ipv6hdr **ip6h)
{
	struct ipv6hdr *hdr = cursor->pos;

	if ((void *)(hdr + 1) > cursor->end)
		return -1;

	if (hdr->version != 6)
		return -1;

	*ip6h = hdr;
	cursor_advance(cursor, sizeof(*hdr));

	return sizeof(*hdr);
}

static inline int peek_ipv6hdr(struct hdr_cursor *cursor, struct ipv6hdr **ip6h)
{
	struct ipv6hdr *hdr = cursor->pos;

	if ((void *)(hdr + 1) > cursor->end)
		return -1;

	if (hdr->version != 6)
		return -1;

	*ip6h = hdr;
	return sizeof(*hdr);
}

static inline int ptr_is_valid(void *ptr, int size, void *end)
{
	return (ptr + size <= end);
}

static inline void *ptr_at(void *data, void *data_end, uint32_t offset, uint32_t size)
{
	void *ptr = data + offset;

	if (ptr + size > data_end)
		return NULL;

	return ptr;
}

static inline uint32_t cursor_remaining(struct hdr_cursor *cursor)
{
	if (cursor->pos >= cursor->end)
		return 0;
	return cursor->end - cursor->pos;
}

static inline void cursor_reinit(struct xdp_md *ctx, struct hdr_cursor *cursor)
{
	cursor->pos = (void *)(long)ctx->data;
	cursor->end = (void *)(long)ctx->data_end;
}

/* ========== Test Cases ========== */

void test_cursor_init()
{
	const char *test_name = "cursor_init";
	uint8_t packet[100] = {0};
	struct xdp_md ctx = {
		.data = (uint64_t)packet,
		.data_end = (uint64_t)(packet + sizeof(packet)),
	};
	struct hdr_cursor cursor;

	cursor_init(&ctx, &cursor);

	ASSERT_EQ(cursor.pos, packet, "cursor.pos should point to packet start");
	ASSERT_EQ(cursor.end, packet + sizeof(packet), "cursor.end should point to packet end");

	TEST_PASS(test_name);
}

void test_cursor_check()
{
	const char *test_name = "cursor_check";
	uint8_t packet[100] = {0};
	struct hdr_cursor cursor = {
		.pos = packet,
		.end = packet + sizeof(packet),
	};

	ASSERT(cursor_check(&cursor, 50), "should have space for 50 bytes");
	ASSERT(cursor_check(&cursor, 100), "should have space for exactly 100 bytes");
	ASSERT(!cursor_check(&cursor, 101), "should NOT have space for 101 bytes");

	cursor.pos = packet + 90;
	ASSERT(cursor_check(&cursor, 10), "should have space for 10 bytes at offset 90");
	ASSERT(!cursor_check(&cursor, 11), "should NOT have space for 11 bytes at offset 90");

	TEST_PASS(test_name);
}

void test_cursor_advance()
{
	const char *test_name = "cursor_advance";
	uint8_t packet[100] = {0};
	struct hdr_cursor cursor = {
		.pos = packet,
		.end = packet + sizeof(packet),
	};

	cursor_advance(&cursor, 14);
	ASSERT_EQ(cursor.pos, packet + 14, "cursor should advance 14 bytes");

	cursor_advance(&cursor, 20);
	ASSERT_EQ(cursor.pos, packet + 34, "cursor should advance another 20 bytes");

	TEST_PASS(test_name);
}

void test_cursor_remaining()
{
	const char *test_name = "cursor_remaining";
	uint8_t packet[100] = {0};
	struct hdr_cursor cursor = {
		.pos = packet,
		.end = packet + sizeof(packet),
	};

	ASSERT_EQ(cursor_remaining(&cursor), 100, "should have 100 bytes remaining");

	cursor.pos = packet + 50;
	ASSERT_EQ(cursor_remaining(&cursor), 50, "should have 50 bytes remaining");

	cursor.pos = packet + 100;
	ASSERT_EQ(cursor_remaining(&cursor), 0, "should have 0 bytes remaining");

	cursor.pos = packet + 110; /* Beyond end */
	ASSERT_EQ(cursor_remaining(&cursor), 0, "should return 0 when pos > end");

	TEST_PASS(test_name);
}

void test_parse_ethhdr_valid()
{
	const char *test_name = "parse_ethhdr - valid header";
	uint8_t packet[100] = {0};
	struct ethhdr *eth_hdr = (struct ethhdr *)packet;
	struct hdr_cursor cursor = {
		.pos = packet,
		.end = packet + sizeof(packet),
	};
	struct ethhdr *parsed_eth = NULL;
	int proto;

	/* Create valid Ethernet header */
	memset(eth_hdr->h_dest, 0xff, ETH_ALEN);    /* Broadcast */
	memset(eth_hdr->h_source, 0x11, ETH_ALEN);  /* Source MAC */
	eth_hdr->h_proto = htons(ETH_P_IP);         /* IPv4 */

	proto = parse_ethhdr(&cursor, &parsed_eth);

	ASSERT_NOT_NULL(parsed_eth, "should parse Ethernet header");
	ASSERT_EQ(proto, ETH_P_IP, "should return IPv4 protocol (0x0800)");
	ASSERT_EQ(cursor.pos, packet + sizeof(struct ethhdr), "cursor should advance past Ethernet header");

	TEST_PASS(test_name);
}

void test_parse_ethhdr_truncated()
{
	const char *test_name = "parse_ethhdr - truncated packet";
	uint8_t packet[10] = {0}; /* Too small for Ethernet header */
	struct hdr_cursor cursor = {
		.pos = packet,
		.end = packet + sizeof(packet),
	};
	struct ethhdr *parsed_eth = NULL;
	int proto;

	proto = parse_ethhdr(&cursor, &parsed_eth);

	ASSERT_EQ(proto, -1, "should return -1 for truncated packet");

	TEST_PASS(test_name);
}

void test_parse_iphdr_valid()
{
	const char *test_name = "parse_iphdr - valid header";
	uint8_t packet[100] = {0};
	struct iphdr *ip_hdr = (struct iphdr *)packet;
	struct hdr_cursor cursor = {
		.pos = packet,
		.end = packet + sizeof(packet),
	};
	struct iphdr *parsed_ip = NULL;
	int hdr_len;

	/* Create valid IPv4 header (20 bytes, IHL=5) */
	ip_hdr->version = 4;
	ip_hdr->ihl = 5;  /* 5 * 4 = 20 bytes */
	ip_hdr->protocol = IPPROTO_TCP;

	hdr_len = parse_iphdr(&cursor, &parsed_ip);

	ASSERT_NOT_NULL(parsed_ip, "should parse IPv4 header");
	ASSERT_EQ(hdr_len, 20, "should return 20 byte header length");
	ASSERT_EQ(cursor.pos, packet + 20, "cursor should advance 20 bytes");

	TEST_PASS(test_name);
}

void test_parse_iphdr_with_options()
{
	const char *test_name = "parse_iphdr - with IP options";
	uint8_t packet[100] = {0};
	struct iphdr *ip_hdr = (struct iphdr *)packet;
	struct hdr_cursor cursor = {
		.pos = packet,
		.end = packet + sizeof(packet),
	};
	struct iphdr *parsed_ip = NULL;
	int hdr_len;

	/* Create IPv4 header with options (IHL=6 -> 24 bytes) */
	ip_hdr->version = 4;
	ip_hdr->ihl = 6;  /* 6 * 4 = 24 bytes */
	ip_hdr->protocol = IPPROTO_GRE;

	hdr_len = parse_iphdr(&cursor, &parsed_ip);

	ASSERT_NOT_NULL(parsed_ip, "should parse IPv4 header with options");
	ASSERT_EQ(hdr_len, 24, "should return 24 byte header length");
	ASSERT_EQ(cursor.pos, packet + 24, "cursor should advance 24 bytes");

	TEST_PASS(test_name);
}

void test_parse_iphdr_invalid_ihl()
{
	const char *test_name = "parse_iphdr - invalid IHL";
	uint8_t packet[100] = {0};
	struct iphdr *ip_hdr = (struct iphdr *)packet;
	struct hdr_cursor cursor = {
		.pos = packet,
		.end = packet + sizeof(packet),
	};
	struct iphdr *parsed_ip = NULL;
	int hdr_len;

	/* Create invalid IPv4 header (IHL=4 -> 16 bytes < minimum 20) */
	ip_hdr->version = 4;
	ip_hdr->ihl = 4;  /* Invalid: 4 * 4 = 16 bytes < 20 */

	hdr_len = parse_iphdr(&cursor, &parsed_ip);

	ASSERT_EQ(hdr_len, -1, "should reject invalid IHL");

	TEST_PASS(test_name);
}

void test_parse_iphdr_truncated()
{
	const char *test_name = "parse_iphdr - truncated packet";
	uint8_t packet[25] = {0}; /* Large enough for struct but truncated at end */
	struct iphdr *ip_hdr = (struct iphdr *)packet;
	struct hdr_cursor cursor = {
		.pos = packet,
		.end = packet + 15, /* Truncate to 15 bytes */
	};
	struct iphdr *parsed_ip = NULL;
	int hdr_len;

	ip_hdr->version = 4;
	ip_hdr->ihl = 5; /* Requires 20 bytes but only 15 available */

	hdr_len = parse_iphdr(&cursor, &parsed_ip);

	ASSERT_EQ(hdr_len, -1, "should reject truncated packet");

	TEST_PASS(test_name);
}

void test_peek_iphdr()
{
	const char *test_name = "peek_iphdr - cursor not advanced";
	uint8_t packet[100] = {0};
	struct iphdr *ip_hdr = (struct iphdr *)packet;
	struct hdr_cursor cursor = {
		.pos = packet,
		.end = packet + sizeof(packet),
	};
	struct iphdr *peeked_ip = NULL;
	void *original_pos = cursor.pos;
	int hdr_len;

	/* Create valid IPv4 header */
	ip_hdr->version = 4;
	ip_hdr->ihl = 5;

	hdr_len = peek_iphdr(&cursor, &peeked_ip);

	ASSERT_NOT_NULL(peeked_ip, "should peek IPv4 header");
	ASSERT_EQ(hdr_len, 20, "should return 20 byte header length");
	ASSERT_EQ(cursor.pos, original_pos, "cursor position should NOT change");

	TEST_PASS(test_name);
}

void test_parse_ipv6hdr_valid()
{
	const char *test_name = "parse_ipv6hdr - valid header";
	uint8_t packet[100] = {0};
	struct ipv6hdr *ip6_hdr = (struct ipv6hdr *)packet;
	struct hdr_cursor cursor = {
		.pos = packet,
		.end = packet + sizeof(packet),
	};
	struct ipv6hdr *parsed_ip6 = NULL;
	int hdr_len;

	/* Create valid IPv6 header */
	ip6_hdr->version = 6;
	ip6_hdr->nexthdr = IPPROTO_TCP;

	hdr_len = parse_ipv6hdr(&cursor, &parsed_ip6);

	ASSERT_NOT_NULL(parsed_ip6, "should parse IPv6 header");
	ASSERT_EQ(hdr_len, 40, "should return 40 byte header length");
	ASSERT_EQ(cursor.pos, packet + 40, "cursor should advance 40 bytes");

	TEST_PASS(test_name);
}

void test_parse_ipv6hdr_invalid_version()
{
	const char *test_name = "parse_ipv6hdr - invalid version";
	uint8_t packet[100] = {0};
	struct ipv6hdr *ip6_hdr = (struct ipv6hdr *)packet;
	struct hdr_cursor cursor = {
		.pos = packet,
		.end = packet + sizeof(packet),
	};
	struct ipv6hdr *parsed_ip6 = NULL;
	int hdr_len;

	/* Create header with invalid version */
	ip6_hdr->version = 4;  /* Wrong version */

	hdr_len = parse_ipv6hdr(&cursor, &parsed_ip6);

	ASSERT_EQ(hdr_len, -1, "should reject invalid IPv6 version");

	TEST_PASS(test_name);
}

void test_parse_ipv6hdr_truncated()
{
	const char *test_name = "parse_ipv6hdr - truncated packet";
	uint8_t packet[30] = {0}; /* Too small for IPv6 header (40 bytes) */
	struct ipv6hdr *ip6_hdr = (struct ipv6hdr *)packet;
	struct hdr_cursor cursor = {
		.pos = packet,
		.end = packet + sizeof(packet),
	};
	struct ipv6hdr *parsed_ip6 = NULL;
	int hdr_len;

	ip6_hdr->version = 6;

	hdr_len = parse_ipv6hdr(&cursor, &parsed_ip6);

	ASSERT_EQ(hdr_len, -1, "should reject truncated IPv6 packet");

	TEST_PASS(test_name);
}

void test_peek_ipv6hdr()
{
	const char *test_name = "peek_ipv6hdr - cursor not advanced";
	uint8_t packet[100] = {0};
	struct ipv6hdr *ip6_hdr = (struct ipv6hdr *)packet;
	struct hdr_cursor cursor = {
		.pos = packet,
		.end = packet + sizeof(packet),
	};
	struct ipv6hdr *peeked_ip6 = NULL;
	void *original_pos = cursor.pos;
	int hdr_len;

	/* Create valid IPv6 header */
	ip6_hdr->version = 6;

	hdr_len = peek_ipv6hdr(&cursor, &peeked_ip6);

	ASSERT_NOT_NULL(peeked_ip6, "should peek IPv6 header");
	ASSERT_EQ(hdr_len, 40, "should return 40 byte header length");
	ASSERT_EQ(cursor.pos, original_pos, "cursor position should NOT change");

	TEST_PASS(test_name);
}

void test_ptr_is_valid()
{
	const char *test_name = "ptr_is_valid";
	uint8_t packet[100] = {0};
	void *data = packet;
	void *data_end = packet + sizeof(packet);

	ASSERT(ptr_is_valid(data, 50, data_end), "50 bytes at start should be valid");
	ASSERT(ptr_is_valid(data, 100, data_end), "exactly 100 bytes should be valid");
	ASSERT(!ptr_is_valid(data, 101, data_end), "101 bytes should be invalid");

	ASSERT(ptr_is_valid(data + 90, 10, data_end), "10 bytes at offset 90 should be valid");
	ASSERT(!ptr_is_valid(data + 95, 10, data_end), "10 bytes at offset 95 should be invalid");

	TEST_PASS(test_name);
}

void test_ptr_at_valid()
{
	const char *test_name = "ptr_at - valid offset";
	uint8_t packet[100] = {0};
	void *data = packet;
	void *data_end = packet + sizeof(packet);
	void *ptr;

	ptr = ptr_at(data, data_end, 0, sizeof(struct ethhdr));
	ASSERT_NOT_NULL(ptr, "should return pointer at offset 0");
	ASSERT_EQ(ptr, packet, "should point to packet start");

	ptr = ptr_at(data, data_end, 14, sizeof(struct iphdr));
	ASSERT_NOT_NULL(ptr, "should return pointer at offset 14");
	ASSERT_EQ(ptr, packet + 14, "should point to offset 14");

	TEST_PASS(test_name);
}

void test_ptr_at_out_of_bounds()
{
	const char *test_name = "ptr_at - out of bounds";
	uint8_t packet[100] = {0};
	void *data = packet;
	void *data_end = packet + sizeof(packet);
	void *ptr;

	ptr = ptr_at(data, data_end, 90, 20);
	ASSERT_NULL(ptr, "should return NULL for out of bounds access");

	ptr = ptr_at(data, data_end, 100, 1);
	ASSERT_NULL(ptr, "should return NULL when offset == size");

	TEST_PASS(test_name);
}

void test_cursor_reinit()
{
	const char *test_name = "cursor_reinit";
	uint8_t packet1[100] = {0};
	uint8_t packet2[200] = {0};
	struct xdp_md ctx = {
		.data = (uint64_t)packet1,
		.data_end = (uint64_t)(packet1 + sizeof(packet1)),
	};
	struct hdr_cursor cursor;

	cursor_init(&ctx, &cursor);
	ASSERT_EQ(cursor.pos, packet1, "initial cursor should point to packet1");

	/* Simulate packet modification (like bpf_xdp_adjust_head) */
	ctx.data = (uint64_t)packet2;
	ctx.data_end = (uint64_t)(packet2 + sizeof(packet2));

	cursor_reinit(&ctx, &cursor);
	ASSERT_EQ(cursor.pos, packet2, "reinitialized cursor should point to packet2");
	ASSERT_EQ(cursor.end, packet2 + sizeof(packet2), "cursor end should be updated");

	TEST_PASS(test_name);
}

void test_parse_multi_layer()
{
	const char *test_name = "multi-layer parsing (Eth + IPv4)";
	uint8_t packet[100] = {0};
	struct ethhdr *eth_hdr = (struct ethhdr *)packet;
	struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ethhdr));
	struct hdr_cursor cursor = {
		.pos = packet,
		.end = packet + sizeof(packet),
	};
	struct ethhdr *parsed_eth = NULL;
	struct iphdr *parsed_ip = NULL;
	int proto, ip_len;

	/* Create Ethernet header */
	eth_hdr->h_proto = htons(ETH_P_IP);

	/* Create IPv4 header */
	ip_hdr->version = 4;
	ip_hdr->ihl = 5;
	ip_hdr->protocol = IPPROTO_GRE;

	/* Parse Ethernet */
	proto = parse_ethhdr(&cursor, &parsed_eth);
	ASSERT_EQ(proto, ETH_P_IP, "should parse Ethernet header");

	/* Parse IPv4 */
	ip_len = parse_iphdr(&cursor, &parsed_ip);
	ASSERT_EQ(ip_len, 20, "should parse IPv4 header");
	ASSERT_EQ(cursor.pos, packet + sizeof(struct ethhdr) + 20, "cursor at correct position");

	TEST_PASS(test_name);
}

void test_parse_ipv6_after_eth()
{
	const char *test_name = "multi-layer parsing (Eth + IPv6)";
	uint8_t packet[100] = {0};
	struct ethhdr *eth_hdr = (struct ethhdr *)packet;
	struct ipv6hdr *ip6_hdr = (struct ipv6hdr *)(packet + sizeof(struct ethhdr));
	struct hdr_cursor cursor = {
		.pos = packet,
		.end = packet + sizeof(packet),
	};
	struct ethhdr *parsed_eth = NULL;
	struct ipv6hdr *parsed_ip6 = NULL;
	int proto, ip6_len;

	/* Create Ethernet header */
	eth_hdr->h_proto = htons(ETH_P_IPV6);

	/* Create IPv6 header */
	ip6_hdr->version = 6;
	ip6_hdr->nexthdr = IPPROTO_GRE;

	/* Parse Ethernet */
	proto = parse_ethhdr(&cursor, &parsed_eth);
	ASSERT_EQ(proto, ETH_P_IPV6, "should parse Ethernet header with IPv6");

	/* Parse IPv6 */
	ip6_len = parse_ipv6hdr(&cursor, &parsed_ip6);
	ASSERT_EQ(ip6_len, 40, "should parse IPv6 header");
	ASSERT_EQ(cursor.pos, packet + sizeof(struct ethhdr) + 40, "cursor at correct position");

	TEST_PASS(test_name);
}

void test_cursor_bounds_edge_cases()
{
	const char *test_name = "cursor bounds edge cases";
	uint8_t packet[100] = {0};
	struct hdr_cursor cursor = {
		.pos = packet,
		.end = packet + sizeof(packet),
	};

	/* Test exact boundary */
	cursor.pos = packet + 99;
	ASSERT(cursor_check(&cursor, 1), "should allow exactly 1 byte at boundary");
	ASSERT(!cursor_check(&cursor, 2), "should reject 2 bytes at boundary");

	/* Test zero length */
	cursor.pos = packet;
	ASSERT(cursor_check(&cursor, 0), "should allow zero length check");

	/* Test cursor at end */
	cursor.pos = packet + 100;
	ASSERT(!cursor_check(&cursor, 1), "should reject when cursor at end");
	ASSERT_EQ(cursor_remaining(&cursor), 0, "should have 0 bytes remaining");

	TEST_PASS(test_name);
}

void test_parse_iphdr_max_ihl()
{
	const char *test_name = "parse_iphdr - maximum IHL";
	uint8_t packet[100] = {0};
	struct iphdr *ip_hdr = (struct iphdr *)packet;
	struct hdr_cursor cursor = {
		.pos = packet,
		.end = packet + sizeof(packet),
	};
	struct iphdr *parsed_ip = NULL;
	int hdr_len;

	/* Create IPv4 header with maximum IHL (15 -> 60 bytes) */
	ip_hdr->version = 4;
	ip_hdr->ihl = 15;  /* 15 * 4 = 60 bytes (maximum) */

	hdr_len = parse_iphdr(&cursor, &parsed_ip);

	ASSERT_NOT_NULL(parsed_ip, "should parse IPv4 header with max IHL");
	ASSERT_EQ(hdr_len, 60, "should return 60 byte header length");
	ASSERT_EQ(cursor.pos, packet + 60, "cursor should advance 60 bytes");

	TEST_PASS(test_name);
}

/* ========== Main Test Runner ========== */

int main(void)
{
	printf("\n=== Parsing Helpers Unit Tests ===\n\n");

	/* Cursor operations */
	test_cursor_init();
	test_cursor_check();
	test_cursor_advance();
	test_cursor_remaining();
	test_cursor_reinit();
	test_cursor_bounds_edge_cases();

	/* Ethernet parsing */
	test_parse_ethhdr_valid();
	test_parse_ethhdr_truncated();

	/* IPv4 parsing */
	test_parse_iphdr_valid();
	test_parse_iphdr_with_options();
	test_parse_iphdr_invalid_ihl();
	test_parse_iphdr_truncated();
	test_parse_iphdr_max_ihl();
	test_peek_iphdr();

	/* IPv6 parsing */
	test_parse_ipv6hdr_valid();
	test_parse_ipv6hdr_invalid_version();
	test_parse_ipv6hdr_truncated();
	test_peek_ipv6hdr();

	/* Pointer utilities */
	test_ptr_is_valid();
	test_ptr_at_valid();
	test_ptr_at_out_of_bounds();

	/* Multi-layer parsing */
	test_parse_multi_layer();
	test_parse_ipv6_after_eth();

	/* Summary */
	printf("\n");
	printf("=================================\n");
	printf("Results: %d passed, %d failed\n", passed, failed);
	printf("=================================\n\n");

	return (failed > 0) ? 1 : 0;
}
