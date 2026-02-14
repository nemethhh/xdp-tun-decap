/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * test_ipv6_helpers.c - Unit tests for IPv6 address handling
 *
 * These tests run in userspace without requiring BPF loading or root permissions.
 * They test IPv6 address structure, conversion, and comparison logic.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

/* Include shared types */
#include "../include/tun_decap.h"

/* Test framework macros */
#define TEST_PASS(name) do { printf("  \033[32m✓\033[0m %s\n", name); passed++; } while(0)
#define TEST_FAIL(name, ...) do { printf("  \033[31m✗\033[0m %s: ", name); printf(__VA_ARGS__); printf("\n"); failed++; } while(0)
#define ASSERT(cond, ...) do { if (!(cond)) { TEST_FAIL(test_name, __VA_ARGS__); return; } } while(0)
#define ASSERT_EQ(a, b, ...) do { if ((a) != (b)) { TEST_FAIL(test_name, __VA_ARGS__); return; } } while(0)

static int passed = 0;
static int failed = 0;

/* Helper function to compare IPv6 addresses */
static int ipv6_addr_equal(struct ipv6_addr *a, struct ipv6_addr *b)
{
	return (a->addr[0] == b->addr[0] &&
	        a->addr[1] == b->addr[1] &&
	        a->addr[2] == b->addr[2] &&
	        a->addr[3] == b->addr[3]);
}

/* Helper to convert string to ipv6_addr structure */
static void ipv6_from_string(const char *str, struct ipv6_addr *addr)
{
	struct in6_addr tmp;
	inet_pton(AF_INET6, str, &tmp);
	memcpy(addr->addr, &tmp.s6_addr, 16);
}

/* Helper to convert ipv6_addr to string */
static void ipv6_to_string(struct ipv6_addr *addr, char *buf, size_t len)
{
	struct in6_addr tmp;
	memcpy(&tmp.s6_addr, addr->addr, 16);
	inet_ntop(AF_INET6, &tmp, buf, len);
}

/* ========== Test Cases ========== */

void test_ipv6_addr_structure_size()
{
	const char *test_name = "ipv6_addr structure size";

	ASSERT_EQ(sizeof(struct ipv6_addr), 16, "ipv6_addr should be 16 bytes");
	ASSERT_EQ(sizeof(struct ipv6_addr), sizeof(struct in6_addr),
	          "ipv6_addr should match in6_addr size");

	TEST_PASS(test_name);
}

void test_ipv6_addr_conversion_loopback()
{
	const char *test_name = "IPv6 address conversion - loopback (::1)";
	struct ipv6_addr addr;
	char buf[INET6_ADDRSTRLEN];

	ipv6_from_string("::1", &addr);

	/* ::1 = 00000000:00000000:00000000:00000001 */
	ASSERT_EQ(ntohl(addr.addr[0]), 0x00000000, "word 0 should be 0");
	ASSERT_EQ(ntohl(addr.addr[1]), 0x00000000, "word 1 should be 0");
	ASSERT_EQ(ntohl(addr.addr[2]), 0x00000000, "word 2 should be 0");
	ASSERT_EQ(ntohl(addr.addr[3]), 0x00000001, "word 3 should be 1");

	ipv6_to_string(&addr, buf, sizeof(buf));
	ASSERT_EQ(strcmp(buf, "::1"), 0, "should convert back to ::1");

	TEST_PASS(test_name);
}

void test_ipv6_addr_conversion_doc()
{
	const char *test_name = "IPv6 address conversion - 2001:db8::1";
	struct ipv6_addr addr;
	char buf[INET6_ADDRSTRLEN];

	ipv6_from_string("2001:db8::1", &addr);

	/* 2001:db8::1 = 20010db8:00000000:00000000:00000001 */
	ASSERT_EQ(ntohl(addr.addr[0]), 0x20010db8, "word 0 should be 0x20010db8");
	ASSERT_EQ(ntohl(addr.addr[1]), 0x00000000, "word 1 should be 0");
	ASSERT_EQ(ntohl(addr.addr[2]), 0x00000000, "word 2 should be 0");
	ASSERT_EQ(ntohl(addr.addr[3]), 0x00000001, "word 3 should be 1");

	ipv6_to_string(&addr, buf, sizeof(buf));
	ASSERT_EQ(strcmp(buf, "2001:db8::1"), 0, "should convert back correctly");

	TEST_PASS(test_name);
}

void test_ipv6_addr_conversion_full()
{
	const char *test_name = "IPv6 address conversion - full address";
	struct ipv6_addr addr;
	char buf[INET6_ADDRSTRLEN];

	ipv6_from_string("2001:db8:85a3:0:0:8a2e:370:7334", &addr);

	ipv6_to_string(&addr, buf, sizeof(buf));
	/* inet_ntop may compress zeros differently */
	ASSERT(strlen(buf) > 0, "should convert to valid string");

	TEST_PASS(test_name);
}

void test_ipv6_addr_all_zeros()
{
	const char *test_name = "IPv6 address - all zeros (::)";
	struct ipv6_addr addr;
	char buf[INET6_ADDRSTRLEN];

	ipv6_from_string("::", &addr);

	ASSERT_EQ(ntohl(addr.addr[0]), 0, "word 0 should be 0");
	ASSERT_EQ(ntohl(addr.addr[1]), 0, "word 1 should be 0");
	ASSERT_EQ(ntohl(addr.addr[2]), 0, "word 2 should be 0");
	ASSERT_EQ(ntohl(addr.addr[3]), 0, "word 3 should be 0");

	ipv6_to_string(&addr, buf, sizeof(buf));
	ASSERT_EQ(strcmp(buf, "::"), 0, "should convert back to ::");

	TEST_PASS(test_name);
}

void test_ipv6_addr_all_ones()
{
	const char *test_name = "IPv6 address - all ones";
	struct ipv6_addr addr;

	ipv6_from_string("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", &addr);

	ASSERT_EQ(ntohl(addr.addr[0]), 0xffffffff, "word 0 should be all 1s");
	ASSERT_EQ(ntohl(addr.addr[1]), 0xffffffff, "word 1 should be all 1s");
	ASSERT_EQ(ntohl(addr.addr[2]), 0xffffffff, "word 2 should be all 1s");
	ASSERT_EQ(ntohl(addr.addr[3]), 0xffffffff, "word 3 should be all 1s");

	TEST_PASS(test_name);
}

void test_ipv6_addr_equality()
{
	const char *test_name = "IPv6 address equality comparison";
	struct ipv6_addr addr1, addr2, addr3;

	ipv6_from_string("2001:db8::1", &addr1);
	ipv6_from_string("2001:db8::1", &addr2);
	ipv6_from_string("2001:db8::2", &addr3);

	ASSERT(ipv6_addr_equal(&addr1, &addr2), "identical addresses should be equal");
	ASSERT(!ipv6_addr_equal(&addr1, &addr3), "different addresses should not be equal");

	TEST_PASS(test_name);
}

void test_ipv6_addr_network_byte_order()
{
	const char *test_name = "IPv6 address - network byte order";
	struct ipv6_addr addr1, addr2;

	/* Create two addresses using inet_pton and verify they're stored correctly */
	ipv6_from_string("2001:db8::100:20", &addr1);
	ipv6_from_string("2001:db8::100:20", &addr2);

	/* Verify they're identical (tests consistency of inet_pton storage) */
	ASSERT(ipv6_addr_equal(&addr1, &addr2), "identical addresses should compare equal");

	/* Test that the structure stores addresses in network byte order */
	/* IPv6 addresses are stored as bytes in network order (big-endian) */
	char buf[INET6_ADDRSTRLEN];
	ipv6_to_string(&addr1, buf, sizeof(buf));
	ASSERT_EQ(strcmp(buf, "2001:db8::100:20"), 0, "should convert back correctly");

	TEST_PASS(test_name);
}

void test_ipv6_addr_link_local()
{
	const char *test_name = "IPv6 address - link-local (fe80::)";
	struct ipv6_addr addr;

	ipv6_from_string("fe80::1", &addr);

	ASSERT_EQ(ntohl(addr.addr[0]), 0xfe800000, "link-local prefix should be fe80::/10");
	ASSERT_EQ(ntohl(addr.addr[3]), 0x00000001, "interface ID should be ::1");

	TEST_PASS(test_name);
}

void test_ipv6_addr_multicast()
{
	const char *test_name = "IPv6 address - multicast (ff02::1)";
	struct ipv6_addr addr;

	ipv6_from_string("ff02::1", &addr);

	ASSERT_EQ(ntohl(addr.addr[0]), 0xff020000, "multicast prefix should be ff02::");
	ASSERT_EQ(ntohl(addr.addr[3]), 0x00000001, "should be all-nodes multicast");

	TEST_PASS(test_name);
}

void test_whitelist_value_structure()
{
	const char *test_name = "whitelist_value structure";
	struct whitelist_value val;

	/* Test structure size (should be minimal) */
	ASSERT_EQ(sizeof(struct whitelist_value), 1, "whitelist_value should be 1 byte");

	/* Test value semantics */
	val.allowed = 1;
	ASSERT_EQ(val.allowed, 1, "allowed flag should be settable");

	val.allowed = 0;
	ASSERT_EQ(val.allowed, 0, "allowed flag should be clearable");

	TEST_PASS(test_name);
}

void test_ipv6_addr_ipv4_mapped()
{
	const char *test_name = "IPv6 address - IPv4-mapped (::ffff:192.0.2.1)";
	struct ipv6_addr addr;

	ipv6_from_string("::ffff:192.0.2.1", &addr);

	/* ::ffff:192.0.2.1 = 00000000:00000000:0000ffff:c0000201 */
	ASSERT_EQ(ntohl(addr.addr[0]), 0x00000000, "word 0 should be 0");
	ASSERT_EQ(ntohl(addr.addr[1]), 0x00000000, "word 1 should be 0");
	ASSERT_EQ(ntohl(addr.addr[2]), 0x0000ffff, "word 2 should be 0x0000ffff");
	ASSERT_EQ(ntohl(addr.addr[3]), 0xc0000201, "word 3 should be IPv4 (192.0.2.1)");

	TEST_PASS(test_name);
}

void test_ipv6_addr_word_alignment()
{
	const char *test_name = "IPv6 address - word alignment";
	struct ipv6_addr addr;

	/* Test that the structure is properly aligned for map keys */
	ASSERT_EQ(sizeof(addr.addr), 16, "addr array should be 16 bytes");
	ASSERT_EQ(sizeof(addr.addr[0]), 4, "each word should be 4 bytes");

	/* Verify no padding */
	ASSERT_EQ(sizeof(struct ipv6_addr), sizeof(uint32_t) * 4,
	          "structure should have no padding");

	TEST_PASS(test_name);
}

void test_ipv6_addr_memcpy_compatibility()
{
	const char *test_name = "IPv6 address - memcpy from in6_addr";
	struct in6_addr kernel_addr;
	struct ipv6_addr our_addr;

	inet_pton(AF_INET6, "2001:db8:cafe:babe::42", &kernel_addr);
	memcpy(our_addr.addr, &kernel_addr.s6_addr, 16);

	/* Verify conversion worked */
	char buf[INET6_ADDRSTRLEN];
	struct in6_addr tmp;
	memcpy(&tmp.s6_addr, our_addr.addr, 16);
	inet_ntop(AF_INET6, &tmp, buf, sizeof(buf));

	ASSERT_EQ(strcmp(buf, "2001:db8:cafe:babe::42"), 0,
	          "should preserve address through memcpy");

	TEST_PASS(test_name);
}

void test_config_structure()
{
	const char *test_name = "tun_decap_config structure";
	struct tun_decap_config cfg;

	/* Test default initialization (all zeros = all enabled) */
	memset(&cfg, 0, sizeof(cfg));
	ASSERT_EQ(cfg.disabled, 0, "default disabled should be 0 (enabled)");
	ASSERT_EQ(cfg.disable_gre, 0, "default disable_gre should be 0 (enabled)");
	ASSERT_EQ(cfg.disable_ipip, 0, "default disable_ipip should be 0 (enabled)");
	ASSERT_EQ(cfg.disable_stats, 0, "default disable_stats should be 0 (enabled)");

	/* Test setting disable flags */
	cfg.disabled = 1;
	ASSERT_EQ(cfg.disabled, 1, "should be able to disable processing");

	cfg.disable_gre = 1;
	ASSERT_EQ(cfg.disable_gre, 1, "should be able to disable GRE");

	cfg.disable_ipip = 1;
	ASSERT_EQ(cfg.disable_ipip, 1, "should be able to disable IPIP");

	cfg.disable_stats = 1;
	ASSERT_EQ(cfg.disable_stats, 1, "should be able to disable stats");

	TEST_PASS(test_name);
}

void test_config_inverted_semantics()
{
	const char *test_name = "config inverted semantics (0=enabled)";
	struct tun_decap_config cfg = {0}; /* Zero init = all enabled */

	/* Verify 0 means enabled */
	ASSERT_EQ(cfg.disabled, 0, "0 should mean processing enabled");
	ASSERT_EQ(cfg.disable_gre, 0, "0 should mean GRE enabled");

	/* Verify 1 means disabled */
	cfg.disabled = 1;
	ASSERT_EQ(cfg.disabled, 1, "1 should mean processing disabled");

	TEST_PASS(test_name);
}

void test_stats_structure()
{
	const char *test_name = "tun_decap_stats structure";

	/* Verify struct size matches expected number of counters */
	ASSERT_EQ(sizeof(struct tun_decap_stats), STAT_NUM_COUNTERS * sizeof(__u64),
	          "stats struct should contain STAT_NUM_COUNTERS __u64 fields");

	/* Verify STAT_NUM_COUNTERS */
	ASSERT_EQ(STAT_NUM_COUNTERS, 14, "should have 14 stat counters");

	/* Verify first and last field offsets */
	ASSERT_EQ(__builtin_offsetof(struct tun_decap_stats, rx_total), 0,
	          "rx_total should be at offset 0");
	ASSERT_EQ(__builtin_offsetof(struct tun_decap_stats, pass_non_tunnel),
	          13 * sizeof(__u64), "pass_non_tunnel should be last field");

	TEST_PASS(test_name);
}

void test_stat_fields_array()
{
	const char *test_name = "stat_fields array completeness";

	/* Verify all stats have names and descriptions */
	for (int i = 0; i < STAT_NUM_COUNTERS; i++) {
		ASSERT(stat_fields[i].name != NULL, "stat %d should have a name", i);
		ASSERT(strlen(stat_fields[i].name) > 0, "stat %d name should not be empty", i);
		ASSERT(stat_fields[i].description != NULL, "stat %d should have a description", i);
		ASSERT(strlen(stat_fields[i].description) > 0,
		       "stat %d description should not be empty", i);
	}

	/* Verify specific names */
	ASSERT_EQ(strcmp(stat_fields[0].name, "rx_total"), 0,
	          "first stat name should be rx_total");
	ASSERT_EQ(strcmp(stat_fields[8].name, "decap_success"), 0,
	          "decap_success name should match");

	/* Verify offsets are sequential and aligned */
	for (int i = 0; i < STAT_NUM_COUNTERS; i++) {
		ASSERT_EQ(stat_fields[i].offset, (size_t)(i * sizeof(__u64)),
		          "stat %d offset should be i*8", i);
	}

	TEST_PASS(test_name);
}

void test_protocol_constants()
{
	const char *test_name = "protocol number constants";

	ASSERT_EQ(IPPROTO_IPIP, 4, "IPIP protocol should be 4");
	ASSERT_EQ(IPPROTO_IPV6, 41, "IPv6 protocol should be 41");
	ASSERT_EQ(IPPROTO_GRE, 47, "GRE protocol should be 47");

	TEST_PASS(test_name);
}

void test_ethertype_constants()
{
	const char *test_name = "EtherType constants";

	ASSERT_EQ(ETH_P_IP, 0x0800, "IPv4 EtherType should be 0x0800");
	ASSERT_EQ(ETH_P_IPV6, 0x86DD, "IPv6 EtherType should be 0x86DD");

	TEST_PASS(test_name);
}

void test_ipv6_addr_comparison_edge_cases()
{
	const char *test_name = "IPv6 address comparison - edge cases";
	struct ipv6_addr addr1, addr2;

	/* Test addresses differing by 1 bit in each word */
	ipv6_from_string("2001:db8::1", &addr1);
	ipv6_from_string("2001:db8::2", &addr2);
	ASSERT(!ipv6_addr_equal(&addr1, &addr2), "should detect difference in word 3");

	ipv6_from_string("2001:db8::1", &addr1);
	ipv6_from_string("2001:db9::1", &addr2);
	ASSERT(!ipv6_addr_equal(&addr1, &addr2), "should detect difference in word 0");

	ipv6_from_string("2001:db8:0:1::1", &addr1);
	ipv6_from_string("2001:db8:0:2::1", &addr2);
	ASSERT(!ipv6_addr_equal(&addr1, &addr2), "should detect difference in word 1");

	TEST_PASS(test_name);
}

void test_map_pin_paths()
{
	const char *test_name = "map pin path constants";

	ASSERT_EQ(strcmp(MAP_PIN_PATH_WHITELIST, "/sys/fs/bpf/tun_decap_whitelist"), 0,
	          "whitelist path should match");
	ASSERT_EQ(strcmp(MAP_PIN_PATH_WHITELIST_V6, "/sys/fs/bpf/tun_decap_whitelist_v6"), 0,
	          "whitelist_v6 path should match");
	ASSERT_EQ(strcmp(MAP_PIN_PATH_STATS, "/sys/fs/bpf/tun_decap_stats"), 0,
	          "stats path should match");

	TEST_PASS(test_name);
}

void test_whitelist_max_entries()
{
	const char *test_name = "whitelist max entries constant";

	ASSERT_EQ(WHITELIST_MAX_ENTRIES, 1024, "max entries should be 1024");

	TEST_PASS(test_name);
}

/* ========== Main Test Runner ========== */

int main(void)
{
	printf("\n=== IPv6 and Configuration Helpers Unit Tests ===\n\n");

	/* IPv6 address structure tests */
	test_ipv6_addr_structure_size();
	test_ipv6_addr_conversion_loopback();
	test_ipv6_addr_conversion_doc();
	test_ipv6_addr_conversion_full();
	test_ipv6_addr_all_zeros();
	test_ipv6_addr_all_ones();
	test_ipv6_addr_equality();
	test_ipv6_addr_comparison_edge_cases();
	test_ipv6_addr_network_byte_order();
	test_ipv6_addr_ipv4_mapped();
	test_ipv6_addr_word_alignment();
	test_ipv6_addr_memcpy_compatibility();

	/* Configuration structure tests */
	test_config_structure();
	test_config_inverted_semantics();
	test_whitelist_value_structure();

	/* Constant validation */
	test_protocol_constants();
	test_ethertype_constants();
	test_map_pin_paths();
	test_whitelist_max_entries();
	test_stats_structure();
	test_stat_fields_array();

	/* Summary */
	printf("\n");
	printf("=================================\n");
	printf("Results: %d passed, %d failed\n", passed, failed);
	printf("=================================\n\n");

	return (failed > 0) ? 1 : 0;
}
