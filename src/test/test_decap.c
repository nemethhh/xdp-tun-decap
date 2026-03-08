// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * test_decap.c - Unit tests for XDP tunnel decapsulation program
 *
 * Uses BPF_PROG_TEST_RUN to verify decapsulation logic with
 * pre-crafted test packets.
 *
 * Run with: sudo ./test_decap
 */

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_packets.h"
#include "tun_decap.h"
#include "tun_decap.skel.h"

/* Test result tracking */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

/* Colors for output */
#define COLOR_RED    "\033[31m"
#define COLOR_GREEN  "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_RESET  "\033[0m"

#define TEST_PASS(name)                                                                            \
	do {                                                                                       \
		tests_run++;                                                                       \
		tests_passed++;                                                                    \
		printf(COLOR_GREEN "[PASS]" COLOR_RESET " %s\n", name);                            \
	} while (0)

#define TEST_FAIL(name, reason)                                                                    \
	do {                                                                                       \
		tests_run++;                                                                       \
		tests_failed++;                                                                    \
		printf(COLOR_RED "[FAIL]" COLOR_RESET " %s: %s\n", name, reason);                  \
	} while (0)

#define TEST_SKIP(name, reason)                                                                    \
	do {                                                                                       \
		printf(COLOR_YELLOW "[SKIP]" COLOR_RESET " %s: %s\n", name, reason);               \
	} while (0)

/*
 * Run XDP program with test packet using BPF_PROG_TEST_RUN
 *
 * @prog_fd: BPF program file descriptor
 * @pkt: Input packet data
 * @pkt_len: Input packet length
 * @retval: Output - XDP return value
 * @data_out: Output buffer for modified packet (can be NULL)
 * @data_out_len: In/out - buffer size / actual output length
 * @return: 0 on success, negative errno on failure
 */
static int run_xdp_test(int prog_fd, void *pkt, size_t pkt_len, __u32 *retval, void *data_out,
                        size_t *data_out_len)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = pkt, .data_size_in = pkt_len,
	            .data_out = data_out, .data_size_out = data_out_len ? *data_out_len : 0,
	            .repeat = 1, );

	int err = bpf_prog_test_run_opts(prog_fd, &opts);
	if (err < 0)
		return err;

	*retval = opts.retval;
	if (data_out_len)
		*data_out_len = opts.data_size_out;

	return 0;
}

#ifdef ENABLE_WHITELIST
/*
 * Add IPv4 address to whitelist map
 *
 * Uses BPF_MAP_TYPE_HASH (not PERCPU), so a single value suffices.
 */
static int whitelist_add(int map_fd, __u32 ip_be)
{
	struct whitelist_value val = { .allowed = 1 };
	return bpf_map_update_elem(map_fd, &ip_be, &val, BPF_ANY);
}

/*
 * Add IPv6 address to whitelist map
 *
 * @map_fd: IPv6 whitelist map file descriptor
 * @ip6_addr: IPv6 address as array of 4x 32-bit words (network byte order)
 */
static int whitelist_v6_add(int map_fd, const __u32 ip6_addr[4])
{
	struct whitelist_value val = { .allowed = 1 };
	struct ipv6_addr key;

	key.addr[0] = ip6_addr[0];
	key.addr[1] = ip6_addr[1];
	key.addr[2] = ip6_addr[2];
	key.addr[3] = ip6_addr[3];

	return bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
}

/*
 * Clear whitelist map (IPv4)
 */
static int whitelist_clear(int map_fd)
{
	__u32 key, next_key;

	if (bpf_map_get_next_key(map_fd, NULL, &key) != 0)
		return 0; /* Map is empty */

	while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
		bpf_map_delete_elem(map_fd, &key);
		key = next_key;
	}
	bpf_map_delete_elem(map_fd, &key);

	return 0;
}

/*
 * Clear IPv6 whitelist map
 */
static int whitelist_v6_clear(int map_fd)
{
	struct ipv6_addr key, next_key;

	if (bpf_map_get_next_key(map_fd, NULL, &key) != 0)
		return 0; /* Map is empty */

	while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
		bpf_map_delete_elem(map_fd, &key);
		key = next_key;
	}
	bpf_map_delete_elem(map_fd, &key);

	return 0;
}
#endif /* ENABLE_WHITELIST */

#ifdef ENABLE_STATS
/*
 * Read and aggregate a specific stat field from per-CPU stats struct
 *
 * @map_fd: Stats map file descriptor
 * @offset: Byte offset of the __u64 field within tun_decap_stats
 * @return: Aggregated value across all CPUs
 */
static __u64 read_stat_field(int map_fd, size_t offset)
{
	int ncpus = libbpf_num_possible_cpus();
	struct tun_decap_stats values[ncpus];
	__u32 key = 0;
	__u64 total = 0;

	if (bpf_map_lookup_elem(map_fd, &key, values) < 0)
		return 0;

	for (int i = 0; i < ncpus; i++)
		total += *(__u64 *)((char *)&values[i] + offset);

	return total;
}

/*
 * Convenience macros for reading specific stats
 */
#define read_stat(map_fd, field) \
	read_stat_field(map_fd, __builtin_offsetof(struct tun_decap_stats, field))

/*
 * Reset all statistics to zero
 */
static void reset_stats(int map_fd)
{
	int ncpus = libbpf_num_possible_cpus();
	struct tun_decap_stats zeros[ncpus];
	__u32 key = 0;

	memset(zeros, 0, sizeof(zeros));
	bpf_map_update_elem(map_fd, &key, zeros, BPF_ANY);
}
#endif /* ENABLE_STATS */

/*
 * Test: GRE decapsulation with whitelisted source
 */
static void test_gre_whitelisted(struct tun_decap_bpf *skel)
{
	const char *name = "GRE decap (whitelisted)";
	int prog_fd = bpf_program__fd(skel->progs.xdp_tun_decap);
	__u32 retval;
	unsigned char data_out[256];
	size_t data_out_len = sizeof(data_out);
	int err;

#ifdef ENABLE_WHITELIST
	/* Add whitelisted IP (use little-endian representation for x86) */
	int wl_fd = bpf_map__fd(skel->maps.tun_decap_whitelist);
	err = whitelist_add(wl_fd, TEST_IP_WHITELISTED_1);
	if (err < 0) {
		TEST_FAIL(name, "Failed to add whitelist entry");
		return;
	}
#endif

	/* Run test */
	err = run_xdp_test(prog_fd, pkt_gre_whitelisted, PKT_GRE_WHITELISTED_LEN, &retval, data_out,
	                   &data_out_len);
	if (err < 0) {
		TEST_FAIL(name, "bpf_prog_test_run failed");
		return;
	}

	/* Verify XDP_PASS */
	if (retval != XDP_PASS) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected XDP_PASS(%d), got %d", XDP_PASS, retval);
		TEST_FAIL(name, buf);
		return;
	}

	/* Verify decapsulation - packet should be smaller */
	if (data_out_len != PKT_GRE_WHITELISTED_DECAP_LEN) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected len=%zu, got %zu",
		         (size_t)PKT_GRE_WHITELISTED_DECAP_LEN, data_out_len);
		TEST_FAIL(name, buf);
		return;
	}

	/* Verify inner IP header is now at correct position */
	struct ethhdr *eth = (struct ethhdr *)data_out;
	struct iphdr *iph = (struct iphdr *)(eth + 1);

	if (iph->saddr != htonl(0xac100001)) { /* 172.16.0.1 */
		TEST_FAIL(name, "Inner source IP mismatch");
		return;
	}

	TEST_PASS(name);
}

#ifdef ENABLE_WHITELIST
/*
 * Test: GRE packet from non-whitelisted source should be dropped
 */
static void test_gre_blocked(struct tun_decap_bpf *skel)
{
	const char *name = "GRE drop (non-whitelisted)";
	int prog_fd = bpf_program__fd(skel->progs.xdp_tun_decap);
	int wl_fd = bpf_map__fd(skel->maps.tun_decap_whitelist);
	__u32 retval;
	int err;

	/* Clear whitelist - ensure blocked IP is not there */
	whitelist_clear(wl_fd);
	/* Re-add only 10.0.0.x, not 11.0.0.x */
	whitelist_add(wl_fd, TEST_IP_WHITELISTED_1);

#ifdef ENABLE_STATS
	int stats_fd = bpf_map__fd(skel->maps.tun_decap_stats);
	__u64 drops_before = read_stat(stats_fd, drop_not_whitelisted);
#endif

	/* Run test with packet from 11.0.0.1 */
	err = run_xdp_test(prog_fd, pkt_gre_blocked, PKT_GRE_BLOCKED_LEN, &retval, NULL, NULL);
	if (err < 0) {
		TEST_FAIL(name, "bpf_prog_test_run failed");
		return;
	}

	/* Verify XDP_DROP */
	if (retval != XDP_DROP) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected XDP_DROP(%d), got %d", XDP_DROP, retval);
		TEST_FAIL(name, buf);
		return;
	}

#ifdef ENABLE_STATS
	/* Verify drop counter incremented */
	__u64 drops_after = read_stat(stats_fd, drop_not_whitelisted);
	if (drops_after <= drops_before) {
		TEST_FAIL(name, "Drop counter not incremented");
		return;
	}
#endif

	TEST_PASS(name);
}
#endif /* ENABLE_WHITELIST */

/*
 * Test: GRE packet with Key option
 */
static void test_gre_with_key(struct tun_decap_bpf *skel)
{
	const char *name = "GRE decap (with key option)";
	int prog_fd = bpf_program__fd(skel->progs.xdp_tun_decap);
	__u32 retval;
	unsigned char data_out[256];
	size_t data_out_len = sizeof(data_out);
	int err;

#ifdef ENABLE_WHITELIST
	/* Add whitelisted IP (10.0.0.2) */
	int wl_fd = bpf_map__fd(skel->maps.tun_decap_whitelist);
	whitelist_add(wl_fd, TEST_IP_WHITELISTED_2);
#endif

	/* Run test */
	err = run_xdp_test(prog_fd, pkt_gre_with_key, PKT_GRE_WITH_KEY_LEN, &retval, data_out,
	                   &data_out_len);
	if (err < 0) {
		TEST_FAIL(name, "bpf_prog_test_run failed");
		return;
	}

	if (retval != XDP_PASS) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected XDP_PASS, got %d", retval);
		TEST_FAIL(name, buf);
		return;
	}

	/* Verify correct decap length (outer IP + GRE with key = 20 + 8) */
	if (data_out_len != PKT_GRE_WITH_KEY_DECAP_LEN) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected len=%zu, got %zu",
		         (size_t)PKT_GRE_WITH_KEY_DECAP_LEN, data_out_len);
		TEST_FAIL(name, buf);
		return;
	}

	TEST_PASS(name);
}

/*
 * Test: IPIP decapsulation with whitelisted source
 */
static void test_ipip_whitelisted(struct tun_decap_bpf *skel)
{
	const char *name = "IPIP decap (whitelisted)";
	int prog_fd = bpf_program__fd(skel->progs.xdp_tun_decap);
	__u32 retval;
	unsigned char data_out[256];
	size_t data_out_len = sizeof(data_out);
	int err;

#ifdef ENABLE_WHITELIST
	/* Add whitelisted IP */
	int wl_fd = bpf_map__fd(skel->maps.tun_decap_whitelist);
	whitelist_add(wl_fd, TEST_IP_WHITELISTED_2);
#endif

	/* Run test */
	err = run_xdp_test(prog_fd, pkt_ipip_whitelisted, PKT_IPIP_WHITELISTED_LEN, &retval,
	                   data_out, &data_out_len);
	if (err < 0) {
		TEST_FAIL(name, "bpf_prog_test_run failed");
		return;
	}

	if (retval != XDP_PASS) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected XDP_PASS, got %d", retval);
		TEST_FAIL(name, buf);
		return;
	}

	/* IPIP: only outer IP removed (20 bytes) */
	if (data_out_len != PKT_IPIP_WHITELISTED_DECAP_LEN) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected len=%zu, got %zu",
		         (size_t)PKT_IPIP_WHITELISTED_DECAP_LEN, data_out_len);
		TEST_FAIL(name, buf);
		return;
	}

	TEST_PASS(name);
}

#ifdef ENABLE_WHITELIST
/*
 * Test: IPIP packet from non-whitelisted source
 */
static void test_ipip_blocked(struct tun_decap_bpf *skel)
{
	const char *name = "IPIP drop (non-whitelisted)";
	int prog_fd = bpf_program__fd(skel->progs.xdp_tun_decap);
	__u32 retval;
	int err;

	err = run_xdp_test(prog_fd, pkt_ipip_blocked, PKT_IPIP_BLOCKED_LEN, &retval, NULL, NULL);
	if (err < 0) {
		TEST_FAIL(name, "bpf_prog_test_run failed");
		return;
	}

	if (retval != XDP_DROP) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected XDP_DROP, got %d", retval);
		TEST_FAIL(name, buf);
		return;
	}

	TEST_PASS(name);
}
#endif /* ENABLE_WHITELIST */

/*
 * Test: Non-tunnel TCP traffic passes through unchanged
 */
static void test_tcp_passthrough(struct tun_decap_bpf *skel)
{
	const char *name = "TCP passthrough (non-tunnel)";
	int prog_fd = bpf_program__fd(skel->progs.xdp_tun_decap);
	__u32 retval;
	unsigned char data_out[256];
	size_t data_out_len = sizeof(data_out);
	int err;

	err = run_xdp_test(prog_fd, pkt_tcp_normal, PKT_TCP_NORMAL_LEN, &retval, data_out,
	                   &data_out_len);
	if (err < 0) {
		TEST_FAIL(name, "bpf_prog_test_run failed");
		return;
	}

	if (retval != XDP_PASS) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected XDP_PASS, got %d", retval);
		TEST_FAIL(name, buf);
		return;
	}

	/* Packet should be unchanged */
	if (data_out_len != PKT_TCP_NORMAL_LEN) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Packet length changed: %zu -> %zu",
		         (size_t)PKT_TCP_NORMAL_LEN, data_out_len);
		TEST_FAIL(name, buf);
		return;
	}

	/* Verify content unchanged */
	if (memcmp(pkt_tcp_normal, data_out, PKT_TCP_NORMAL_LEN) != 0) {
		TEST_FAIL(name, "Packet content modified");
		return;
	}

	TEST_PASS(name);
}

/*
 * Test: UDP traffic passes through unchanged
 */
static void test_udp_passthrough(struct tun_decap_bpf *skel)
{
	const char *name = "UDP passthrough (non-tunnel)";
	int prog_fd = bpf_program__fd(skel->progs.xdp_tun_decap);
	__u32 retval;
	unsigned char data_out[256];
	size_t data_out_len = sizeof(data_out);
	int err;

	err = run_xdp_test(prog_fd, pkt_udp_normal, PKT_UDP_NORMAL_LEN, &retval, data_out,
	                   &data_out_len);
	if (err < 0) {
		TEST_FAIL(name, "bpf_prog_test_run failed");
		return;
	}

	if (retval != XDP_PASS) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected XDP_PASS, got %d", retval);
		TEST_FAIL(name, buf);
		return;
	}

	if (data_out_len != PKT_UDP_NORMAL_LEN) {
		TEST_FAIL(name, "Packet length changed");
		return;
	}

	TEST_PASS(name);
}

/*
 * Test: IPv6 traffic passes through unchanged
 */
static void test_ipv6_passthrough(struct tun_decap_bpf *skel)
{
	const char *name = "IPv6 passthrough";
	int prog_fd = bpf_program__fd(skel->progs.xdp_tun_decap);
	__u32 retval;
	unsigned char data_out[256];
	size_t data_out_len = sizeof(data_out);
	int err;

	err = run_xdp_test(prog_fd, pkt_ipv6, PKT_IPV6_LEN, &retval, data_out, &data_out_len);
	if (err < 0) {
		TEST_FAIL(name, "bpf_prog_test_run failed");
		return;
	}

	if (retval != XDP_PASS) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected XDP_PASS, got %d", retval);
		TEST_FAIL(name, buf);
		return;
	}

	if (data_out_len != PKT_IPV6_LEN) {
		TEST_FAIL(name, "Packet length changed");
		return;
	}

	TEST_PASS(name);
}

/*
 * Test: Truncated GRE packet is dropped
 */
static void test_gre_truncated(struct tun_decap_bpf *skel)
{
	const char *name = "GRE drop (truncated)";
	int prog_fd = bpf_program__fd(skel->progs.xdp_tun_decap);
	__u32 retval;
	int err;

#ifdef ENABLE_WHITELIST
	/* Add to whitelist so we test the malformed check, not whitelist */
	int wl_fd = bpf_map__fd(skel->maps.tun_decap_whitelist);
	whitelist_add(wl_fd, TEST_IP_WHITELISTED_1);
#endif

	err = run_xdp_test(prog_fd, pkt_gre_truncated, PKT_GRE_TRUNCATED_LEN, &retval, NULL, NULL);
	if (err < 0) {
		TEST_FAIL(name, "bpf_prog_test_run failed");
		return;
	}

	if (retval != XDP_DROP) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected XDP_DROP, got %d", retval);
		TEST_FAIL(name, buf);
		return;
	}

	TEST_PASS(name);
}

/*
 * Test: GRE with IPv6 inner packet decapsulation
 */
static void test_gre_ipv6_inner(struct tun_decap_bpf *skel)
{
	const char *name = "GRE decap (IPv6 inner)";
	int prog_fd = bpf_program__fd(skel->progs.xdp_tun_decap);
	__u32 retval;
	unsigned char data_out[256];
	size_t data_out_len = sizeof(data_out);
	int err;

#ifdef ENABLE_WHITELIST
	/* Add whitelisted IP */
	int wl_fd = bpf_map__fd(skel->maps.tun_decap_whitelist);
	whitelist_add(wl_fd, TEST_IP_WHITELISTED_1);
#endif

	/* Run test */
	err = run_xdp_test(prog_fd, pkt_gre_ipv6_inner, PKT_GRE_IPV6_INNER_LEN, &retval, data_out,
	                   &data_out_len);
	if (err < 0) {
		TEST_FAIL(name, "bpf_prog_test_run failed");
		return;
	}

	/* Verify XDP_PASS */
	if (retval != XDP_PASS) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected XDP_PASS, got %d", retval);
		TEST_FAIL(name, buf);
		return;
	}

	/* Verify decapsulation */
	if (data_out_len != PKT_GRE_IPV6_INNER_DECAP_LEN) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected len=%zu, got %zu",
		         (size_t)PKT_GRE_IPV6_INNER_DECAP_LEN, data_out_len);
		TEST_FAIL(name, buf);
		return;
	}

	/* Verify EtherType is now IPv6 */
	struct ethhdr *eth = (struct ethhdr *)data_out;
	if (eth->h_proto != htons(0x86DD)) {
		TEST_FAIL(name, "EtherType not set to IPv6");
		return;
	}

	TEST_PASS(name);
}

/*
 * Test: IPv6-in-IPv4 (protocol 41) decapsulation
 */
static void test_ipv6_in_ipv4(struct tun_decap_bpf *skel)
{
	const char *name = "IPv6-in-IPv4 decap (proto 41)";
	int prog_fd = bpf_program__fd(skel->progs.xdp_tun_decap);
	__u32 retval;
	unsigned char data_out[256];
	size_t data_out_len = sizeof(data_out);
	int err;

#ifdef ENABLE_WHITELIST
	/* Add whitelisted IP */
	int wl_fd = bpf_map__fd(skel->maps.tun_decap_whitelist);
	whitelist_add(wl_fd, TEST_IP_WHITELISTED_2);
#endif

	/* Run test */
	err = run_xdp_test(prog_fd, pkt_ipv6_in_ipv4, PKT_IPV6_IN_IPV4_LEN, &retval, data_out,
	                   &data_out_len);
	if (err < 0) {
		TEST_FAIL(name, "bpf_prog_test_run failed");
		return;
	}

	/* Verify XDP_PASS */
	if (retval != XDP_PASS) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected XDP_PASS, got %d", retval);
		TEST_FAIL(name, buf);
		return;
	}

	/* Verify decapsulation */
	if (data_out_len != PKT_IPV6_IN_IPV4_DECAP_LEN) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected len=%zu, got %zu",
		         (size_t)PKT_IPV6_IN_IPV4_DECAP_LEN, data_out_len);
		TEST_FAIL(name, buf);
		return;
	}

	/* Verify EtherType is now IPv6 */
	struct ethhdr *eth = (struct ethhdr *)data_out;
	if (eth->h_proto != htons(0x86DD)) {
		TEST_FAIL(name, "EtherType not set to IPv6");
		return;
	}

	TEST_PASS(name);
}

/*
 * Test: IPv6 outer header + GRE + IPv4 inner (whitelisted)
 */
static void test_ipv6_outer_gre_ipv4(struct tun_decap_bpf *skel)
{
	const char *name = "IPv6 outer + GRE + IPv4 inner (whitelisted)";
	int prog_fd = bpf_program__fd(skel->progs.xdp_tun_decap);
	__u32 retval;
	unsigned char data_out[256];
	size_t data_out_len = sizeof(data_out);
	int err;

#ifdef ENABLE_WHITELIST
	/* Add IPv6 source (2001:db8::1) to whitelist */
	int wl_v6_fd = bpf_map__fd(skel->maps.tun_decap_whitelist_v6);
	__u32 ipv6_addr[] = TEST_IPV6_WHITELISTED_1;
	err = whitelist_v6_add(wl_v6_fd, ipv6_addr);
	if (err < 0) {
		TEST_FAIL(name, "Failed to add IPv6 to whitelist");
		return;
	}
#endif

	/* Run test */
	err = run_xdp_test(prog_fd, pkt_ipv6_outer_gre_ipv4, PKT_IPV6_OUTER_GRE_IPV4_LEN, &retval,
	                   data_out, &data_out_len);
	if (err < 0) {
		TEST_FAIL(name, "bpf_prog_test_run failed");
		return;
	}

	/* Verify XDP_PASS */
	if (retval != XDP_PASS) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected XDP_PASS, got %d", retval);
		TEST_FAIL(name, buf);
		return;
	}

	/* Verify decapsulation */
	if (data_out_len != PKT_IPV6_OUTER_GRE_IPV4_DECAP_LEN) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected len=%zu, got %zu",
		         (size_t)PKT_IPV6_OUTER_GRE_IPV4_DECAP_LEN, data_out_len);
		TEST_FAIL(name, buf);
		return;
	}

	/* Verify EtherType is IPv4 */
	struct ethhdr *eth = (struct ethhdr *)data_out;
	if (eth->h_proto != htons(0x0800)) {
		TEST_FAIL(name, "EtherType not set to IPv4");
		return;
	}

	TEST_PASS(name);
}

/*
 * Test: IPv4-in-IPv6 decapsulation (whitelisted)
 */
static void test_ipv4_in_ipv6(struct tun_decap_bpf *skel)
{
	const char *name = "IPv4-in-IPv6 decap (whitelisted)";
	int prog_fd = bpf_program__fd(skel->progs.xdp_tun_decap);
	__u32 retval;
	unsigned char data_out[256];
	size_t data_out_len = sizeof(data_out);
	int err;

#ifdef ENABLE_WHITELIST
	/* Add IPv6 source (2001:db8::2) to whitelist */
	int wl_v6_fd = bpf_map__fd(skel->maps.tun_decap_whitelist_v6);
	__u32 ipv6_addr[] = TEST_IPV6_WHITELISTED_2;
	err = whitelist_v6_add(wl_v6_fd, ipv6_addr);
	if (err < 0) {
		TEST_FAIL(name, "Failed to add IPv6 to whitelist");
		return;
	}
#endif

	/* Run test */
	err = run_xdp_test(prog_fd, pkt_ipv4_in_ipv6, PKT_IPV4_IN_IPV6_LEN, &retval, data_out,
	                   &data_out_len);
	if (err < 0) {
		TEST_FAIL(name, "bpf_prog_test_run failed");
		return;
	}

	/* Verify XDP_PASS */
	if (retval != XDP_PASS) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected XDP_PASS, got %d", retval);
		TEST_FAIL(name, buf);
		return;
	}

	/* Verify decapsulation */
	if (data_out_len != PKT_IPV4_IN_IPV6_DECAP_LEN) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected len=%zu, got %zu",
		         (size_t)PKT_IPV4_IN_IPV6_DECAP_LEN, data_out_len);
		TEST_FAIL(name, buf);
		return;
	}

	/* Verify EtherType is IPv4 */
	struct ethhdr *eth = (struct ethhdr *)data_out;
	if (eth->h_proto != htons(0x0800)) {
		TEST_FAIL(name, "EtherType not set to IPv4");
		return;
	}

	TEST_PASS(name);
}

/*
 * Test: IPv6-in-IPv6 decapsulation (whitelisted)
 */
static void test_ipv6_in_ipv6(struct tun_decap_bpf *skel)
{
	const char *name = "IPv6-in-IPv6 decap (whitelisted)";
	int prog_fd = bpf_program__fd(skel->progs.xdp_tun_decap);
	__u32 retval;
	unsigned char data_out[256];
	size_t data_out_len = sizeof(data_out);
	int err;

#ifdef ENABLE_WHITELIST
	/* Add IPv6 source (2001:db8::3) to whitelist */
	int wl_v6_fd = bpf_map__fd(skel->maps.tun_decap_whitelist_v6);
	__u32 ipv6_addr[] = TEST_IPV6_WHITELISTED_3;
	err = whitelist_v6_add(wl_v6_fd, ipv6_addr);
	if (err < 0) {
		TEST_FAIL(name, "Failed to add IPv6 to whitelist");
		return;
	}
#endif

	/* Run test */
	err = run_xdp_test(prog_fd, pkt_ipv6_in_ipv6, PKT_IPV6_IN_IPV6_LEN, &retval, data_out,
	                   &data_out_len);
	if (err < 0) {
		TEST_FAIL(name, "bpf_prog_test_run failed");
		return;
	}

	/* Verify XDP_PASS */
	if (retval != XDP_PASS) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected XDP_PASS, got %d", retval);
		TEST_FAIL(name, buf);
		return;
	}

	/* Verify decapsulation */
	if (data_out_len != PKT_IPV6_IN_IPV6_DECAP_LEN) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected len=%zu, got %zu",
		         (size_t)PKT_IPV6_IN_IPV6_DECAP_LEN, data_out_len);
		TEST_FAIL(name, buf);
		return;
	}

	/* Verify EtherType is IPv6 */
	struct ethhdr *eth = (struct ethhdr *)data_out;
	if (eth->h_proto != htons(0x86DD)) {
		TEST_FAIL(name, "EtherType not set to IPv6");
		return;
	}

	TEST_PASS(name);
}

#ifdef ENABLE_WHITELIST
/*
 * Test: IPv6 outer header packet from non-whitelisted source (should drop)
 */
static void test_ipv6_outer_blocked(struct tun_decap_bpf *skel)
{
	const char *name = "IPv6 outer drop (non-whitelisted)";
	int prog_fd = bpf_program__fd(skel->progs.xdp_tun_decap);
	int wl_v6_fd = bpf_map__fd(skel->maps.tun_decap_whitelist_v6);
	__u32 retval;
	int err;

	/* Clear IPv6 whitelist and add only specific addresses */
	/* The packet has source 2001:db8::1, we'll only whitelist 2001:db8::99 */
	whitelist_v6_clear(wl_v6_fd);
	__u32 ipv6_blocked[] = TEST_IPV6_BLOCKED;
	whitelist_v6_add(wl_v6_fd, ipv6_blocked);

#ifdef ENABLE_STATS
	int stats_fd = bpf_map__fd(skel->maps.tun_decap_stats);
	__u64 drops_before = read_stat(stats_fd, drop_not_whitelisted);
#endif

	/* Run test with IPv6 outer packet from 2001:db8::1 (not whitelisted) */
	err = run_xdp_test(prog_fd, pkt_ipv6_outer_gre_ipv4, PKT_IPV6_OUTER_GRE_IPV4_LEN, &retval,
	                   NULL, NULL);
	if (err < 0) {
		TEST_FAIL(name, "bpf_prog_test_run failed");
		return;
	}

	/* Verify XDP_DROP */
	if (retval != XDP_DROP) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected XDP_DROP, got %d", retval);
		TEST_FAIL(name, buf);
		return;
	}

#ifdef ENABLE_STATS
	/* Verify drop counter incremented */
	__u64 drops_after = read_stat(stats_fd, drop_not_whitelisted);
	if (drops_after <= drops_before) {
		TEST_FAIL(name, "Drop counter not incremented");
		return;
	}
#endif

	TEST_PASS(name);
}
#endif /* ENABLE_WHITELIST */

/*
 * Test: Fragmented GRE packet is dropped
 */
static void test_gre_fragmented_drop(struct tun_decap_bpf *skel)
{
	const char *name = "GRE drop (fragmented)";
	int prog_fd = bpf_program__fd(skel->progs.xdp_tun_decap);
	__u32 retval;
	int err;

#ifdef ENABLE_WHITELIST
	/* Ensure source is whitelisted - we're testing fragment drop, not whitelist */
	int wl_fd = bpf_map__fd(skel->maps.tun_decap_whitelist);
	whitelist_add(wl_fd, TEST_IP_WHITELISTED_1);
#endif

#ifdef ENABLE_STATS
	int stats_fd = bpf_map__fd(skel->maps.tun_decap_stats);
	__u64 frag_drops_before = read_stat(stats_fd, drop_fragmented);
#endif

	err = run_xdp_test(prog_fd, pkt_gre_fragmented_ipv4, PKT_GRE_FRAGMENTED_IPV4_LEN,
	                   &retval, NULL, NULL);
	if (err < 0) {
		TEST_FAIL(name, "bpf_prog_test_run failed");
		return;
	}

	if (retval != XDP_DROP) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected XDP_DROP(%d), got %d", XDP_DROP, retval);
		TEST_FAIL(name, buf);
		return;
	}

#ifdef ENABLE_STATS
	__u64 frag_drops_after = read_stat(stats_fd, drop_fragmented);
	if (frag_drops_after <= frag_drops_before) {
		TEST_FAIL(name, "drop_fragmented counter not incremented");
		return;
	}
#endif

	TEST_PASS(name);
}

/*
 * Test: Fragmented IPIP packet is dropped
 */
static void test_ipip_fragmented_drop(struct tun_decap_bpf *skel)
{
	const char *name = "IPIP drop (fragmented)";
	int prog_fd = bpf_program__fd(skel->progs.xdp_tun_decap);
	__u32 retval;
	int err;

#ifdef ENABLE_WHITELIST
	int wl_fd = bpf_map__fd(skel->maps.tun_decap_whitelist);
	whitelist_add(wl_fd, TEST_IP_WHITELISTED_2);
#endif

#ifdef ENABLE_STATS
	int stats_fd = bpf_map__fd(skel->maps.tun_decap_stats);
	__u64 frag_drops_before = read_stat(stats_fd, drop_fragmented);
#endif

	err = run_xdp_test(prog_fd, pkt_ipip_fragmented_ipv4, PKT_IPIP_FRAGMENTED_IPV4_LEN,
	                   &retval, NULL, NULL);
	if (err < 0) {
		TEST_FAIL(name, "bpf_prog_test_run failed");
		return;
	}

	if (retval != XDP_DROP) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected XDP_DROP(%d), got %d", XDP_DROP, retval);
		TEST_FAIL(name, buf);
		return;
	}

#ifdef ENABLE_STATS
	__u64 frag_drops_after = read_stat(stats_fd, drop_fragmented);
	if (frag_drops_after <= frag_drops_before) {
		TEST_FAIL(name, "drop_fragmented counter not incremented");
		return;
	}
#endif

	TEST_PASS(name);
}

/*
 * Test: IPv6 packet with Fragment extension header is dropped
 */
static void test_ipv6_fragment_ext_drop(struct tun_decap_bpf *skel)
{
	const char *name = "IPv6 drop (fragment extension header)";
	int prog_fd = bpf_program__fd(skel->progs.xdp_tun_decap);
	__u32 retval;
	int err;

#ifdef ENABLE_WHITELIST
	/* Ensure IPv6 source is whitelisted */
	int wl_v6_fd = bpf_map__fd(skel->maps.tun_decap_whitelist_v6);
	__u32 ipv6_addr[] = TEST_IPV6_WHITELISTED_1;
	whitelist_v6_add(wl_v6_fd, ipv6_addr);
#endif

#ifdef ENABLE_STATS
	int stats_fd = bpf_map__fd(skel->maps.tun_decap_stats);
	__u64 frag_drops_before = read_stat(stats_fd, drop_fragmented);
#endif

	err = run_xdp_test(prog_fd, pkt_ipv6_fragment_hdr, PKT_IPV6_FRAGMENT_HDR_LEN,
	                   &retval, NULL, NULL);
	if (err < 0) {
		TEST_FAIL(name, "bpf_prog_test_run failed");
		return;
	}

	if (retval != XDP_DROP) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected XDP_DROP(%d), got %d", XDP_DROP, retval);
		TEST_FAIL(name, buf);
		return;
	}

#ifdef ENABLE_STATS
	__u64 frag_drops_after = read_stat(stats_fd, drop_fragmented);
	if (frag_drops_after <= frag_drops_before) {
		TEST_FAIL(name, "drop_fragmented counter not incremented");
		return;
	}
#endif

	TEST_PASS(name);
}

#ifdef ENABLE_STATS
/*
 * Test: Statistics are correctly updated
 */
static void test_statistics(struct tun_decap_bpf *skel)
{
	const char *name = "Statistics tracking";
	int stats_fd = bpf_map__fd(skel->maps.tun_decap_stats);

	/* Read statistics after all previous tests */
	__u64 total = read_stat(stats_fd, rx_total);
	__u64 gre = read_stat(stats_fd, rx_gre);
	__u64 ipip = read_stat(stats_fd, rx_ipip);
	__u64 decap_ok = read_stat(stats_fd, decap_success);
	__u64 drops_wl = read_stat(stats_fd, drop_not_whitelisted);
	__u64 pass_non = read_stat(stats_fd, pass_non_tunnel);

	printf("\n  Statistics summary:\n");
	for (int i = 0; i < STAT_NUM_COUNTERS; i++) {
		__u64 val = read_stat_field(stats_fd, stat_fields[i].offset);
		printf("    %-25s %llu\n", stat_fields[i].description, (unsigned long long)val);
	}

	/* Verify reasonable values */
	if (total == 0) {
		TEST_FAIL(name, "No packets counted");
		return;
	}

	if (gre == 0) {
		TEST_FAIL(name, "No GRE packets counted");
		return;
	}

	if (ipip == 0) {
		TEST_FAIL(name, "No IPIP packets counted");
		return;
	}

	if (decap_ok == 0) {
		TEST_FAIL(name, "No successful decaps counted");
		return;
	}

	/* Suppress unused variable warnings */
	(void)drops_wl;
	(void)pass_non;

	TEST_PASS(name);
}
#endif /* ENABLE_STATS */

/*
 * Print test summary
 */
static void print_summary(void)
{
	printf("\n");
	printf("==========================================\n");
	printf("          Test Results Summary\n");
	printf("==========================================\n");
	printf("  Total tests: %d\n", tests_run);
	printf("  " COLOR_GREEN "Passed:      %d" COLOR_RESET "\n", tests_passed);
	if (tests_failed > 0) {
		printf("  " COLOR_RED "Failed:      %d" COLOR_RESET "\n", tests_failed);
	} else {
		printf("  Failed:      %d\n", tests_failed);
	}
	printf("==========================================\n");

	if (tests_failed == 0) {
		printf(COLOR_GREEN "\nAll tests passed!\n" COLOR_RESET);
	} else {
		printf(COLOR_RED "\nSome tests failed!\n" COLOR_RESET);
	}
}

/*
 * Test: GRE packet with inner dst matching bypass subnet should NOT be decapsulated
 */
static void test_gre_bypass_dst(struct tun_decap_bpf *skel)
{
	const char *name = "GRE bypass (inner dst matches bypass subnet)";
	int prog_fd = bpf_program__fd(skel->progs.xdp_tun_decap);
	__u32 retval;
	unsigned char data_out[256];
	size_t data_out_len = sizeof(data_out);
	int err;

#ifdef ENABLE_WHITELIST
	int wl_fd = bpf_map__fd(skel->maps.tun_decap_whitelist);
	whitelist_add(wl_fd, TEST_IP_WHITELISTED_1);
#endif

	/* Set bypass subnet: 172.20.5.48/30 */
	/* 172.20.5.48 = 0xac140530, mask /30 = 0xfffffffc */
	skel->bss->cfg_global.bypass_dst_net = htonl(0xac140530);
	skel->bss->cfg_global.bypass_dst_mask = htonl(0xfffffffc);

	/* Run test with packet whose inner dst is 172.20.5.49 */
	err = run_xdp_test(prog_fd, pkt_gre_bypass_dst, PKT_GRE_BYPASS_DST_LEN, &retval, data_out,
	                   &data_out_len);
	if (err < 0) {
		TEST_FAIL(name, "bpf_prog_test_run failed");
		goto cleanup;
	}

	/* Verify XDP_PASS (not decapsulated) */
	if (retval != XDP_PASS) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected XDP_PASS(%d), got %d", XDP_PASS, retval);
		TEST_FAIL(name, buf);
		goto cleanup;
	}

	/* Verify packet was NOT decapsulated - length should be unchanged */
	if (data_out_len != PKT_GRE_BYPASS_DST_LEN) {
		char buf[96];
		snprintf(buf, sizeof(buf), "Expected len=%zu (no decap), got %zu",
		         (size_t)PKT_GRE_BYPASS_DST_LEN, data_out_len);
		TEST_FAIL(name, buf);
		goto cleanup;
	}

	TEST_PASS(name);

cleanup:
	/* Reset bypass config for other tests */
	skel->bss->cfg_global.bypass_dst_net = 0;
	skel->bss->cfg_global.bypass_dst_mask = 0;
}

/*
 * Test: GRE packet with IPv6 inner dst matching bypass prefix should NOT be decapsulated
 */
static void test_gre_bypass_dst6(struct tun_decap_bpf *skel)
{
	const char *name = "GRE bypass (inner IPv6 dst matches bypass prefix)";
	int prog_fd = bpf_program__fd(skel->progs.xdp_tun_decap);
	__u32 retval;
	unsigned char data_out[256];
	size_t data_out_len = sizeof(data_out);
	int err;

#ifdef ENABLE_WHITELIST
	int wl_fd = bpf_map__fd(skel->maps.tun_decap_whitelist);
	whitelist_add(wl_fd, TEST_IP_WHITELISTED_1);
#endif

	/* Set bypass IPv6 prefix: fd00:10:11::/48
	 * net  = fd00:0010:0011:0000:0000:0000:0000:0000
	 * mask = ffff:ffff:ffff:0000:0000:0000:0000:0000
	 */
	skel->bss->cfg_global.bypass_dst6_net.addr[0] = htonl(0xfd000010);
	skel->bss->cfg_global.bypass_dst6_net.addr[1] = htonl(0x00110000);
	skel->bss->cfg_global.bypass_dst6_net.addr[2] = 0;
	skel->bss->cfg_global.bypass_dst6_net.addr[3] = 0;
	skel->bss->cfg_global.bypass_dst6_mask.addr[0] = htonl(0xffffffff);
	skel->bss->cfg_global.bypass_dst6_mask.addr[1] = htonl(0xffff0000);
	skel->bss->cfg_global.bypass_dst6_mask.addr[2] = 0;
	skel->bss->cfg_global.bypass_dst6_mask.addr[3] = 0;

	/* Run test with packet whose inner IPv6 dst is fd00:10:11::ac14:531 */
	err = run_xdp_test(prog_fd, pkt_gre_bypass_dst6, PKT_GRE_BYPASS_DST6_LEN, &retval,
	                   data_out, &data_out_len);
	if (err < 0) {
		TEST_FAIL(name, "bpf_prog_test_run failed");
		goto cleanup;
	}

	/* Verify XDP_PASS (not decapsulated) */
	if (retval != XDP_PASS) {
		char buf[64];
		snprintf(buf, sizeof(buf), "Expected XDP_PASS(%d), got %d", XDP_PASS, retval);
		TEST_FAIL(name, buf);
		goto cleanup;
	}

	/* Verify packet was NOT decapsulated - length should be unchanged */
	if (data_out_len != PKT_GRE_BYPASS_DST6_LEN) {
		char buf[96];
		snprintf(buf, sizeof(buf), "Expected len=%zu (no decap), got %zu",
		         (size_t)PKT_GRE_BYPASS_DST6_LEN, data_out_len);
		TEST_FAIL(name, buf);
		goto cleanup;
	}

	TEST_PASS(name);

cleanup:
	__builtin_memset((void *)&skel->bss->cfg_global.bypass_dst6_net, 0,
	                 sizeof(skel->bss->cfg_global.bypass_dst6_net));
	__builtin_memset((void *)&skel->bss->cfg_global.bypass_dst6_mask, 0,
	                 sizeof(skel->bss->cfg_global.bypass_dst6_mask));
}

int main(int argc, char **argv)
{
	struct tun_decap_bpf *skel;
	int err;

	(void)argc;
	(void)argv;

	/* Check for root privileges */
	if (geteuid() != 0) {
		fprintf(stderr, "Error: Tests require root privileges\n");
		fprintf(stderr, "Run with: sudo %s\n", argv[0]);
		return 1;
	}

	/* Set up libbpf logging */
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	printf("==========================================\n");
	printf("  XDP Tunnel Decap Unit Tests\n");
	printf("==========================================\n\n");

	/* Open BPF skeleton */
	printf("Loading BPF program...\n");
	skel = tun_decap_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton: %s\n", strerror(errno));
		return 1;
	}

	/* Load BPF program */
	err = tun_decap_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF program: %s\n", strerror(-err));
		tun_decap_bpf__destroy(skel);
		return 1;
	}

	printf("BPF program loaded successfully\n\n");

	/* Initialize: clear whitelist and reset stats */
#ifdef ENABLE_WHITELIST
	whitelist_clear(bpf_map__fd(skel->maps.tun_decap_whitelist));
#endif
#ifdef ENABLE_STATS
	reset_stats(bpf_map__fd(skel->maps.tun_decap_stats));
#endif

	/* Config is a global variable in .bss (zero = all enabled).
	 * Set explicitly via skeleton to verify access path works. */
	skel->bss->cfg_global.disabled = 0;
	skel->bss->cfg_global.disable_gre = 0;
	skel->bss->cfg_global.disable_ipip = 0;
	skel->bss->cfg_global.disable_stats = 0;
	skel->bss->cfg_global.bypass_dst_net = 0;
	skel->bss->cfg_global.bypass_dst_mask = 0;
	memset((void *)&skel->bss->cfg_global.bypass_dst6_net, 0,
	       sizeof(skel->bss->cfg_global.bypass_dst6_net));
	memset((void *)&skel->bss->cfg_global.bypass_dst6_mask, 0,
	       sizeof(skel->bss->cfg_global.bypass_dst6_mask));

	printf("Config global initialized (all processing enabled)\n");

	/* Run tests */
	printf("Running tests...\n\n");

	/* IPv4 outer header tests */
	test_gre_whitelisted(skel);
#ifdef ENABLE_WHITELIST
	test_gre_blocked(skel);
#endif
	test_gre_with_key(skel);
	test_gre_ipv6_inner(skel);
	test_ipip_whitelisted(skel);
#ifdef ENABLE_WHITELIST
	test_ipip_blocked(skel);
#endif
	test_ipv6_in_ipv4(skel);

	/* IPv6 outer header tests */
	test_ipv6_outer_gre_ipv4(skel);
	test_ipv4_in_ipv6(skel);
	test_ipv6_in_ipv6(skel);
#ifdef ENABLE_WHITELIST
	test_ipv6_outer_blocked(skel);
#endif

	/* Fragment drop tests */
	test_gre_fragmented_drop(skel);
	test_ipip_fragmented_drop(skel);
	test_ipv6_fragment_ext_drop(skel);

	/* Bypass destination tests */
	test_gre_bypass_dst(skel);
	test_gre_bypass_dst6(skel);

	/* Pass-through and malformed packet tests */
	test_tcp_passthrough(skel);
	test_udp_passthrough(skel);
	test_ipv6_passthrough(skel);
	test_gre_truncated(skel);

#ifdef ENABLE_STATS
	/* Statistics verification */
	test_statistics(skel);
#endif

	/* Cleanup */
	tun_decap_bpf__destroy(skel);

	/* Print summary */
	print_summary();

	return tests_failed > 0 ? 1 : 0;
}
