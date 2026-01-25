/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * test_gre_helpers.c - Unit tests for GRE protocol helper functions
 *
 * These tests run in userspace without requiring BPF loading or root permissions.
 * They test the pure C helper functions from gre.h using mock GRE headers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

/* Test framework macros */
#define TEST_PASS(name) do { printf("  \033[32m✓\033[0m %s\n", name); passed++; } while(0)
#define TEST_FAIL(name, ...) do { printf("  \033[31m✗\033[0m %s: ", name); printf(__VA_ARGS__); printf("\n"); failed++; } while(0)
#define ASSERT(cond, ...) do { if (!(cond)) { TEST_FAIL(test_name, __VA_ARGS__); return; } } while(0)
#define ASSERT_EQ(a, b, ...) do { if ((a) != (b)) { TEST_FAIL(test_name, __VA_ARGS__); return; } } while(0)

static int passed = 0;
static int failed = 0;

/* Stub out BPF macros for userspace */
#define __always_inline inline
#define __be16 uint16_t
#define __be32 uint32_t
#define bpf_ntohs(x) ntohs(x)
#define bpf_htons(x) htons(x)

/* GRE structures and constants (from gre.h) */
struct gre_base_hdr {
	__be16 flags;
	__be16 protocol;
} __attribute__((packed));

struct gre_checksum_hdr {
	__be16 checksum;
	__be16 reserved1;
} __attribute__((packed));

struct gre_key_hdr {
	__be32 key;
} __attribute__((packed));

struct gre_seq_hdr {
	__be32 seq;
} __attribute__((packed));

/* GRE flag definitions */
#define GRE_FLAG_CHECKSUM 0x8000
#define GRE_FLAG_ROUTING  0x4000
#define GRE_FLAG_KEY      0x2000
#define GRE_FLAG_SEQ      0x1000
#define GRE_FLAG_STRICT   0x0800
#define GRE_FLAG_RECUR    0x0700
#define GRE_FLAG_ACK      0x0080
#define GRE_FLAG_RESERVED 0x0078
#define GRE_FLAG_VERSION  0x0007

#define GRE_VERSION_0 0
#define GRE_VERSION_1 1

/* GRE helper functions (from gre.h) */
static inline int gre_hdr_len(__be16 flags)
{
	int len = sizeof(struct gre_base_hdr);
	uint16_t flags_host = bpf_ntohs(flags);

	if (flags_host & GRE_FLAG_CHECKSUM)
		len += sizeof(struct gre_checksum_hdr);

	if (flags_host & GRE_FLAG_KEY)
		len += sizeof(struct gre_key_hdr);

	if (flags_host & GRE_FLAG_SEQ)
		len += sizeof(struct gre_seq_hdr);

	return len;
}

static inline int gre_validate_flags(__be16 flags)
{
	uint16_t flags_host = bpf_ntohs(flags);

	/* Version must be 0 for standard GRE */
	if ((flags_host & GRE_FLAG_VERSION) != GRE_VERSION_0)
		return -1;

	/* Routing bit is deprecated and should not be set */
	if (flags_host & GRE_FLAG_ROUTING)
		return -1;

	return 0;
}

static inline int gre_has_checksum(__be16 flags)
{
	return !!(bpf_ntohs(flags) & GRE_FLAG_CHECKSUM);
}

static inline int gre_has_key(__be16 flags)
{
	return !!(bpf_ntohs(flags) & GRE_FLAG_KEY);
}

static inline int gre_has_seq(__be16 flags)
{
	return !!(bpf_ntohs(flags) & GRE_FLAG_SEQ);
}

static inline __be32 gre_get_key(struct gre_base_hdr *greh)
{
	void *key_pos = (void *)(greh + 1);

	if (gre_has_checksum(greh->flags))
		key_pos += sizeof(struct gre_checksum_hdr);

	return *(__be32 *)key_pos;
}

/* ========== Test Cases ========== */

void test_gre_hdr_len_base_only()
{
	const char *test_name = "gre_hdr_len - base header only";
	__be16 flags = htons(0x0000); /* No flags set */
	int len;

	len = gre_hdr_len(flags);

	ASSERT_EQ(len, 4, "base GRE header should be 4 bytes");

	TEST_PASS(test_name);
}

void test_gre_hdr_len_with_checksum()
{
	const char *test_name = "gre_hdr_len - with checksum";
	__be16 flags = htons(GRE_FLAG_CHECKSUM); /* Checksum flag set */
	int len;

	len = gre_hdr_len(flags);

	ASSERT_EQ(len, 8, "GRE header with checksum should be 8 bytes (4 base + 4 checksum)");

	TEST_PASS(test_name);
}

void test_gre_hdr_len_with_key()
{
	const char *test_name = "gre_hdr_len - with key";
	__be16 flags = htons(GRE_FLAG_KEY);
	int len;

	len = gre_hdr_len(flags);

	ASSERT_EQ(len, 8, "GRE header with key should be 8 bytes (4 base + 4 key)");

	TEST_PASS(test_name);
}

void test_gre_hdr_len_with_seq()
{
	const char *test_name = "gre_hdr_len - with sequence";
	__be16 flags = htons(GRE_FLAG_SEQ);
	int len;

	len = gre_hdr_len(flags);

	ASSERT_EQ(len, 8, "GRE header with sequence should be 8 bytes (4 base + 4 seq)");

	TEST_PASS(test_name);
}

void test_gre_hdr_len_checksum_and_key()
{
	const char *test_name = "gre_hdr_len - checksum + key";
	__be16 flags = htons(GRE_FLAG_CHECKSUM | GRE_FLAG_KEY);
	int len;

	len = gre_hdr_len(flags);

	ASSERT_EQ(len, 12, "GRE header with C+K should be 12 bytes (4 base + 4 csum + 4 key)");

	TEST_PASS(test_name);
}

void test_gre_hdr_len_all_fields()
{
	const char *test_name = "gre_hdr_len - all optional fields";
	__be16 flags = htons(GRE_FLAG_CHECKSUM | GRE_FLAG_KEY | GRE_FLAG_SEQ);
	int len;

	len = gre_hdr_len(flags);

	ASSERT_EQ(len, 16, "GRE header with C+K+S should be 16 bytes");

	TEST_PASS(test_name);
}

void test_gre_validate_flags_version_0()
{
	const char *test_name = "gre_validate_flags - version 0 (valid)";
	__be16 flags = htons(0x0000); /* Version 0, no flags */
	int result;

	result = gre_validate_flags(flags);

	ASSERT_EQ(result, 0, "version 0 should be valid");

	TEST_PASS(test_name);
}

void test_gre_validate_flags_version_1()
{
	const char *test_name = "gre_validate_flags - version 1 (invalid)";
	__be16 flags = htons(GRE_VERSION_1); /* Version 1 (PPTP) */
	int result;

	result = gre_validate_flags(flags);

	ASSERT_EQ(result, -1, "version 1 should be invalid");

	TEST_PASS(test_name);
}

void test_gre_validate_flags_routing_bit()
{
	const char *test_name = "gre_validate_flags - routing bit (deprecated)";
	__be16 flags = htons(GRE_FLAG_ROUTING); /* Routing flag set */
	int result;

	result = gre_validate_flags(flags);

	ASSERT_EQ(result, -1, "routing bit should be rejected (deprecated)");

	TEST_PASS(test_name);
}

void test_gre_validate_flags_valid_with_options()
{
	const char *test_name = "gre_validate_flags - valid with C+K+S";
	__be16 flags = htons(GRE_FLAG_CHECKSUM | GRE_FLAG_KEY | GRE_FLAG_SEQ);
	int result;

	result = gre_validate_flags(flags);

	ASSERT_EQ(result, 0, "C+K+S flags with version 0 should be valid");

	TEST_PASS(test_name);
}

void test_gre_has_checksum()
{
	const char *test_name = "gre_has_checksum";
	__be16 flags_with = htons(GRE_FLAG_CHECKSUM);
	__be16 flags_without = htons(0x0000);

	ASSERT(gre_has_checksum(flags_with), "should detect checksum flag");
	ASSERT(!gre_has_checksum(flags_without), "should not detect checksum when absent");

	TEST_PASS(test_name);
}

void test_gre_has_key()
{
	const char *test_name = "gre_has_key";
	__be16 flags_with = htons(GRE_FLAG_KEY);
	__be16 flags_without = htons(0x0000);

	ASSERT(gre_has_key(flags_with), "should detect key flag");
	ASSERT(!gre_has_key(flags_without), "should not detect key when absent");

	TEST_PASS(test_name);
}

void test_gre_has_seq()
{
	const char *test_name = "gre_has_seq";
	__be16 flags_with = htons(GRE_FLAG_SEQ);
	__be16 flags_without = htons(0x0000);

	ASSERT(gre_has_seq(flags_with), "should detect sequence flag");
	ASSERT(!gre_has_seq(flags_without), "should not detect sequence when absent");

	TEST_PASS(test_name);
}

void test_gre_get_key_without_checksum()
{
	const char *test_name = "gre_get_key - without checksum";
	uint8_t packet[100] = {0};
	struct gre_base_hdr *greh = (struct gre_base_hdr *)packet;
	struct gre_key_hdr *key_hdr = (struct gre_key_hdr *)(greh + 1);
	__be32 key;

	/* Create GRE header with key (no checksum) */
	greh->flags = htons(GRE_FLAG_KEY);
	greh->protocol = htons(0x0800); /* IPv4 */
	key_hdr->key = htonl(0x12345678);

	key = gre_get_key(greh);

	ASSERT_EQ(ntohl(key), 0x12345678, "should extract key value correctly");

	TEST_PASS(test_name);
}

void test_gre_get_key_with_checksum()
{
	const char *test_name = "gre_get_key - with checksum";
	uint8_t packet[100] = {0};
	struct gre_base_hdr *greh = (struct gre_base_hdr *)packet;
	struct gre_checksum_hdr *csum_hdr = (struct gre_checksum_hdr *)(greh + 1);
	struct gre_key_hdr *key_hdr = (struct gre_key_hdr *)(csum_hdr + 1);
	__be32 key;

	/* Create GRE header with checksum AND key */
	greh->flags = htons(GRE_FLAG_CHECKSUM | GRE_FLAG_KEY);
	greh->protocol = htons(0x0800);
	csum_hdr->checksum = htons(0xabcd);
	csum_hdr->reserved1 = 0;
	key_hdr->key = htonl(0x87654321);

	key = gre_get_key(greh);

	ASSERT_EQ(ntohl(key), 0x87654321, "should extract key value after checksum field");

	TEST_PASS(test_name);
}

void test_gre_flag_combinations()
{
	const char *test_name = "GRE flag combinations";
	__be16 flags;

	/* Test individual flags */
	flags = htons(GRE_FLAG_CHECKSUM);
	ASSERT(gre_has_checksum(flags) && !gre_has_key(flags) && !gre_has_seq(flags),
	       "should detect only checksum flag");

	flags = htons(GRE_FLAG_KEY);
	ASSERT(!gre_has_checksum(flags) && gre_has_key(flags) && !gre_has_seq(flags),
	       "should detect only key flag");

	flags = htons(GRE_FLAG_SEQ);
	ASSERT(!gre_has_checksum(flags) && !gre_has_key(flags) && gre_has_seq(flags),
	       "should detect only seq flag");

	/* Test combinations */
	flags = htons(GRE_FLAG_CHECKSUM | GRE_FLAG_KEY);
	ASSERT(gre_has_checksum(flags) && gre_has_key(flags) && !gre_has_seq(flags),
	       "should detect checksum + key");

	flags = htons(GRE_FLAG_KEY | GRE_FLAG_SEQ);
	ASSERT(!gre_has_checksum(flags) && gre_has_key(flags) && gre_has_seq(flags),
	       "should detect key + seq");

	flags = htons(GRE_FLAG_CHECKSUM | GRE_FLAG_SEQ);
	ASSERT(gre_has_checksum(flags) && !gre_has_key(flags) && gre_has_seq(flags),
	       "should detect checksum + seq");

	/* Test all flags */
	flags = htons(GRE_FLAG_CHECKSUM | GRE_FLAG_KEY | GRE_FLAG_SEQ);
	ASSERT(gre_has_checksum(flags) && gre_has_key(flags) && gre_has_seq(flags),
	       "should detect all flags");

	TEST_PASS(test_name);
}

void test_gre_hdr_len_field_ordering()
{
	const char *test_name = "GRE header length - field ordering";

	/* RFC 2784 specifies field order: Checksum, Key, Sequence */

	/* Key + Seq (no checksum) */
	__be16 flags = htons(GRE_FLAG_KEY | GRE_FLAG_SEQ);
	ASSERT_EQ(gre_hdr_len(flags), 12, "K+S should be 12 bytes (4 base + 4 key + 4 seq)");

	/* Checksum + Seq (no key) */
	flags = htons(GRE_FLAG_CHECKSUM | GRE_FLAG_SEQ);
	ASSERT_EQ(gre_hdr_len(flags), 12, "C+S should be 12 bytes (4 base + 4 csum + 4 seq)");

	TEST_PASS(test_name);
}

void test_gre_validate_reserved_bits()
{
	const char *test_name = "gre_validate_flags - reserved bits ignored";

	/* Version 0 with some reserved bits set (should still be valid) */
	/* The current implementation doesn't check reserved bits, only version and routing */
	__be16 flags = htons(GRE_FLAG_RESERVED | GRE_VERSION_0);
	int result = gre_validate_flags(flags);

	/* Note: Current implementation doesn't validate reserved bits */
	ASSERT_EQ(result, 0, "reserved bits don't affect validation");

	TEST_PASS(test_name);
}

void test_gre_validate_ack_flag()
{
	const char *test_name = "gre_validate_flags - ACK flag (PPTP)";

	/* ACK flag is used in PPTP (version 1) but validation only checks version */
	__be16 flags = htons(GRE_FLAG_ACK | GRE_VERSION_0);
	int result = gre_validate_flags(flags);

	/* ACK flag with version 0 should still validate (only routing is deprecated) */
	ASSERT_EQ(result, 0, "ACK flag doesn't affect version 0 validation");

	TEST_PASS(test_name);
}

void test_gre_hdr_len_endianness()
{
	const char *test_name = "GRE header length - network byte order";

	/* Test that function correctly handles network byte order */
	__be16 flags_net = htons(GRE_FLAG_CHECKSUM | GRE_FLAG_KEY);

	int len_correct = gre_hdr_len(flags_net);

	ASSERT_EQ(len_correct, 12, "should correctly parse network byte order flags");

	/* Note: Input must be in network byte order (big-endian) */

	TEST_PASS(test_name);
}

void test_gre_get_key_value_preservation()
{
	const char *test_name = "gre_get_key - value preservation";
	uint8_t packet[100] = {0};
	struct gre_base_hdr *greh = (struct gre_base_hdr *)packet;
	struct gre_key_hdr *key_hdr = (struct gre_key_hdr *)(greh + 1);
	__be32 test_values[] = {
		htonl(0x00000000), /* Zero */
		htonl(0xffffffff), /* All bits set */
		htonl(0x12345678), /* Arbitrary value */
		htonl(0xdeadbeef), /* Another arbitrary value */
	};

	greh->flags = htons(GRE_FLAG_KEY);

	for (int i = 0; i < 4; i++) {
		key_hdr->key = test_values[i];
		__be32 extracted = gre_get_key(greh);
		ASSERT_EQ(extracted, test_values[i], "key value should be preserved");
	}

	TEST_PASS(test_name);
}

void test_gre_flag_detection_multiple()
{
	const char *test_name = "GRE flag detection - multiple flags";
	__be16 flags = htons(GRE_FLAG_CHECKSUM | GRE_FLAG_KEY | GRE_FLAG_SEQ);

	ASSERT(gre_has_checksum(flags), "should detect checksum in combined flags");
	ASSERT(gre_has_key(flags), "should detect key in combined flags");
	ASSERT(gre_has_seq(flags), "should detect seq in combined flags");

	TEST_PASS(test_name);
}


void test_gre_hdr_len_boundary()
{
	const char *test_name = "GRE header length - boundary conditions";

	/* Minimum size */
	__be16 flags_min = htons(0x0000);
	ASSERT_EQ(gre_hdr_len(flags_min), 4, "minimum GRE header is 4 bytes");

	/* Maximum realistic size (C+K+S) */
	__be16 flags_max = htons(GRE_FLAG_CHECKSUM | GRE_FLAG_KEY | GRE_FLAG_SEQ);
	ASSERT_EQ(gre_hdr_len(flags_max), 16, "maximum GRE header is 16 bytes");

	TEST_PASS(test_name);
}

void test_gre_flags_boolean_return()
{
	const char *test_name = "GRE flag functions - boolean return";
	__be16 flags = htons(GRE_FLAG_KEY);

	/* Functions should return 0 or 1, not arbitrary values */
	int has_key = gre_has_key(flags);
	int has_csum = gre_has_checksum(flags);
	int has_seq = gre_has_seq(flags);

	ASSERT_EQ(has_key, 1, "gre_has_key should return 1 when present");
	ASSERT_EQ(has_csum, 0, "gre_has_checksum should return 0 when absent");
	ASSERT_EQ(has_seq, 0, "gre_has_seq should return 0 when absent");

	TEST_PASS(test_name);
}

void test_gre_key_position_calculation()
{
	const char *test_name = "GRE key position - with/without checksum";
	uint8_t packet[100] = {0};
	struct gre_base_hdr *greh = (struct gre_base_hdr *)packet;

	/* Test 1: Key without checksum - key is at offset 4 */
	greh->flags = htons(GRE_FLAG_KEY);
	struct gre_key_hdr *key_direct = (struct gre_key_hdr *)(greh + 1);
	key_direct->key = htonl(0x11111111);

	__be32 extracted1 = gre_get_key(greh);
	ASSERT_EQ(ntohl(extracted1), 0x11111111, "key at offset 4 (no checksum)");

	/* Test 2: Key with checksum - key is at offset 8 */
	memset(packet, 0, sizeof(packet));
	greh->flags = htons(GRE_FLAG_CHECKSUM | GRE_FLAG_KEY);
	struct gre_checksum_hdr *csum = (struct gre_checksum_hdr *)(greh + 1);
	struct gre_key_hdr *key_after_csum = (struct gre_key_hdr *)(csum + 1);
	csum->checksum = htons(0x1234);
	key_after_csum->key = htonl(0x22222222);

	__be32 extracted2 = gre_get_key(greh);
	ASSERT_EQ(ntohl(extracted2), 0x22222222, "key at offset 8 (after checksum)");

	TEST_PASS(test_name);
}

void test_gre_header_size_progressive()
{
	const char *test_name = "GRE header size - progressive flag addition";
	int len;

	/* Base: 4 bytes */
	len = gre_hdr_len(htons(0));
	ASSERT_EQ(len, 4, "base header");

	/* Add checksum: +4 = 8 bytes */
	len = gre_hdr_len(htons(GRE_FLAG_CHECKSUM));
	ASSERT_EQ(len, 8, "base + checksum");

	/* Add key to checksum: +4 = 12 bytes */
	len = gre_hdr_len(htons(GRE_FLAG_CHECKSUM | GRE_FLAG_KEY));
	ASSERT_EQ(len, 12, "base + checksum + key");

	/* Add sequence to all: +4 = 16 bytes */
	len = gre_hdr_len(htons(GRE_FLAG_CHECKSUM | GRE_FLAG_KEY | GRE_FLAG_SEQ));
	ASSERT_EQ(len, 16, "base + checksum + key + seq");

	TEST_PASS(test_name);
}

void test_gre_validate_complex_invalid()
{
	const char *test_name = "gre_validate_flags - routing + version 0";

	/* Even with version 0, routing bit makes it invalid */
	__be16 flags = htons(GRE_FLAG_ROUTING | GRE_VERSION_0);
	int result = gre_validate_flags(flags);

	ASSERT_EQ(result, -1, "routing bit should invalidate even with version 0");

	TEST_PASS(test_name);
}

void test_gre_validate_routing_and_version_1()
{
	const char *test_name = "gre_validate_flags - routing + version 1";

	/* Both routing and version 1 are invalid */
	__be16 flags = htons(GRE_FLAG_ROUTING | GRE_VERSION_1);
	int result = gre_validate_flags(flags);

	ASSERT_EQ(result, -1, "should reject routing + version 1");

	TEST_PASS(test_name);
}

/* ========== Main Test Runner ========== */

int main(void)
{
	printf("\n=== GRE Helpers Unit Tests ===\n\n");

	/* GRE header length calculation */
	test_gre_hdr_len_base_only();
	test_gre_hdr_len_with_checksum();
	test_gre_hdr_len_with_key();
	test_gre_hdr_len_with_seq();
	test_gre_hdr_len_checksum_and_key();
	test_gre_hdr_len_all_fields();
	test_gre_hdr_len_field_ordering();
	test_gre_hdr_len_boundary();
	test_gre_header_size_progressive();

	/* GRE flag validation */
	test_gre_validate_flags_version_0();
	test_gre_validate_flags_version_1();
	test_gre_validate_flags_routing_bit();
	test_gre_validate_flags_valid_with_options();
	test_gre_validate_reserved_bits();
	test_gre_validate_ack_flag();
	test_gre_validate_complex_invalid();
	test_gre_validate_routing_and_version_1();

	/* GRE flag detection */
	test_gre_has_checksum();
	test_gre_has_key();
	test_gre_has_seq();
	test_gre_flag_combinations();
	test_gre_flags_boolean_return();

	/* GRE key extraction */
	test_gre_get_key_without_checksum();
	test_gre_get_key_with_checksum();
	test_gre_get_key_value_preservation();
	test_gre_key_position_calculation();

	/* Summary */
	printf("\n");
	printf("=================================\n");
	printf("Results: %d passed, %d failed\n", passed, failed);
	printf("=================================\n\n");

	return (failed > 0) ? 1 : 0;
}
