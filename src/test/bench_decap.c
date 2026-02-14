// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * bench_decap.c - Benchmarks for XDP tunnel decapsulation program
 *
 * Measures per-packet-type latency and hardware counters using
 * BPF_PROG_TEST_RUN with perf_event_open() for PMU access.
 *
 * Run with: sudo ./bench_decap [--repeat N] [--warmup N] [--no-hwcounters]
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "test_packets.h"
#include "tun_decap.h"
#include "tun_decap.skel.h"

/* Default benchmark parameters */
#define DEFAULT_REPEAT 100000
#define DEFAULT_WARMUP 1000
#define BENCH_CPU      0

/* ===== XDP action names ===== */

static const char *xdp_action_str(unsigned int action)
{
	switch (action) {
	case XDP_ABORTED:
		return "ABORT";
	case XDP_DROP:
		return "DROP";
	case XDP_PASS:
		return "PASS";
	case XDP_TX:
		return "TX";
	case XDP_REDIRECT:
		return "REDIR";
	default:
		return "???";
	}
}

/* ===== Hardware performance counters via perf_event_open() ===== */

static long sys_perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd,
                                unsigned long flags)
{
	return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

struct hw_counters {
	int fd_cycles;
	int fd_instructions;
	int fd_cache_refs;
	int fd_cache_misses;
	int available;
};

struct hw_values {
	double cycles;
	double instructions;
	double cache_refs;
	double cache_misses;
};

static int open_hw_counter(__u64 config)
{
	struct perf_event_attr pe;

	memset(&pe, 0, sizeof(pe));
	pe.type = PERF_TYPE_HARDWARE;
	pe.size = sizeof(pe);
	pe.config = config;
	pe.disabled = 1;
	pe.exclude_kernel = 0; /* BPF runs in kernel context */
	pe.exclude_hv = 1;

	return sys_perf_event_open(&pe, 0, -1, -1, 0);
}

static int hw_counters_init(struct hw_counters *hw)
{
	hw->fd_cycles = open_hw_counter(PERF_COUNT_HW_CPU_CYCLES);
	hw->fd_instructions = open_hw_counter(PERF_COUNT_HW_INSTRUCTIONS);
	hw->fd_cache_refs = open_hw_counter(PERF_COUNT_HW_CACHE_REFERENCES);
	hw->fd_cache_misses = open_hw_counter(PERF_COUNT_HW_CACHE_MISSES);

	hw->available = (hw->fd_cycles >= 0 && hw->fd_instructions >= 0);
	if (!hw->available) {
		fprintf(stderr,
		        "Warning: Hardware counters unavailable "
		        "(try CAP_PERFMON or check /proc/sys/kernel/perf_event_paranoid)\n");
		if (hw->fd_cycles >= 0)
			close(hw->fd_cycles);
		if (hw->fd_instructions >= 0)
			close(hw->fd_instructions);
		if (hw->fd_cache_refs >= 0)
			close(hw->fd_cache_refs);
		if (hw->fd_cache_misses >= 0)
			close(hw->fd_cache_misses);
		hw->fd_cycles = hw->fd_instructions = -1;
		hw->fd_cache_refs = hw->fd_cache_misses = -1;
	}
	return hw->available ? 0 : -1;
}

static void hw_counters_close(struct hw_counters *hw)
{
	if (hw->fd_cycles >= 0)
		close(hw->fd_cycles);
	if (hw->fd_instructions >= 0)
		close(hw->fd_instructions);
	if (hw->fd_cache_refs >= 0)
		close(hw->fd_cache_refs);
	if (hw->fd_cache_misses >= 0)
		close(hw->fd_cache_misses);
}

static void hw_counters_reset_enable(struct hw_counters *hw)
{
	if (!hw->available)
		return;
	ioctl(hw->fd_cycles, PERF_EVENT_IOC_RESET, 0);
	ioctl(hw->fd_instructions, PERF_EVENT_IOC_RESET, 0);
	ioctl(hw->fd_cache_refs, PERF_EVENT_IOC_RESET, 0);
	ioctl(hw->fd_cache_misses, PERF_EVENT_IOC_RESET, 0);
	ioctl(hw->fd_cycles, PERF_EVENT_IOC_ENABLE, 0);
	ioctl(hw->fd_instructions, PERF_EVENT_IOC_ENABLE, 0);
	ioctl(hw->fd_cache_refs, PERF_EVENT_IOC_ENABLE, 0);
	ioctl(hw->fd_cache_misses, PERF_EVENT_IOC_ENABLE, 0);
}

static void hw_counters_disable_read(struct hw_counters *hw, struct hw_values *vals)
{
	__u64 tmp;

	memset(vals, 0, sizeof(*vals));
	if (!hw->available)
		return;
	ioctl(hw->fd_cycles, PERF_EVENT_IOC_DISABLE, 0);
	ioctl(hw->fd_instructions, PERF_EVENT_IOC_DISABLE, 0);
	ioctl(hw->fd_cache_refs, PERF_EVENT_IOC_DISABLE, 0);
	ioctl(hw->fd_cache_misses, PERF_EVENT_IOC_DISABLE, 0);

	if (read(hw->fd_cycles, &tmp, sizeof(tmp)) == sizeof(tmp))
		vals->cycles = (double)tmp;
	if (read(hw->fd_instructions, &tmp, sizeof(tmp)) == sizeof(tmp))
		vals->instructions = (double)tmp;
	if (read(hw->fd_cache_refs, &tmp, sizeof(tmp)) == sizeof(tmp))
		vals->cache_refs = (double)tmp;
	if (read(hw->fd_cache_misses, &tmp, sizeof(tmp)) == sizeof(tmp))
		vals->cache_misses = (double)tmp;
}

#ifdef ENABLE_WHITELIST
/* ===== Whitelist helpers ===== */

static int whitelist_add(int map_fd, __u32 ip_be)
{
	struct whitelist_value val = { .allowed = 1 };
	return bpf_map_update_elem(map_fd, &ip_be, &val, BPF_ANY);
}

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
#endif /* ENABLE_WHITELIST */

/* ===== Code path classification for operation counts ===== */

enum bench_path {
	PATH_DECAP,       /* tunnel decapsulated: config + stats? + whitelist? + adjust_head */
#ifdef ENABLE_WHITELIST
	PATH_DROP_WL,     /* dropped (not whitelisted): config + stats? + whitelist */
#endif
	PATH_DROP_FRAG,   /* dropped (fragmented): config + stats? */
	PATH_DROP_MALFORM, /* dropped (malformed after whitelist): config + stats? + whitelist? */
	PATH_PASSTHROUGH, /* non-tunnel pass: config + stats? */
};

static void compute_ops(enum bench_path path, int *map_lookups, int *helpers)
{
	int base = 0; /* config is a global variable, no map lookup */
#ifdef ENABLE_STATS
	base += 1; /* stats map lookup */
#endif
	switch (path) {
	case PATH_DECAP:
#ifdef ENABLE_WHITELIST
		*map_lookups = base + 1; /* + whitelist */
		*helpers = base + 2;     /* + whitelist + adjust_head */
#else
		*map_lookups = base;
		*helpers = base + 1;     /* + adjust_head only */
#endif
		break;
#ifdef ENABLE_WHITELIST
	case PATH_DROP_WL:
#endif
	case PATH_DROP_MALFORM:
#ifdef ENABLE_WHITELIST
		*map_lookups = base + 1;
		*helpers = base + 1;
#else
		*map_lookups = base;
		*helpers = base;
#endif
		break;
	case PATH_DROP_FRAG:
	case PATH_PASSTHROUGH:
		*map_lookups = base;
		*helpers = base;
		break;
	}
}

/* ===== Benchmark entry and result structs ===== */

struct bench_entry {
	const char *name;
	void *pkt;
	size_t pkt_len;
	__u32 expected_verdict;
	enum bench_path path;
};

struct bench_result {
	const char *name;
	__u32 verdict;
	double ns_per_pkt;
	double mpps;
	struct hw_values hw;
	int map_lookups;
	int helper_calls;
	int ok; /* 1 if verdict matched expected */
};

/* ===== Extra test packets not in test_packets.h ===== */

/*
 * GRE packet with checksum option from whitelisted source (10.0.0.1)
 * GRE flags: C=1 (0x8000), 8 byte GRE header (4 base + 4 csum+reserved)
 */
static unsigned char pkt_gre_with_csum[] = {
    /* Ethernet header (14 bytes) */
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0x08, 0x00,
    /* Outer IPv4 header (20 bytes) */
    0x45, 0x00, 0x00, 0x44,             /* Total length: 68 bytes */
    0x00, 0x01, 0x00, 0x00,
    0x40, 0x2f,                         /* Protocol: GRE */
    0x00, 0x00,
    0x0a, 0x00, 0x00, 0x01,             /* Source: 10.0.0.1 */
    0xc0, 0xa8, 0x01, 0x01,
    /* GRE header with checksum (8 bytes) */
    0x80, 0x00,                         /* Flags: C=1 */
    0x08, 0x00,                         /* Protocol: IPv4 */
    0x00, 0x00,                         /* Checksum (zeroed) */
    0x00, 0x00,                         /* Reserved */
    /* Inner IPv4 header (20 bytes) */
    0x45, 0x00, 0x00, 0x28,
    0x00, 0x02, 0x00, 0x00,
    0x40, 0x06, 0x00, 0x00,
    0xac, 0x10, 0x00, 0x01,
    0xac, 0x10, 0x00, 0x02,
    /* TCP header (20 bytes) */
    0x00, 0x50, 0x00, 0x51,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x50, 0x02, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00,
};

/* ===== Benchmark table ===== */

static struct bench_entry bench_entries[] = {
    /* GRE with IPv4 outer */
    { "GRE IPv4 (whitelisted)",        pkt_gre_whitelisted,       sizeof(pkt_gre_whitelisted),       XDP_PASS, PATH_DECAP },
#ifdef ENABLE_WHITELIST
    { "GRE IPv4 (blocked)",            pkt_gre_blocked,           sizeof(pkt_gre_blocked),           XDP_DROP, PATH_DROP_WL },
#else
    { "GRE IPv4 (no whitelist)",       pkt_gre_blocked,           sizeof(pkt_gre_blocked),           XDP_PASS, PATH_DECAP },
#endif
    { "GRE with key (whitelisted)",    pkt_gre_with_key,          sizeof(pkt_gre_with_key),          XDP_PASS, PATH_DECAP },
    { "GRE with csum (whitelisted)",   pkt_gre_with_csum,         sizeof(pkt_gre_with_csum),         XDP_PASS, PATH_DECAP },
    { "GRE IPv6 inner (whitelisted)",  pkt_gre_ipv6_inner,        sizeof(pkt_gre_ipv6_inner),        XDP_PASS, PATH_DECAP },

    /* IPIP */
    { "IPIP IPv4 (whitelisted)",       pkt_ipip_whitelisted,      sizeof(pkt_ipip_whitelisted),      XDP_PASS, PATH_DECAP },
#ifdef ENABLE_WHITELIST
    { "IPIP IPv4 (blocked)",           pkt_ipip_blocked,          sizeof(pkt_ipip_blocked),          XDP_DROP, PATH_DROP_WL },
#else
    { "IPIP IPv4 (no whitelist)",      pkt_ipip_blocked,          sizeof(pkt_ipip_blocked),          XDP_PASS, PATH_DECAP },
#endif

    /* IPv6-in-IPv4 */
    { "IPv6-in-IPv4 (whitelisted)",    pkt_ipv6_in_ipv4,          sizeof(pkt_ipv6_in_ipv4),          XDP_PASS, PATH_DECAP },

    /* IPv6 outer header combinations */
    { "IPv6 outer + GRE + IPv4",       pkt_ipv6_outer_gre_ipv4,   sizeof(pkt_ipv6_outer_gre_ipv4),   XDP_PASS, PATH_DECAP },
    { "IPv4-in-IPv6 (whitelisted)",    pkt_ipv4_in_ipv6,          sizeof(pkt_ipv4_in_ipv6),          XDP_PASS, PATH_DECAP },
    { "IPv6-in-IPv6 (whitelisted)",    pkt_ipv6_in_ipv6,          sizeof(pkt_ipv6_in_ipv6),          XDP_PASS, PATH_DECAP },

    /* Fragment drops */
    { "GRE fragmented (drop)",         pkt_gre_fragmented_ipv4,   sizeof(pkt_gre_fragmented_ipv4),   XDP_DROP, PATH_DROP_FRAG },
    { "IPIP fragmented (drop)",        pkt_ipip_fragmented_ipv4,  sizeof(pkt_ipip_fragmented_ipv4),  XDP_DROP, PATH_DROP_FRAG },
    { "IPv6 frag ext hdr (drop)",      pkt_ipv6_fragment_hdr,     sizeof(pkt_ipv6_fragment_hdr),     XDP_DROP, PATH_DROP_FRAG },

    /* Malformed */
    { "GRE truncated (malformed)",     pkt_gre_truncated,         sizeof(pkt_gre_truncated),         XDP_DROP, PATH_DROP_MALFORM },

    /* Passthrough */
    { "TCP passthrough",               pkt_tcp_normal,            sizeof(pkt_tcp_normal),            XDP_PASS, PATH_PASSTHROUGH },
    { "UDP passthrough",               pkt_udp_normal,            sizeof(pkt_udp_normal),            XDP_PASS, PATH_PASSTHROUGH },
    { "IPv6 passthrough",              pkt_ipv6,                  sizeof(pkt_ipv6),                  XDP_PASS, PATH_PASSTHROUGH },
};

#define NUM_BENCH_ENTRIES (sizeof(bench_entries) / sizeof(bench_entries[0]))

/* ===== Benchmark runner ===== */

static int run_bench(int prog_fd, struct bench_entry *entry, int repeat, int warmup,
                     struct hw_counters *hw, struct bench_result *result)
{
	int err;

	result->name = entry->name;
	compute_ops(entry->path, &result->map_lookups, &result->helper_calls);

	/* Warmup run */
	if (warmup > 0) {
		LIBBPF_OPTS(bpf_test_run_opts, wopts,
		            .data_in = entry->pkt,
		            .data_size_in = entry->pkt_len,
		            .repeat = warmup,
		);
		err = bpf_prog_test_run_opts(prog_fd, &wopts);
		if (err < 0) {
			fprintf(stderr, "  Warmup failed for %s: %s\n", entry->name, strerror(-err));
			return -1;
		}
	}

	/* Benchmark run with hardware counters */
	LIBBPF_OPTS(bpf_test_run_opts, opts,
	            .data_in = entry->pkt,
	            .data_size_in = entry->pkt_len,
	            .repeat = repeat,
	);

	if (hw && hw->available)
		hw_counters_reset_enable(hw);

	err = bpf_prog_test_run_opts(prog_fd, &opts);

	if (hw && hw->available)
		hw_counters_disable_read(hw, &result->hw);

	if (err < 0) {
		fprintf(stderr, "  Benchmark failed for %s: %s\n", entry->name, strerror(-err));
		return -1;
	}

	result->verdict = opts.retval;
	result->ok = (opts.retval == entry->expected_verdict);

	/*
	 * opts.duration: kernel returns average ns per run (already divided
	 * by repeat via do_div() in kernel/bpf/test_run.c).
	 */
	result->ns_per_pkt = (double)opts.duration;
	result->mpps = (result->ns_per_pkt > 0) ? 1000.0 / result->ns_per_pkt : 0;

	/* Normalize hw values per packet (double division preserves fractions) */
	if (hw && hw->available && repeat > 0) {
		result->hw.cycles /= (double)repeat;
		result->hw.instructions /= (double)repeat;
		result->hw.cache_refs /= (double)repeat;
		result->hw.cache_misses /= (double)repeat;
	}

	return 0;
}

/* ===== Output formatting ===== */

/* Colors */
#define C_RED    "\033[31m"
#define C_GREEN  "\033[32m"
#define C_YELLOW "\033[33m"
#define C_BOLD   "\033[1m"
#define C_RESET  "\033[0m"

static void print_header(int repeat, int warmup, int use_hw)
{
	printf(C_BOLD "XDP Tunnel Decap Benchmarks" C_RESET
	       " (repeat=%d, warmup=%d"
#ifdef ENABLE_STATS
	       ", stats=on"
#else
	       ", stats=off"
#endif
#ifdef ENABLE_WHITELIST
	       ", whitelist=on"
#else
	       ", whitelist=off"
#endif
	       ")\n\n",
	       repeat, warmup);

	if (use_hw) {
		printf("%-34s %-7s %7s %7s %7s %8s %5s %8s %8s %8s\n",
		       "Packet Type", "Verdict", "ns/pkt", "Mpps",
		       "insns", "cycles", "IPC", "L1-miss",
		       "lookups", "helpers");
		printf("%-34s %-7s %7s %7s %7s %8s %5s %8s %8s %8s\n",
		       "---", "-------", "------", "------",
		       "------", "-------", "-----", "-------",
		       "-------", "-------");
	} else {
		printf("%-34s %-7s %7s %7s %8s %8s\n",
		       "Packet Type", "Verdict", "ns/pkt", "Mpps",
		       "lookups", "helpers");
		printf("%-34s %-7s %7s %7s %8s %8s\n",
		       "---", "-------", "------", "------",
		       "-------", "-------");
	}
}

static void print_result(struct bench_result *r, int use_hw)
{
	const char *verdict_color = (r->verdict == XDP_PASS) ? C_GREEN : C_YELLOW;
	const char *status = r->ok ? "" : " " C_RED "MISMATCH!" C_RESET;

	if (use_hw) {
		double ipc = (r->hw.cycles > 0)
		             ? r->hw.instructions / r->hw.cycles
		             : 0;

		printf("%-34s %s%-7s" C_RESET " %7.1f %7.2f %7.0f %8.0f %5.2f %8.2f %8d %8d%s\n",
		       r->name, verdict_color, xdp_action_str(r->verdict),
		       r->ns_per_pkt, r->mpps,
		       r->hw.instructions, r->hw.cycles,
		       ipc, r->hw.cache_misses,
		       r->map_lookups, r->helper_calls, status);
	} else {
		printf("%-34s %s%-7s" C_RESET " %7.1f %7.2f %8d %8d%s\n",
		       r->name, verdict_color, xdp_action_str(r->verdict),
		       r->ns_per_pkt, r->mpps,
		       r->map_lookups, r->helper_calls, status);
	}
}

static void print_summary(struct bench_result *results, int count, int use_hw)
{
	int fastest_idx = 0, slowest_idx = 0;
	double best_ipc = 0;
	int best_ipc_idx = 0;

	for (int i = 0; i < count; i++) {
		if (results[i].ns_per_pkt < results[fastest_idx].ns_per_pkt)
			fastest_idx = i;
		if (results[i].ns_per_pkt > results[slowest_idx].ns_per_pkt)
			slowest_idx = i;
		if (use_hw && results[i].hw.cycles > 0) {
			double ipc = results[i].hw.instructions /
			             results[i].hw.cycles;
			if (ipc > best_ipc) {
				best_ipc = ipc;
				best_ipc_idx = i;
			}
		}
	}

	printf("\n" C_BOLD "Summary:" C_RESET "\n");
	printf("  Fastest: %s (%.1f ns, %.2f Mpps)\n",
	       results[fastest_idx].name,
	       results[fastest_idx].ns_per_pkt,
	       results[fastest_idx].mpps);
	printf("  Slowest: %s (%.1f ns, %.2f Mpps)\n",
	       results[slowest_idx].name,
	       results[slowest_idx].ns_per_pkt,
	       results[slowest_idx].mpps);
	if (use_hw && best_ipc > 0) {
		printf("  Best IPC: %s (%.2f)\n",
		       results[best_ipc_idx].name, best_ipc);
	}
}

/* ===== CLI argument parsing ===== */

static struct option long_opts[] = {
    { "repeat",         required_argument, NULL, 'r' },
    { "warmup",         required_argument, NULL, 'w' },
    { "no-hwcounters",  no_argument,       NULL, 'H' },
    { "help",           no_argument,       NULL, 'h' },
    { NULL, 0, NULL, 0 },
};

static void usage(const char *prog)
{
	fprintf(stderr,
	        "Usage: %s [OPTIONS]\n\n"
	        "Options:\n"
	        "  --repeat N         Iterations per benchmark (default: %d)\n"
	        "  --warmup N         Warmup iterations (default: %d)\n"
	        "  --no-hwcounters    Skip hardware performance counters\n"
	        "  --help             Show this help\n",
	        prog, DEFAULT_REPEAT, DEFAULT_WARMUP);
}

/* ===== Main ===== */

int main(int argc, char **argv)
{
	struct tun_decap_bpf *skel;
	struct hw_counters hw = { .fd_cycles = -1, .fd_instructions = -1,
	                          .fd_cache_refs = -1, .fd_cache_misses = -1,
	                          .available = 0 };
	struct bench_result results[NUM_BENCH_ENTRIES];
	int repeat = DEFAULT_REPEAT;
	int warmup = DEFAULT_WARMUP;
	int use_hw = 1;
	int opt, err;
	int prog_fd;

	/* Parse arguments */
	while ((opt = getopt_long(argc, argv, "r:w:Hh", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'r':
			repeat = atoi(optarg);
			if (repeat < 1) {
				fprintf(stderr, "Error: repeat must be >= 1\n");
				return 1;
			}
			break;
		case 'w':
			warmup = atoi(optarg);
			break;
		case 'H':
			use_hw = 0;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	/* Check root */
	if (geteuid() != 0) {
		fprintf(stderr, "Error: Benchmarks require root privileges\n");
		fprintf(stderr, "Run with: sudo %s\n", argv[0]);
		return 1;
	}

	/* Pin to CPU for consistent measurements */
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(BENCH_CPU, &cpuset);
	if (sched_setaffinity(0, sizeof(cpuset), &cpuset) < 0)
		fprintf(stderr, "Warning: Could not pin to CPU %d: %s\n",
		        BENCH_CPU, strerror(errno));

	/* Set up libbpf */
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	/* Open and load BPF program */
	skel = tun_decap_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton: %s\n", strerror(errno));
		return 1;
	}

	err = tun_decap_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF program: %s\n", strerror(-err));
		tun_decap_bpf__destroy(skel);
		return 1;
	}

	prog_fd = bpf_program__fd(skel->progs.xdp_tun_decap);

	/* Config is a global variable in .bss (zero = all enabled) */
	skel->bss->cfg_global.disabled = 0;
	skel->bss->cfg_global.disable_gre = 0;
	skel->bss->cfg_global.disable_ipip = 0;
	skel->bss->cfg_global.disable_stats = 0;

#ifdef ENABLE_WHITELIST
	/* Set up whitelists: add all IPs that whitelisted tests need */
	int wl_fd = bpf_map__fd(skel->maps.tun_decap_whitelist);
	int wl_v6_fd = bpf_map__fd(skel->maps.tun_decap_whitelist_v6);
	whitelist_add(wl_fd, TEST_IP_WHITELISTED_1);
	whitelist_add(wl_fd, TEST_IP_WHITELISTED_2);

	__u32 v6_1[] = TEST_IPV6_WHITELISTED_1;
	__u32 v6_2[] = TEST_IPV6_WHITELISTED_2;
	__u32 v6_3[] = TEST_IPV6_WHITELISTED_3;
	whitelist_v6_add(wl_v6_fd, v6_1);
	whitelist_v6_add(wl_v6_fd, v6_2);
	whitelist_v6_add(wl_v6_fd, v6_3);
#endif

	/* Initialize hardware counters */
	if (use_hw) {
		if (hw_counters_init(&hw) < 0)
			use_hw = 0;
	}

	/* Print header */
	print_header(repeat, warmup, use_hw);

	/* Run benchmarks */
	int ok_count = 0;
	for (int i = 0; i < (int)NUM_BENCH_ENTRIES; i++) {
		err = run_bench(prog_fd, &bench_entries[i], repeat, warmup,
		                use_hw ? &hw : NULL, &results[i]);
		if (err < 0) {
			fprintf(stderr, "Benchmark failed for: %s\n", bench_entries[i].name);
			results[i].name = bench_entries[i].name;
			results[i].ns_per_pkt = -1;
			continue;
		}
		print_result(&results[i], use_hw);
		if (results[i].ok)
			ok_count++;
	}

	/* Summary */
	print_summary(results, NUM_BENCH_ENTRIES, use_hw);

	/* Verdict check */
	if (ok_count < (int)NUM_BENCH_ENTRIES) {
		printf("\n" C_RED "WARNING: %d/%d benchmarks had verdict mismatches!" C_RESET "\n",
		       (int)NUM_BENCH_ENTRIES - ok_count, (int)NUM_BENCH_ENTRIES);
	} else {
		printf("\n" C_GREEN "All %d benchmarks: verdict OK" C_RESET "\n",
		       (int)NUM_BENCH_ENTRIES);
	}

	/* Cleanup */
	hw_counters_close(&hw);
	tun_decap_bpf__destroy(skel);
	return (ok_count < (int)NUM_BENCH_ENTRIES) ? 1 : 0;
}
