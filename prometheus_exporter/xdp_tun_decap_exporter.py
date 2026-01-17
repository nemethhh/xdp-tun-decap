#!/usr/bin/env python3
"""
XDP Tunnel Decapsulation Prometheus Exporter (Improved Version)

Uses direct BPF syscalls via ctypes for more reliable pinned map access.
This version works with any BPF map without requiring BCC.

Requires:
- prometheus_client
- Root privileges to read BPF maps
"""

import argparse
import ctypes
import logging
import os
import sys
import time
from pathlib import Path

from prometheus_client import Gauge, start_http_server

# BPF syscall number (x86_64)
__NR_bpf = 321

# BPF commands
BPF_MAP_LOOKUP_ELEM = 1
BPF_OBJ_GET = 7

# Map pin paths
MAP_PIN_PATH_STATS = "/sys/fs/bpf/tun_decap_stats"

# Statistics indices
STAT_RX_TOTAL = 0
STAT_RX_GRE = 1
STAT_RX_IPIP = 2
STAT_RX_IPV6_IN_IPV4 = 3
STAT_RX_IPV6_OUTER = 4
STAT_RX_GRE_IPV6_INNER = 5
STAT_RX_IPIP_IPV6_INNER = 6
STAT_DECAP_SUCCESS = 7
STAT_DECAP_FAILED = 8
STAT_DROP_NOT_WHITELISTED = 9
STAT_DROP_MALFORMED = 10
STAT_PASS_NON_TUNNEL = 11
STAT_MAX = 12

# Metric definitions
METRIC_DEFINITIONS = [
    ("xdp_tun_decap_rx_total", "Total packets received", STAT_RX_TOTAL),
    ("xdp_tun_decap_rx_gre", "GRE tunnel packets received", STAT_RX_GRE),
    ("xdp_tun_decap_rx_ipip", "IPIP tunnel packets received", STAT_RX_IPIP),
    ("xdp_tun_decap_rx_ipv6_in_ipv4", "IPv6-in-IPv4 tunnel packets received", STAT_RX_IPV6_IN_IPV4),
    ("xdp_tun_decap_rx_ipv6_outer", "Packets with IPv6 outer header", STAT_RX_IPV6_OUTER),
    ("xdp_tun_decap_rx_gre_ipv6_inner", "GRE with IPv6 inner packet", STAT_RX_GRE_IPV6_INNER),
    ("xdp_tun_decap_rx_ipip_ipv6_inner", "IPIP with IPv6 inner packet", STAT_RX_IPIP_IPV6_INNER),
    ("xdp_tun_decap_decap_success", "Packets successfully decapsulated", STAT_DECAP_SUCCESS),
    ("xdp_tun_decap_decap_failed", "Decapsulation failures", STAT_DECAP_FAILED),
    (
        "xdp_tun_decap_drop_not_whitelisted",
        "Dropped (source not whitelisted)",
        STAT_DROP_NOT_WHITELISTED,
    ),
    ("xdp_tun_decap_drop_malformed", "Dropped (malformed packet)", STAT_DROP_MALFORMED),
    ("xdp_tun_decap_pass_non_tunnel", "Non-tunnel traffic passed", STAT_PASS_NON_TUNNEL),
]


# BPF syscall structures
class BpfAttrObjGet(ctypes.Structure):
    """BPF_OBJ_GET attribute structure."""

    _fields_ = [
        ("pathname", ctypes.c_uint64),
        ("bpf_fd", ctypes.c_uint32),
        ("file_flags", ctypes.c_uint32),
    ]


class BpfAttrMapLookup(ctypes.Structure):
    """BPF_MAP_LOOKUP_ELEM attribute structure."""

    _fields_ = [
        ("map_fd", ctypes.c_uint32),
        ("key", ctypes.c_uint64),
        ("value", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
    ]


class BPFMapReader:
    """Low-level BPF map reader using direct syscalls."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.libc = ctypes.CDLL("libc.so.6", use_errno=True)
        self.num_cpus = os.cpu_count()

    def bpf_syscall(self, cmd, attr, size):
        """Make a BPF syscall."""
        result = self.libc.syscall(__NR_bpf, cmd, ctypes.byref(attr), size)
        if result < 0:
            errno = ctypes.get_errno()
            raise OSError(errno, os.strerror(errno))
        return result

    def bpf_obj_get(self, pathname):
        """Get FD for a pinned BPF object."""
        pathname_bytes = pathname.encode("utf-8") + b"\x00"
        pathname_buf = ctypes.create_string_buffer(pathname_bytes)

        attr = BpfAttrObjGet()
        attr.pathname = ctypes.cast(pathname_buf, ctypes.c_void_p).value
        attr.bpf_fd = 0
        attr.file_flags = 0

        fd = self.bpf_syscall(BPF_OBJ_GET, attr, ctypes.sizeof(attr))
        self.logger.debug("Opened map FD %d for %s", fd, pathname)
        return fd

    def map_lookup_elem(self, map_fd, key, value_size):
        """Lookup element in BPF map."""
        key_buf = ctypes.c_uint32(key)
        value_buf = (ctypes.c_uint64 * (value_size // 8))()

        attr = BpfAttrMapLookup()
        attr.map_fd = map_fd
        attr.key = ctypes.cast(ctypes.pointer(key_buf), ctypes.c_void_p).value
        attr.value = ctypes.cast(ctypes.pointer(value_buf), ctypes.c_void_p).value
        attr.flags = 0

        try:
            self.bpf_syscall(BPF_MAP_LOOKUP_ELEM, attr, ctypes.sizeof(attr))
            return list(value_buf)
        except OSError as e:
            if e.errno == 2:  # ENOENT - key not found
                return [0] * (value_size // 8)
            raise


class XDPTunDecapExporter:
    """Prometheus exporter for XDP tunnel decapsulation statistics."""

    def __init__(self, map_path=MAP_PIN_PATH_STATS):
        """Initialize the exporter."""
        self.map_path = map_path
        self.logger = logging.getLogger(__name__)
        self.metrics = {}
        self.bpf_reader = BPFMapReader()
        self.map_fd = None
        self.num_cpus = os.cpu_count()

        # Initialize Prometheus metrics
        for name, description, _ in METRIC_DEFINITIONS:
            self.metrics[name] = Gauge(name, description)

        self.logger.info("Initialized %d Prometheus metrics", len(self.metrics))
        self.logger.info("Number of CPUs: %d", self.num_cpus)

    def open_map(self):
        """Open the pinned BPF stats map."""
        if not Path(self.map_path).exists():
            raise FileNotFoundError(
                f"BPF stats map not found at {self.map_path}. " "Is the XDP program loaded?"
            )

        try:
            self.map_fd = self.bpf_reader.bpf_obj_get(self.map_path)
            self.logger.info("Opened BPF stats map: %s (FD: %d)", self.map_path, self.map_fd)
        except Exception as e:
            raise RuntimeError(f"Failed to open BPF map: {e}") from e

    def read_percpu_stat(self, stat_idx):
        """Read and aggregate per-CPU statistic.

        For per-CPU arrays, the value is an array of uint64 (one per CPU).
        We need to sum across all CPUs.
        """
        try:
            # Value size = 8 bytes (uint64) * number of CPUs
            value_size = 8 * self.num_cpus
            values = self.bpf_reader.map_lookup_elem(self.map_fd, stat_idx, value_size)

            # Sum across all CPUs
            total = sum(values)
            return total
        except Exception as e:
            self.logger.error("Error reading stat %d: %s", stat_idx, e)
            return 0

    def update_metrics(self):
        """Update all Prometheus metrics with current BPF map values."""
        for name, _, stat_idx in METRIC_DEFINITIONS:
            value = self.read_percpu_stat(stat_idx)
            self.metrics[name].set(value)
            self.logger.debug("%s = %s", name, value)

    def run(self, scrape_interval=5):
        """Run the exporter update loop."""
        self.logger.info("Starting metric update loop (interval: %ds)", scrape_interval)

        while True:
            try:
                self.update_metrics()
            except Exception as e:
                self.logger.error("Error updating metrics: %s", e, exc_info=True)

            time.sleep(scrape_interval)

    def close(self):
        """Close the BPF map file descriptor."""
        if self.map_fd is not None:
            os.close(self.map_fd)
            self.logger.info("Closed BPF map FD")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Prometheus exporter for xdp-tun-decap statistics")
    parser.add_argument(
        "-a",
        "--address",
        type=str,
        default="0.0.0.0",
        help="IP address to bind to (default: 0.0.0.0 - all interfaces)",
    )
    parser.add_argument(
        "-p", "--port", type=int, default=9100, help="Prometheus metrics HTTP port (default: 9100)"
    )
    parser.add_argument(
        "-i",
        "--interval",
        type=int,
        default=5,
        help="Metric update interval in seconds (default: 5)",
    )
    parser.add_argument(
        "-m",
        "--map-path",
        default=MAP_PIN_PATH_STATS,
        help=f"Path to pinned BPF stats map (default: {MAP_PIN_PATH_STATS})",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Set logging level (default: INFO)",
    )

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else getattr(logging, args.log_level)
    logging.basicConfig(
        level=log_level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    logger = logging.getLogger(__name__)

    # Check if running as root
    if os.geteuid() != 0:
        logger.error("This program must be run as root to access BPF maps")
        sys.exit(1)

    exporter = None
    try:
        # Initialize exporter
        exporter = XDPTunDecapExporter(map_path=args.map_path)
        exporter.open_map()

        # Start Prometheus HTTP server
        start_http_server(args.port, addr=args.address)
        logger.info("Prometheus metrics server started on %s:%d", args.address, args.port)
        logger.info("Metrics available at http://%s:%d/metrics", args.address, args.port)

        # Run update loop
        exporter.run(scrape_interval=args.interval)

    except KeyboardInterrupt:
        logger.info("Exporter stopped by user")
        if exporter:
            exporter.close()
        sys.exit(0)
    except Exception as e:
        logger.error("Fatal error: %s", e, exc_info=True)
        if exporter:
            exporter.close()
        sys.exit(1)


if __name__ == "__main__":
    main()
