#!/usr/bin/env python3
"""
XDP Tunnel Decapsulation Map Manager

Manage BPF maps for xdp-tun-decap program:
- Add/remove IPv4/IPv6 addresses to/from whitelists
- View whitelists
- Update runtime configuration
- View statistics

Requires root privileges to access BPF maps.
"""

import argparse
import ctypes
import ipaddress
import os
import struct
import sys
from pathlib import Path

# BPF syscall number (x86_64)
__NR_bpf = 321

# BPF commands
BPF_MAP_LOOKUP_ELEM = 1
BPF_MAP_UPDATE_ELEM = 2
BPF_MAP_DELETE_ELEM = 3
BPF_OBJ_GET = 7

# BPF update flags
BPF_ANY = 0
BPF_NOEXIST = 1
BPF_EXIST = 2

# Map pin paths
MAP_PIN_PATH_WHITELIST = "/sys/fs/bpf/tun_decap_whitelist"
MAP_PIN_PATH_WHITELIST_V6 = "/sys/fs/bpf/tun_decap_whitelist_v6"
MAP_PIN_PATH_STATS = "/sys/fs/bpf/tun_decap_stats"
# NOTE: Config is now a BPF global variable (not a map).
# Use bpftool to modify: find .bss map ID via `bpftool prog show`,
# then `bpftool map update id <ID> ...`

# Statistics field names from tun_decap.h (struct tun_decap_stats)
# These match the order of fields in the struct
STAT_NAMES = [
    "rx_total",
    "rx_gre",
    "rx_ipip",
    "rx_ipv6_in_ipv4",
    "rx_ipv6_outer",
    "rx_gre_ipv6_inner",
    "rx_ipip_ipv6_inner",
    "rx_ipv6_in_ipv6",
    "decap_success",
    "decap_failed",
    "drop_not_whitelisted",
    "drop_malformed",
    "drop_fragmented",
    "pass_non_tunnel",
]


# BPF syscall structures
class BpfAttrObjGet(ctypes.Structure):
    """BPF_OBJ_GET attribute structure."""

    _fields_ = [
        ("pathname", ctypes.c_uint64),
        ("bpf_fd", ctypes.c_uint32),
        ("file_flags", ctypes.c_uint32),
    ]


class BpfAttrMapOp(ctypes.Structure):
    """BPF map operation attribute structure."""

    _fields_ = [
        ("map_fd", ctypes.c_uint32),
        ("key", ctypes.c_uint64),
        ("value_or_next_key", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
    ]


class BPFMapManager:
    """Low-level BPF map manager using direct syscalls."""

    def __init__(self):
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
        return fd

    def map_lookup_elem(self, map_fd, key_bytes):
        """Lookup element in BPF map."""
        key_buf = ctypes.create_string_buffer(key_bytes)
        # For per-CPU maps, allocate enough space for all CPUs
        # Stats struct: 14 fields x 8 bytes x num_cpus = 112 x num_cpus
        # Use generous buffer size to handle any map value
        value_buf = ctypes.create_string_buffer(256 * self.num_cpus)

        attr = BpfAttrMapOp()
        attr.map_fd = map_fd
        attr.key = ctypes.cast(key_buf, ctypes.c_void_p).value
        attr.value_or_next_key = ctypes.cast(value_buf, ctypes.c_void_p).value
        attr.flags = 0

        try:
            self.bpf_syscall(BPF_MAP_LOOKUP_ELEM, attr, ctypes.sizeof(attr))
            return bytes(value_buf)
        except OSError as e:
            if e.errno == 2:  # ENOENT - key not found
                return None
            raise

    def map_update_elem(self, map_fd, key_bytes, value_bytes, flags=BPF_ANY):
        """Update element in BPF map."""
        key_buf = ctypes.create_string_buffer(key_bytes)
        value_buf = ctypes.create_string_buffer(value_bytes)

        attr = BpfAttrMapOp()
        attr.map_fd = map_fd
        attr.key = ctypes.cast(key_buf, ctypes.c_void_p).value
        attr.value_or_next_key = ctypes.cast(value_buf, ctypes.c_void_p).value
        attr.flags = flags

        self.bpf_syscall(BPF_MAP_UPDATE_ELEM, attr, ctypes.sizeof(attr))

    def map_delete_elem(self, map_fd, key_bytes):
        """Delete element from BPF map."""
        key_buf = ctypes.create_string_buffer(key_bytes)

        attr = BpfAttrMapOp()
        attr.map_fd = map_fd
        attr.key = ctypes.cast(key_buf, ctypes.c_void_p).value
        attr.value_or_next_key = 0
        attr.flags = 0

        self.bpf_syscall(BPF_MAP_DELETE_ELEM, attr, ctypes.sizeof(attr))


class XDPTunDecapManager:
    """High-level manager for xdp-tun-decap BPF maps."""

    def __init__(self):
        self.bpf = BPFMapManager()

    def _open_map(self, path):
        """Open a pinned BPF map."""
        if not Path(path).exists():
            raise FileNotFoundError(f"Map not found: {path}. Is XDP program loaded?")
        return self.bpf.bpf_obj_get(path)

    # IPv4 Whitelist operations
    def whitelist_add_ipv4(self, ip_address):
        """Add IPv4 address to whitelist."""
        ip = ipaddress.IPv4Address(ip_address)
        key = struct.pack("!I", int(ip))  # Network byte order
        value = struct.pack("B", 1)  # allowed = 1

        map_fd = self._open_map(MAP_PIN_PATH_WHITELIST)
        self.bpf.map_update_elem(map_fd, key, value, BPF_ANY)
        os.close(map_fd)
        print(f"✓ Added {ip_address} to IPv4 whitelist")

    def whitelist_remove_ipv4(self, ip_address):
        """Remove IPv4 address from whitelist."""
        ip = ipaddress.IPv4Address(ip_address)
        key = struct.pack("!I", int(ip))

        map_fd = self._open_map(MAP_PIN_PATH_WHITELIST)
        try:
            self.bpf.map_delete_elem(map_fd, key)
            print(f"✓ Removed {ip_address} from IPv4 whitelist")
        except OSError as e:
            if e.errno == 2:
                print(f"✗ {ip_address} not in whitelist")
                sys.exit(1)
            raise
        finally:
            os.close(map_fd)

    def whitelist_check_ipv4(self, ip_address):
        """Check if IPv4 address is whitelisted."""
        ip = ipaddress.IPv4Address(ip_address)
        key = struct.pack("!I", int(ip))

        map_fd = self._open_map(MAP_PIN_PATH_WHITELIST)
        result = self.bpf.map_lookup_elem(map_fd, key)
        os.close(map_fd)

        if result:
            print(f"✓ {ip_address} is whitelisted")
            return True
        else:
            print(f"✗ {ip_address} is NOT whitelisted")
            return False

    # IPv6 Whitelist operations
    def whitelist_add_ipv6(self, ip_address):
        """Add IPv6 address to whitelist."""
        ip = ipaddress.IPv6Address(ip_address)
        # IPv6 as 4x 32-bit words in network byte order
        ip_bytes = ip.packed
        key = struct.pack("!IIII", *struct.unpack("!IIII", ip_bytes))
        value = struct.pack("B", 1)

        map_fd = self._open_map(MAP_PIN_PATH_WHITELIST_V6)
        self.bpf.map_update_elem(map_fd, key, value, BPF_ANY)
        os.close(map_fd)
        print(f"✓ Added {ip_address} to IPv6 whitelist")

    def whitelist_remove_ipv6(self, ip_address):
        """Remove IPv6 address from whitelist."""
        ip = ipaddress.IPv6Address(ip_address)
        ip_bytes = ip.packed
        key = struct.pack("!IIII", *struct.unpack("!IIII", ip_bytes))

        map_fd = self._open_map(MAP_PIN_PATH_WHITELIST_V6)
        try:
            self.bpf.map_delete_elem(map_fd, key)
            print(f"✓ Removed {ip_address} from IPv6 whitelist")
        except OSError as e:
            if e.errno == 2:
                print(f"✗ {ip_address} not in whitelist")
                sys.exit(1)
            raise
        finally:
            os.close(map_fd)

    def whitelist_check_ipv6(self, ip_address):
        """Check if IPv6 address is whitelisted."""
        ip = ipaddress.IPv6Address(ip_address)
        ip_bytes = ip.packed
        key = struct.pack("!IIII", *struct.unpack("!IIII", ip_bytes))

        map_fd = self._open_map(MAP_PIN_PATH_WHITELIST_V6)
        result = self.bpf.map_lookup_elem(map_fd, key)
        os.close(map_fd)

        if result:
            print(f"✓ {ip_address} is whitelisted")
            return True
        else:
            print(f"✗ {ip_address} is NOT whitelisted")
            return False

    # Statistics operations
    def stats_show(self):
        """Show current statistics.

        The stats map contains a single entry (key=0) with a struct
        containing all 14 counters. For per-CPU maps, the value is
        an array of structs (one per CPU).
        """
        map_fd = self._open_map(MAP_PIN_PATH_STATS)

        # Read the single struct at key=0
        key = struct.pack("I", 0)
        result = self.bpf.map_lookup_elem(map_fd, key)

        if not result:
            print("Error: Could not read statistics")
            os.close(map_fd)
            return

        # Parse per-CPU structs: each CPU has 14 uint64 fields
        num_fields = len(STAT_NAMES)
        values_per_cpu = struct.unpack(f"{self.bpf.num_cpus * num_fields}Q", result)

        print("Statistics (aggregated across all CPUs):")
        print("-" * 50)

        # Aggregate each field across all CPUs
        for field_idx, name in enumerate(STAT_NAMES):
            total = 0
            for cpu in range(self.bpf.num_cpus):
                # Extract the field value for this CPU
                offset = cpu * num_fields + field_idx
                total += values_per_cpu[offset]

            print(f"  {name:25s}: {total:>15,}")

        os.close(map_fd)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Manage xdp-tun-decap BPF maps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # IPv4 whitelist
  %(prog)s whitelist-add 10.200.0.20
  %(prog)s whitelist-remove 10.200.0.20
  %(prog)s whitelist-check 10.200.0.20

  # IPv6 whitelist
  %(prog)s whitelist-add 2001:db8::1
  %(prog)s whitelist-remove 2001:db8::1
  %(prog)s whitelist-check 2001:db8::1

  # Statistics
  %(prog)s stats
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Whitelist commands
    add_parser = subparsers.add_parser(
        "whitelist-add", help="Add IP to whitelist"
    )
    add_parser.add_argument("ip", help="IPv4 or IPv6 address")

    remove_parser = subparsers.add_parser(
        "whitelist-remove", help="Remove IP from whitelist"
    )
    remove_parser.add_argument("ip", help="IPv4 or IPv6 address")

    check_parser = subparsers.add_parser(
        "whitelist-check", help="Check if IP is whitelisted"
    )
    check_parser.add_argument("ip", help="IPv4 or IPv6 address")

    # Stats commands
    subparsers.add_parser("stats", help="Show statistics")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Check if running as root
    if os.geteuid() != 0:
        print("Error: This program must be run as root to access BPF maps")
        sys.exit(1)

    manager = XDPTunDecapManager()

    try:
        # Whitelist operations
        if args.command == "whitelist-add":
            ip = ipaddress.ip_address(args.ip)
            if ip.version == 4:
                manager.whitelist_add_ipv4(str(ip))
            else:
                manager.whitelist_add_ipv6(str(ip))

        elif args.command == "whitelist-remove":
            ip = ipaddress.ip_address(args.ip)
            if ip.version == 4:
                manager.whitelist_remove_ipv4(str(ip))
            else:
                manager.whitelist_remove_ipv6(str(ip))

        elif args.command == "whitelist-check":
            ip = ipaddress.ip_address(args.ip)
            if ip.version == 4:
                manager.whitelist_check_ipv4(str(ip))
            else:
                manager.whitelist_check_ipv6(str(ip))

        # Stats operations
        elif args.command == "stats":
            manager.stats_show()

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
