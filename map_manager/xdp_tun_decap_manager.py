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
MAP_PIN_PATH_CONFIG = "/sys/fs/bpf/tun_decap_config"

# Statistics indices from tun_decap.h
STAT_NAMES = [
    "rx_total",
    "rx_gre",
    "rx_ipip",
    "rx_ipv6_in_ipv4",
    "rx_ipv6_outer",
    "rx_gre_ipv6_inner",
    "rx_ipip_ipv6_inner",
    "decap_success",
    "decap_failed",
    "drop_not_whitelisted",
    "drop_malformed",
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
        value_buf = ctypes.create_string_buffer(8 * self.num_cpus)

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

    # Configuration operations
    def config_set(
        self, disabled=None, disable_gre=None, disable_ipip=None, disable_stats=None
    ):
        """Update runtime configuration."""
        # Read current config
        map_fd = self._open_map(MAP_PIN_PATH_CONFIG)
        key = struct.pack("I", 0)

        current = self.bpf.map_lookup_elem(map_fd, key)
        if current:
            (
                current_disabled,
                current_gre,
                current_ipip,
                current_stats,
            ) = struct.unpack("BBBB", current[:4])
        else:
            current_disabled = current_gre = current_ipip = current_stats = 0

        # Update values
        new_disabled = disabled if disabled is not None else current_disabled
        new_gre = disable_gre if disable_gre is not None else current_gre
        new_ipip = disable_ipip if disable_ipip is not None else current_ipip
        new_stats = disable_stats if disable_stats is not None else current_stats

        value = struct.pack("BBBB", new_disabled, new_gre, new_ipip, new_stats)
        self.bpf.map_update_elem(map_fd, key, value, BPF_ANY)
        os.close(map_fd)

        print("✓ Configuration updated:")
        print(f"  All processing:  {'DISABLED' if new_disabled else 'enabled'}")
        print(f"  GRE processing:  {'DISABLED' if new_gre else 'enabled'}")
        print(f"  IPIP processing: {'DISABLED' if new_ipip else 'enabled'}")
        print(f"  Statistics:      {'DISABLED' if new_stats else 'enabled'}")

    def config_show(self):
        """Show current configuration."""
        map_fd = self._open_map(MAP_PIN_PATH_CONFIG)
        key = struct.pack("I", 0)

        result = self.bpf.map_lookup_elem(map_fd, key)
        os.close(map_fd)

        if result:
            disabled, disable_gre, disable_ipip, disable_stats = struct.unpack(
                "BBBB", result[:4]
            )
        else:
            disabled = disable_gre = disable_ipip = disable_stats = 0

        print("Current configuration:")
        print(f"  All processing:  {'DISABLED' if disabled else 'enabled'}")
        print(f"  GRE processing:  {'DISABLED' if disable_gre else 'enabled'}")
        print(f"  IPIP processing: {'DISABLED' if disable_ipip else 'enabled'}")
        print(f"  Statistics:      {'DISABLED' if disable_stats else 'enabled'}")

    # Statistics operations
    def stats_show(self):
        """Show current statistics."""
        map_fd = self._open_map(MAP_PIN_PATH_STATS)

        print("Statistics (aggregated across all CPUs):")
        print("-" * 50)
        for idx, name in enumerate(STAT_NAMES):
            key = struct.pack("I", idx)
            result = self.bpf.map_lookup_elem(map_fd, key)

            if result:
                # Sum per-CPU values
                values = struct.unpack(f"{self.bpf.num_cpus}Q", result)
                total = sum(values)
                print(f"  {name:25s}: {total:>15,}")
            else:
                print(f"  {name:25s}: {0:>15}")

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

  # Configuration
  %(prog)s config-show
  %(prog)s config-disable-all
  %(prog)s config-enable-all
  %(prog)s config-disable-gre
  %(prog)s config-enable-gre
  %(prog)s config-disable-stats
  %(prog)s config-enable-stats

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

    # Config commands
    subparsers.add_parser("config-show", help="Show current configuration")
    subparsers.add_parser("config-disable-all", help="Disable all processing")
    subparsers.add_parser("config-enable-all", help="Enable all processing")
    subparsers.add_parser("config-disable-gre", help="Disable GRE processing")
    subparsers.add_parser("config-enable-gre", help="Enable GRE processing")
    subparsers.add_parser("config-disable-ipip", help="Disable IPIP processing")
    subparsers.add_parser("config-enable-ipip", help="Enable IPIP processing")
    subparsers.add_parser("config-disable-stats", help="Disable statistics collection")
    subparsers.add_parser("config-enable-stats", help="Enable statistics collection")

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

        # Config operations
        elif args.command == "config-show":
            manager.config_show()

        elif args.command == "config-disable-all":
            manager.config_set(disabled=1)

        elif args.command == "config-enable-all":
            manager.config_set(disabled=0)

        elif args.command == "config-disable-gre":
            manager.config_set(disable_gre=1)

        elif args.command == "config-enable-gre":
            manager.config_set(disable_gre=0)

        elif args.command == "config-disable-ipip":
            manager.config_set(disable_ipip=1)

        elif args.command == "config-enable-ipip":
            manager.config_set(disable_ipip=0)

        elif args.command == "config-disable-stats":
            manager.config_set(disable_stats=1)

        elif args.command == "config-enable-stats":
            manager.config_set(disable_stats=0)

        # Stats operations
        elif args.command == "stats":
            manager.stats_show()

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
