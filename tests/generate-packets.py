#!/usr/bin/env python3
"""
Generate test tunnel packets for XDP decapsulation testing.

This script creates GRE and IPIP encapsulated packets to test
the XDP tunnel decapsulation program.
"""

import sys
import argparse
from scapy.all import (
    Ether, IP, IPv6, UDP, GRE, TCP, ICMP, ICMPv6EchoRequest, ARP,
    sendp, Raw, conf, get_if_hwaddr, srp
)


def get_mac_for_ip(ip, iface="eth0"):
    """Get MAC address for an IP using ARP."""
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, iface=iface, verbose=False)
        if ans:
            return ans[0][1][Ether].src
    except:
        pass
    # Fallback to broadcast
    return "ff:ff:ff:ff:ff:ff"


def send_gre_ipv4_packet(src_ip, dst_ip, inner_src, inner_dst, iface="eth0", count=1):
    """Send GRE-encapsulated IPv4 packet with unique payload."""
    dst_mac = get_mac_for_ip(dst_ip, iface)
    src_mac = get_if_hwaddr(iface)

    outer = IP(src=src_ip, dst=dst_ip, proto=47)
    gre = GRE(proto=0x0800)  # IPv4
    # Add unique payload marker for verification
    payload = Raw(b"TEST_GRE_IPV4_BASIC")
    inner = IP(src=inner_src, dst=inner_dst) / ICMP(type=8, code=0) / payload

    packet = Ether(src=src_mac, dst=dst_mac) / outer / gre / inner

    print(f"Sending {count} GRE IPv4 packet(s): {src_ip} -> {dst_ip} (inner: {inner_src} -> {inner_dst})")
    print(f"  Payload marker: TEST_GRE_IPV4_BASIC")
    sendp(packet, iface=iface, count=count, verbose=False)


def send_gre_ipv4_with_checksum(src_ip, dst_ip, inner_src, inner_dst, iface="eth0", count=1):
    """Send GRE packet with checksum flag and unique payload."""
    dst_mac = get_mac_for_ip(dst_ip, iface)
    src_mac = get_if_hwaddr(iface)

    outer = IP(src=src_ip, dst=dst_ip, proto=47)
    gre = GRE(proto=0x0800, chksum_present=1)
    # Unique payload for this test
    inner = IP(src=inner_src, dst=inner_dst) / UDP(dport=80, sport=12345) / Raw(b"TEST_GRE_CHECKSUM_MARKER")

    packet = Ether(src=src_mac, dst=dst_mac) / outer / gre / inner

    print(f"Sending {count} GRE IPv4 packet(s) with checksum: {src_ip} -> {dst_ip}")
    print(f"  Payload marker: TEST_GRE_CHECKSUM_MARKER")
    sendp(packet, iface=iface, count=count, verbose=False)


def send_gre_ipv4_with_key(src_ip, dst_ip, inner_src, inner_dst, iface="eth0", count=1):
    """Send GRE packet with key field and unique payload."""
    dst_mac = get_mac_for_ip(dst_ip, iface)
    src_mac = get_if_hwaddr(iface)

    outer = IP(src=src_ip, dst=dst_ip, proto=47)
    gre = GRE(proto=0x0800, key_present=1, key=305419896)  # 0x12345678 as decimal
    inner = IP(src=inner_src, dst=inner_dst) / TCP(dport=443, sport=54321) / Raw(b"TEST_GRE_KEY_0x12345678")

    packet = Ether(src=src_mac, dst=dst_mac) / outer / gre / inner

    print(f"Sending {count} GRE IPv4 packet(s) with key: {src_ip} -> {dst_ip}")
    print(f"  Payload marker: TEST_GRE_KEY_0x12345678")
    sendp(packet, iface=iface, count=count, verbose=False)


def send_gre_ipv4_with_sequence(src_ip, dst_ip, inner_src, inner_dst, iface="eth0", count=1):
    """Send GRE packet with sequence number and unique payload."""
    dst_mac = get_mac_for_ip(dst_ip, iface)
    src_mac = get_if_hwaddr(iface)

    outer = IP(src=src_ip, dst=dst_ip, proto=47)
    gre = GRE(proto=0x0800, seqnum_present=1, seqence_number=1)
    payload = Raw(b"TEST_GRE_SEQUENCE_NUM")
    inner = IP(src=inner_src, dst=inner_dst) / ICMP(type=8, code=0) / payload

    packet = Ether(src=src_mac, dst=dst_mac) / outer / gre / inner

    print(f"Sending {count} GRE IPv4 packet(s) with sequence: {src_ip} -> {dst_ip}")
    print(f"  Payload marker: TEST_GRE_SEQUENCE_NUM")
    sendp(packet, iface=iface, count=count, verbose=False)


def send_gre_ipv4_all_flags(src_ip, dst_ip, inner_src, inner_dst, iface="eth0", count=1):
    """Send GRE packet with all optional fields (checksum, key, sequence) and unique payload."""
    dst_mac = get_mac_for_ip(dst_ip, iface)
    src_mac = get_if_hwaddr(iface)

    outer = IP(src=src_ip, dst=dst_ip, proto=47)
    gre = GRE(proto=0x0800, chksum_present=1, key_present=1, key=0xDEADBEEF, seqnum_present=1, seqence_number=42)
    inner = IP(src=inner_src, dst=inner_dst) / UDP(dport=53, sport=12345) / Raw(b"TEST_GRE_ALL_FLAGS_DEADBEEF")

    packet = Ether(src=src_mac, dst=dst_mac) / outer / gre / inner

    print(f"Sending {count} GRE IPv4 packet(s) with all flags: {src_ip} -> {dst_ip}")
    print(f"  Payload marker: TEST_GRE_ALL_FLAGS_DEADBEEF")
    sendp(packet, iface=iface, count=count, verbose=False)


def send_gre_ipv4_with_routing(src_ip, dst_ip, inner_src, inner_dst, iface="eth0", count=1):
    """Send GRE packet with routing bit (deprecated but should be handled) and unique payload."""
    dst_mac = get_mac_for_ip(dst_ip, iface)
    src_mac = get_if_hwaddr(iface)

    outer = IP(src=src_ip, dst=dst_ip, proto=47)
    # Scapy doesn't have direct routing support, so we'll manually set flags
    gre = GRE(proto=0x0800)
    # Modify flags to include routing bit (0x4000)
    gre.flags_version = 0x4000
    payload = Raw(b"TEST_GRE_ROUTING_BIT")
    inner = IP(src=inner_src, dst=inner_dst) / ICMP(type=8, code=0) / payload

    packet = Ether(src=src_mac, dst=dst_mac) / outer / gre / inner

    print(f"Sending {count} GRE IPv4 packet(s) with routing bit: {src_ip} -> {dst_ip}")
    print(f"  Payload marker: TEST_GRE_ROUTING_BIT")
    sendp(packet, iface=iface, count=count, verbose=False)


def send_truncated_gre_packet(src_ip, dst_ip, iface="eth0"):
    """Send truncated GRE packet (header incomplete)."""
    dst_mac = get_mac_for_ip(dst_ip, iface)
    src_mac = get_if_hwaddr(iface)

    outer = IP(src=src_ip, dst=dst_ip, proto=47)
    # Create incomplete GRE header - only 2 bytes instead of 4
    incomplete_gre = Raw(b"\x00\x00")

    packet = Ether(src=src_mac, dst=dst_mac) / outer / incomplete_gre

    print(f"Sending truncated GRE packet: {src_ip} -> {dst_ip}")
    sendp(packet, iface=iface, count=1, verbose=False)


def send_gre_with_invalid_optional_fields(src_ip, dst_ip, inner_src, inner_dst, iface="eth0"):
    """Send GRE packet claiming to have optional fields but truncated."""
    dst_mac = get_mac_for_ip(dst_ip, iface)
    src_mac = get_if_hwaddr(iface)

    outer = IP(src=src_ip, dst=dst_ip, proto=47)
    # Set flags indicating checksum+key+sequence but don't include the data
    # This creates a malformed packet
    gre_flags = 0xB000  # checksum + key + sequence bits
    incomplete_gre = Raw(bytes([
        (gre_flags >> 8) & 0xFF,
        gre_flags & 0xFF,
        0x08, 0x00  # IPv4 protocol
        # Missing the 12 bytes of optional fields!
    ]))
    inner = IP(src=inner_src, dst=inner_dst) / ICMP()

    packet = Ether(src=src_mac, dst=dst_mac) / outer / incomplete_gre / inner

    print(f"Sending GRE with invalid optional fields: {src_ip} -> {dst_ip}")
    sendp(packet, iface=iface, count=1, verbose=False)


def send_ipip_large_payload(src_ip, dst_ip, inner_src, inner_dst, iface="eth0", count=1):
    """Send IPIP packet with large payload to test MTU edge cases."""
    dst_mac = get_mac_for_ip(dst_ip, iface)
    src_mac = get_if_hwaddr(iface)

    outer = IP(src=src_ip, dst=dst_ip, proto=4)
    # Create large payload with unique marker at start (1400 bytes total)
    marker = b"TEST_IPIP_LARGE_PAYLOAD_1400B:"
    large_payload = marker + (b"X" * (1400 - len(marker)))
    inner = IP(src=inner_src, dst=inner_dst) / ICMP(type=8, code=0) / Raw(large_payload)

    packet = Ether(src=src_mac, dst=dst_mac) / outer / inner

    print(f"Sending {count} IPIP packet(s) with large payload: {src_ip} -> {dst_ip}")
    print(f"  Payload marker: TEST_IPIP_LARGE_PAYLOAD_1400B")
    sendp(packet, iface=iface, count=count, verbose=False)


def send_mixed_traffic_burst(src_ip, dst_ip, inner_src, inner_dst, iface="eth0"):
    """Send burst of mixed traffic types."""
    dst_mac = get_mac_for_ip(dst_ip, iface)
    src_mac = get_if_hwaddr(iface)

    packets = []

    # Plain traffic
    packets.append(Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / ICMP())

    # GRE IPv4
    packets.append(Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip, proto=47) /
                   GRE(proto=0x0800) / IP(src=inner_src, dst=inner_dst) / ICMP())

    # IPIP
    packets.append(Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip, proto=4) /
                   IP(src=inner_src, dst=inner_dst) / ICMP())

    # Plain UDP
    packets.append(Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) /
                   UDP(dport=80, sport=12345) / Raw(b"HTTP GET"))

    # GRE with key
    packets.append(Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip, proto=47) /
                   GRE(proto=0x0800, key_present=1, key=0x12345678) /
                   IP(src=inner_src, dst=inner_dst) / TCP(dport=443))

    print(f"Sending burst of {len(packets)} mixed packets: {src_ip} -> {dst_ip}")
    sendp(packets, iface=iface, verbose=False)


def send_ipip_packet(src_ip, dst_ip, inner_src, inner_dst, iface="eth0", count=1):
    """Send IPIP-encapsulated packet with unique payload."""
    dst_mac = get_mac_for_ip(dst_ip, iface)
    src_mac = get_if_hwaddr(iface)

    outer = IP(src=src_ip, dst=dst_ip, proto=4)  # IPIP
    payload = Raw(b"TEST_IPIP_IPV4_IN_IPV4")
    inner = IP(src=inner_src, dst=inner_dst) / ICMP(type=8, code=0) / payload

    packet = Ether(src=src_mac, dst=dst_mac) / outer / inner

    print(f"Sending {count} IPIP packet(s): {src_ip} -> {dst_ip} (inner: {inner_src} -> {inner_dst})")
    print(f"  Payload marker: TEST_IPIP_IPV4_IN_IPV4")
    sendp(packet, iface=iface, count=count, verbose=False)


def send_plain_traffic(src_ip, dst_ip, iface="eth0", count=1):
    """Send regular non-tunnel traffic."""
    dst_mac = get_mac_for_ip(dst_ip, iface)
    src_mac = get_if_hwaddr(iface)

    packet = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / ICMP()

    print(f"Sending {count} plain ICMP packet(s): {src_ip} -> {dst_ip}")
    sendp(packet, iface=iface, count=count, verbose=False)


def send_invalid_gre_version(src_ip, dst_ip, inner_src, inner_dst, iface="eth0"):
    """Send GRE packet with invalid version (should be dropped)."""
    dst_mac = get_mac_for_ip(dst_ip, iface)
    src_mac = get_if_hwaddr(iface)

    outer = IP(src=src_ip, dst=dst_ip, proto=47)
    gre = GRE(proto=0x0800, version=1)
    inner = IP(src=inner_src, dst=inner_dst) / ICMP()

    packet = Ether(src=src_mac, dst=dst_mac) / outer / gre / inner

    print(f"Sending GRE packet with invalid version: {src_ip} -> {dst_ip}")
    sendp(packet, iface=iface, count=1, verbose=False)


# ============== IPv6 Packet Generation Functions ==============

def send_gre_ipv6_outer_ipv4_inner(src_ip, dst_ip, inner_src, inner_dst, iface="eth0", count=1):
    """Send GRE packet with IPv6 outer header and IPv4 inner packet."""
    dst_mac = get_mac_for_ip(dst_ip, iface)
    src_mac = get_if_hwaddr(iface)

    # IPv6 outer header with GRE (next header 47)
    outer = IPv6(src=src_ip, dst=dst_ip, nh=47)
    gre = GRE(proto=0x0800)  # IPv4 inner
    payload = Raw(b"TEST_GRE_IPV6_OUTER_IPV4_INNER")
    inner = IP(src=inner_src, dst=inner_dst) / ICMP(type=8, code=0) / payload

    packet = Ether(src=src_mac, dst=dst_mac) / outer / gre / inner

    print(f"Sending {count} GRE IPv6 outer + IPv4 inner packet(s): {src_ip} -> {dst_ip}")
    print(f"  Payload marker: TEST_GRE_IPV6_OUTER_IPV4_INNER")
    sendp(packet, iface=iface, count=count, verbose=False)


def send_gre_ipv6_outer_ipv6_inner(src_ip, dst_ip, inner_src, inner_dst, iface="eth0", count=1):
    """Send GRE packet with IPv6 outer header and IPv6 inner packet."""
    dst_mac = get_mac_for_ip(dst_ip, iface)
    src_mac = get_if_hwaddr(iface)

    # IPv6 outer header with GRE (next header 47)
    outer = IPv6(src=src_ip, dst=dst_ip, nh=47)
    gre = GRE(proto=0x86DD)  # IPv6 inner (0x86DD)
    payload = Raw(b"TEST_GRE_IPV6_OUTER_IPV6_INNER")
    inner = IPv6(src=inner_src, dst=inner_dst) / ICMPv6EchoRequest() / payload

    packet = Ether(src=src_mac, dst=dst_mac) / outer / gre / inner

    print(f"Sending {count} GRE IPv6 outer + IPv6 inner packet(s): {src_ip} -> {dst_ip}")
    print(f"  Payload marker: TEST_GRE_IPV6_OUTER_IPV6_INNER")
    sendp(packet, iface=iface, count=count, verbose=False)


def send_gre_ipv6_all_flags(src_ip, dst_ip, inner_src, inner_dst, iface="eth0", count=1):
    """Send GRE packet with IPv6 outer and all optional fields."""
    dst_mac = get_mac_for_ip(dst_ip, iface)
    src_mac = get_if_hwaddr(iface)

    # IPv6 outer header with GRE (next header 47)
    outer = IPv6(src=src_ip, dst=dst_ip, nh=47)
    gre = GRE(proto=0x0800, chksum_present=1, key_present=1, key=0xABCD1234,
              seqnum_present=1, seqence_number=99)
    payload = Raw(b"TEST_GRE_IPV6_ALL_FLAGS")
    inner = IP(src=inner_src, dst=inner_dst) / UDP(dport=53, sport=12345) / payload

    packet = Ether(src=src_mac, dst=dst_mac) / outer / gre / inner

    print(f"Sending {count} GRE IPv6 outer with all flags packet(s): {src_ip} -> {dst_ip}")
    print(f"  Payload marker: TEST_GRE_IPV6_ALL_FLAGS")
    sendp(packet, iface=iface, count=count, verbose=False)


def send_ipip_ipv4_in_ipv6(src_ip, dst_ip, inner_src, inner_dst, iface="eth0", count=1):
    """Send IPv4-in-IPv6 tunnel packet (protocol 4)."""
    dst_mac = get_mac_for_ip(dst_ip, iface)
    src_mac = get_if_hwaddr(iface)

    # IPv6 outer header with next header = 4 (IPv4)
    outer = IPv6(src=src_ip, dst=dst_ip, nh=4)
    payload = Raw(b"TEST_IPIP_IPV4_IN_IPV6")
    inner = IP(src=inner_src, dst=inner_dst) / ICMP(type=8, code=0) / payload

    packet = Ether(src=src_mac, dst=dst_mac) / outer / inner

    print(f"Sending {count} IPv4-in-IPv6 packet(s): {src_ip} -> {dst_ip}")
    print(f"  Payload marker: TEST_IPIP_IPV4_IN_IPV6")
    sendp(packet, iface=iface, count=count, verbose=False)


def send_ipip_ipv6_in_ipv4(src_ip, dst_ip, inner_src, inner_dst, iface="eth0", count=1):
    """Send IPv6-in-IPv4 tunnel packet (protocol 41)."""
    dst_mac = get_mac_for_ip(dst_ip, iface)
    src_mac = get_if_hwaddr(iface)

    # IPv4 outer header with protocol = 41 (IPv6)
    outer = IP(src=src_ip, dst=dst_ip, proto=41)
    payload = Raw(b"TEST_IPIP_IPV6_IN_IPV4")
    inner = IPv6(src=inner_src, dst=inner_dst) / ICMPv6EchoRequest() / payload

    packet = Ether(src=src_mac, dst=dst_mac) / outer / inner

    print(f"Sending {count} IPv6-in-IPv4 packet(s): {src_ip} -> {dst_ip}")
    print(f"  Payload marker: TEST_IPIP_IPV6_IN_IPV4")
    sendp(packet, iface=iface, count=count, verbose=False)


def send_ipip_ipv6_in_ipv6(src_ip, dst_ip, inner_src, inner_dst, iface="eth0", count=1):
    """Send IPv6-in-IPv6 tunnel packet (protocol 41)."""
    dst_mac = get_mac_for_ip(dst_ip, iface)
    src_mac = get_if_hwaddr(iface)

    # IPv6 outer header with next header = 41 (IPv6)
    outer = IPv6(src=src_ip, dst=dst_ip, nh=41)
    payload = Raw(b"TEST_IPIP_IPV6_IN_IPV6")
    inner = IPv6(src=inner_src, dst=inner_dst) / ICMPv6EchoRequest() / payload

    packet = Ether(src=src_mac, dst=dst_mac) / outer / inner

    print(f"Sending {count} IPv6-in-IPv6 packet(s): {src_ip} -> {dst_ip}")
    print(f"  Payload marker: TEST_IPIP_IPV6_IN_IPV6")
    sendp(packet, iface=iface, count=count, verbose=False)


def send_ipv6_large_payload(src_ip, dst_ip, inner_src, inner_dst, iface="eth0", count=1):
    """Send IPv6 GRE packet with large payload."""
    dst_mac = get_mac_for_ip(dst_ip, iface)
    src_mac = get_if_hwaddr(iface)

    # IPv6 outer header with GRE
    outer = IPv6(src=src_ip, dst=dst_ip, nh=47)
    gre = GRE(proto=0x0800)
    # Create large payload with unique marker
    marker = b"TEST_IPV6_LARGE_PAYLOAD_1400B:"
    large_payload = marker + (b"Y" * (1400 - len(marker)))
    inner = IP(src=inner_src, dst=inner_dst) / ICMP(type=8, code=0) / Raw(large_payload)

    packet = Ether(src=src_mac, dst=dst_mac) / outer / gre / inner

    print(f"Sending {count} IPv6 GRE packet(s) with large payload: {src_ip} -> {dst_ip}")
    print(f"  Payload marker: TEST_IPV6_LARGE_PAYLOAD_1400B")
    sendp(packet, iface=iface, count=count, verbose=False)


def send_mixed_ipv4_ipv6_traffic(src_ipv4, dst_ipv4, src_ipv6, dst_ipv6, inner_src, inner_dst, iface="eth0"):
    """Send burst of mixed IPv4 and IPv6 tunnel traffic."""
    dst_mac = get_mac_for_ip(dst_ipv4, iface)
    src_mac = get_if_hwaddr(iface)

    packets = []

    # IPv4 GRE
    packets.append(Ether(src=src_mac, dst=dst_mac) / IP(src=src_ipv4, dst=dst_ipv4, proto=47) /
                   GRE(proto=0x0800) / IP(src=inner_src, dst=inner_dst) /
                   ICMP() / Raw(b"TEST_MIXED_IPV4_GRE"))

    # IPv6 GRE with IPv4 inner
    packets.append(Ether(src=src_mac, dst=dst_mac) / IPv6(src=src_ipv6, dst=dst_ipv6, nh=47) /
                   GRE(proto=0x0800) / IP(src=inner_src, dst=inner_dst) /
                   ICMP() / Raw(b"TEST_MIXED_IPV6_GRE_IPV4"))

    # IPv4 IPIP
    packets.append(Ether(src=src_mac, dst=dst_mac) / IP(src=src_ipv4, dst=dst_ipv4, proto=4) /
                   IP(src=inner_src, dst=inner_dst) / ICMP() / Raw(b"TEST_MIXED_IPV4_IPIP"))

    # IPv6-in-IPv4
    packets.append(Ether(src=src_mac, dst=dst_mac) / IP(src=src_ipv4, dst=dst_ipv4, proto=41) /
                   IPv6(src="2001:db8:cafe::100", dst="2001:db8:cafe::1") /
                   ICMPv6EchoRequest() / Raw(b"TEST_MIXED_IPV6_IN_IPV4"))

    # IPv6 GRE with IPv6 inner
    packets.append(Ether(src=src_mac, dst=dst_mac) / IPv6(src=src_ipv6, dst=dst_ipv6, nh=47) /
                   GRE(proto=0x86DD) / IPv6(src="2001:db8:cafe::100", dst="2001:db8:cafe::1") /
                   ICMPv6EchoRequest() / Raw(b"TEST_MIXED_IPV6_GRE_IPV6"))

    print(f"Sending burst of {len(packets)} mixed IPv4/IPv6 tunnel packets")
    sendp(packets, iface=iface, verbose=False)


def main():
    parser = argparse.ArgumentParser(description="Generate test tunnel packets")
    parser.add_argument("--type", required=True,
                       choices=["gre-ipv4", "gre-ipv4-checksum", "gre-ipv4-key",
                               "gre-ipv4-seq", "gre-ipv4-all-flags", "gre-ipv4-routing",
                               "ipip", "ipip-large",
                               "plain", "invalid-gre", "truncated-gre", "invalid-optional-fields",
                               "mixed-burst",
                               "gre-ipv6-outer-ipv4-inner", "gre-ipv6-outer-ipv6-inner",
                               "gre-ipv6-all-flags", "ipip-ipv4-in-ipv6", "ipip-ipv6-in-ipv4",
                               "ipip-ipv6-in-ipv6", "ipv6-large", "mixed-ipv4-ipv6",
                               "all", "all-with-ipv6"],
                       help="Type of packet to send")
    parser.add_argument("--src", default="10.200.0.20", help="Outer source IP (IPv4 or IPv6)")
    parser.add_argument("--dst", default="10.200.0.10", help="Outer destination IP (IPv4 or IPv6)")
    parser.add_argument("--inner-src", default="203.0.113.100", help="Inner source IP (IPv4 or IPv6)")
    parser.add_argument("--inner-dst", default="203.0.113.1", help="Inner destination IP (IPv4 or IPv6)")
    parser.add_argument("--iface", default="eth0", help="Network interface")
    parser.add_argument("--count", type=int, default=1, help="Number of packets to send")
    parser.add_argument("--src-ipv6", default="fd00:db8:1::20", help="Outer source IPv6 (for mixed traffic)")
    parser.add_argument("--dst-ipv6", default="fd00:db8:1::10", help="Outer destination IPv6 (for mixed traffic)")

    args = parser.parse_args()

    # Disable scapy warnings
    conf.verb = 0

    packet_types = {
        "gre-ipv4": send_gre_ipv4_packet,
        "gre-ipv4-checksum": send_gre_ipv4_with_checksum,
        "gre-ipv4-key": send_gre_ipv4_with_key,
        "gre-ipv4-seq": send_gre_ipv4_with_sequence,
        "gre-ipv4-all-flags": send_gre_ipv4_all_flags,
        "gre-ipv4-routing": send_gre_ipv4_with_routing,
        "ipip": send_ipip_packet,
        "ipip-large": send_ipip_large_payload,
        "plain": lambda *a, **kw: send_plain_traffic(args.src, args.dst, args.iface, args.count),
        "invalid-gre": lambda *a, **kw: send_invalid_gre_version(args.src, args.dst, args.inner_src, args.inner_dst, args.iface),
        "truncated-gre": lambda *a, **kw: send_truncated_gre_packet(args.src, args.dst, args.iface),
        "invalid-optional-fields": lambda *a, **kw: send_gre_with_invalid_optional_fields(args.src, args.dst, args.inner_src, args.inner_dst, args.iface),
        "mixed-burst": lambda *a, **kw: send_mixed_traffic_burst(args.src, args.dst, args.inner_src, args.inner_dst, args.iface),
        "gre-ipv6-outer-ipv4-inner": send_gre_ipv6_outer_ipv4_inner,
        "gre-ipv6-outer-ipv6-inner": send_gre_ipv6_outer_ipv6_inner,
        "gre-ipv6-all-flags": send_gre_ipv6_all_flags,
        "ipip-ipv4-in-ipv6": send_ipip_ipv4_in_ipv6,
        "ipip-ipv6-in-ipv4": send_ipip_ipv6_in_ipv4,
        "ipip-ipv6-in-ipv6": send_ipip_ipv6_in_ipv6,
        "ipv6-large": send_ipv6_large_payload,
        "mixed-ipv4-ipv6": lambda *a, **kw: send_mixed_ipv4_ipv6_traffic(args.src, args.dst, args.src_ipv6, args.dst_ipv6, args.inner_src, args.inner_dst, args.iface),
    }

    # Types that don't follow standard signature
    special_types = ["plain", "invalid-gre", "truncated-gre", "invalid-optional-fields", "mixed-burst", "mixed-ipv4-ipv6"]

    # IPv6 packet types that need IPv6 default addresses
    ipv6_types = ["gre-ipv6-outer-ipv4-inner", "gre-ipv6-outer-ipv6-inner", "gre-ipv6-all-flags",
                  "ipip-ipv4-in-ipv6", "ipip-ipv6-in-ipv6", "ipv6-large"]

    if args.type == "all":
        print("Sending all IPv4 packet types...")
        for pkt_type, func in packet_types.items():
            if pkt_type not in ["all", "all-with-ipv6", "mixed-ipv4-ipv6"] and pkt_type not in ipv6_types:
                try:
                    if pkt_type in special_types:
                        func()
                    else:
                        func(args.src, args.dst, args.inner_src, args.inner_dst, args.iface, args.count)
                except Exception as e:
                    print(f"Error sending {pkt_type}: {e}")
    elif args.type == "all-with-ipv6":
        print("Sending all packet types (IPv4 and IPv6)...")
        for pkt_type, func in packet_types.items():
            if pkt_type not in ["all", "all-with-ipv6"]:
                try:
                    if pkt_type in special_types:
                        func()
                    elif pkt_type in ipv6_types:
                        # Use IPv6 addresses for IPv6 packet types
                        func(args.src_ipv6, args.dst_ipv6, args.inner_src, args.inner_dst, args.iface, args.count)
                    else:
                        func(args.src, args.dst, args.inner_src, args.inner_dst, args.iface, args.count)
                except Exception as e:
                    print(f"Error sending {pkt_type}: {e}")
    else:
        func = packet_types[args.type]
        if args.type in special_types:
            func()
        elif args.type in ipv6_types:
            # Use IPv6 addresses for IPv6 packet types if not explicitly provided
            src = args.src if ':' in args.src else args.src_ipv6
            dst = args.dst if ':' in args.dst else args.dst_ipv6
            func(src, dst, args.inner_src, args.inner_dst, args.iface, args.count)
        else:
            func(args.src, args.dst, args.inner_src, args.inner_dst, args.iface, args.count)

    print("Done sending packets")


if __name__ == "__main__":
    main()
