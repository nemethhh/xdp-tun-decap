# XDP Tunnel Decapsulation Map Manager

Python tool to manage BPF maps for the xdp-tun-decap program.

## Features

- **IPv4 Whitelist**: Add/remove/check IPv4 addresses
- **IPv6 Whitelist**: Add/remove/check IPv6 addresses
- **Statistics**: View aggregated packet statistics (all 14 counters)

## Installation

No additional dependencies needed - uses standard Python libraries.

## Usage

### IPv4 Whitelist Management

**Add IPv4 address:**
```bash
sudo python3 xdp_tun_decap_manager.py whitelist-add 10.200.0.20
# ✓ Added 10.200.0.20 to IPv4 whitelist
```

**Remove IPv4 address:**
```bash
sudo python3 xdp_tun_decap_manager.py whitelist-remove 10.200.0.20
# ✓ Removed 10.200.0.20 from IPv4 whitelist
```

**Check if IPv4 is whitelisted:**
```bash
sudo python3 xdp_tun_decap_manager.py whitelist-check 10.200.0.20
# ✓ 10.200.0.20 is whitelisted
# or
# ✗ 10.200.0.20 is NOT whitelisted
```

### IPv6 Whitelist Management

**Add IPv6 address:**
```bash
sudo python3 xdp_tun_decap_manager.py whitelist-add 2001:db8::1
# ✓ Added 2001:db8::1 to IPv6 whitelist
```

**Remove IPv6 address:**
```bash
sudo python3 xdp_tun_decap_manager.py whitelist-remove 2001:db8::100:20
# ✓ Removed 2001:db8::100:20 from IPv6 whitelist
```

**Check if IPv6 is whitelisted:**
```bash
sudo python3 xdp_tun_decap_manager.py whitelist-check 2001:db8::1
# ✓ 2001:db8::1 is whitelisted
```

### Runtime Configuration

**Note:** Runtime configuration is now stored as a BPF global variable (`cfg_global`) for optimal performance. It must be updated via the program's `.bss` map using `bpftool`:

**Show current configuration:**
```bash
# Find the XDP program
sudo bpftool prog show | grep tun_decap

# Show the .bss map (contains cfg_global)
sudo bpftool map dump name tun_decap_b.bss
```

**Update configuration:**
```bash
# Find the .bss map ID
PROG_ID=$(sudo bpftool prog show | grep tun_decap | awk '{print $1}' | sed 's/://')
BSS_MAP_ID=$(sudo bpftool prog show id $PROG_ID | grep 'map_ids' | grep -oP '\d+' | head -n 1)

# Disable all processing (set disabled=1, others=0)
sudo bpftool map update id $BSS_MAP_ID key hex 00 00 00 00 value hex 01 00 00 00

# Enable all processing (set all to 0)
sudo bpftool map update id $BSS_MAP_ID key hex 00 00 00 00 value hex 00 00 00 00

# Disable only GRE (disabled=0, disable_gre=1, disable_ipip=0, disable_stats=0)
sudo bpftool map update id $BSS_MAP_ID key hex 00 00 00 00 value hex 00 01 00 00

# Disable only IPIP
sudo bpftool map update id $BSS_MAP_ID key hex 00 00 00 00 value hex 00 00 01 00

# Disable statistics collection
sudo bpftool map update id $BSS_MAP_ID key hex 00 00 00 00 value hex 00 00 00 01
```

**Configuration struct format:**
- Byte 0: `disabled` (0=enabled, 1=disabled all processing)
- Byte 1: `disable_gre` (0=enabled, 1=disabled GRE only)
- Byte 2: `disable_ipip` (0=enabled, 1=disabled IPIP only)
- Byte 3: `disable_stats` (0=enabled, 1=disabled statistics)

### Statistics

**View statistics:**
```bash
sudo python3 xdp_tun_decap_manager.py stats
# Statistics (aggregated across all CPUs):
# --------------------------------------------------
#   rx_total                 :         123,456
#   rx_gre                   :          50,000
#   rx_ipip                  :          20,000
#   rx_ipv6_in_ipv4          :           5,000
#   rx_ipv6_outer            :          10,000
#   rx_gre_ipv6_inner        :           2,000
#   rx_ipip_ipv6_inner       :           1,000
#   rx_ipv6_in_ipv6          :           1,500
#   decap_success            :          70,000
#   decap_failed             :              10
#   drop_not_whitelisted     :           3,446
#   drop_malformed           :               0
#   drop_fragmented          :              50
#   pass_non_tunnel          :          50,000
```

**Note**: Statistics collection is compile-time configurable (enabled by default in release builds). To disable at runtime, update the `cfg_global.disable_stats` field via the `.bss` map (see Configuration section above).

## Command Reference

```bash
# Whitelist operations (auto-detects IPv4 vs IPv6)
whitelist-add IP          Add IP to whitelist
whitelist-remove IP       Remove IP from whitelist
whitelist-check IP        Check if IP is whitelisted

# Statistics
stats                     Show aggregated statistics (all 14 counters)
```

**Configuration operations** are now done via `bpftool` (see Configuration section above).

## Examples

### Bulk Add IPs

```bash
# Add multiple IPv4 addresses
for ip in 10.200.0.{1..50}; do
    sudo python3 xdp_tun_decap_manager.py whitelist-add $ip
done

# Add multiple IPv6 addresses
for i in {1..10}; do
    sudo python3 xdp_tun_decap_manager.py whitelist-add "2001:db8::$i"
done
```

### Maintenance Mode

```bash
# Disable all processing for maintenance
# First, find the .bss map ID
PROG_ID=$(sudo bpftool prog show | grep tun_decap | awk '{print $1}' | sed 's/://')
BSS_MAP_ID=$(sudo bpftool prog show id $PROG_ID | grep 'map_ids' | grep -oP '\d+' | head -n 1)

# Disable all processing
sudo bpftool map update id $BSS_MAP_ID key hex 00 00 00 00 value hex 01 00 00 00

# ... perform maintenance ...

# Re-enable
sudo bpftool map update id $BSS_MAP_ID key hex 00 00 00 00 value hex 00 00 00 00
```

### Debugging

```bash
# Check if traffic is being processed
sudo python3 xdp_tun_decap_manager.py stats

# Check if source IP is whitelisted
sudo python3 xdp_tun_decap_manager.py whitelist-check 10.200.0.20

# Check configuration (via .bss map)
PROG_ID=$(sudo bpftool prog show | grep tun_decap | awk '{print $1}' | sed 's/://')
sudo bpftool map dump name tun_decap_b.bss
```

## Architecture

```
┌─────────────────────────────────┐
│  xdp_tun_decap_manager.py       │
│  (Python userspace tool)        │
└──────────────┬──────────────────┘
               │
               ▼ (BPF syscalls)
┌─────────────────────────────────┐
│  Pinned BPF Maps                │
│  /sys/fs/bpf/                   │
│                                  │
│  - tun_decap_whitelist    (IPv4)│
│  - tun_decap_whitelist_v6 (IPv6)│
│  - tun_decap_stats        (ro)  │
│  - tun_decap_b.bss        (cfg) │
└──────────────┬──────────────────┘
               │
               ▼ (kernel access)
┌─────────────────────────────────┐
│  XDP BPF Program                │
│  (xdp_tun_decap)                │
└─────────────────────────────────┘
```

## Map Formats

### IPv4 Whitelist
- **Key**: 4 bytes (IPv4 address, network byte order)
- **Value**: 1 byte (allowed flag, 1 = whitelisted)
- **Type**: Hash map (RCU-protected, lock-free reads)

### IPv6 Whitelist
- **Key**: 16 bytes (IPv6 address as 4x 32-bit words, network byte order)
- **Value**: 1 byte (allowed flag, 1 = whitelisted)
- **Type**: Hash map (RCU-protected, lock-free reads)

### Configuration (BPF Global Variable)
- **Location**: Program's `.bss` map (named `tun_decap_b.bss` or similar)
- **Structure**: `struct tun_decap_config` (4 bytes total)
  - Byte 0: `disabled` (master disable switch)
  - Byte 1: `disable_gre` (disable GRE only)
  - Byte 2: `disable_ipip` (disable IPIP only)
  - Byte 3: `disable_stats` (disable statistics collection)
- **Note**: 0 = enabled, 1 = disabled (inverted logic for zero-init defaults)
- **Access**: Via `bpftool map update/dump` on the `.bss` map

### Statistics
- **Key**: 4 bytes (always 0 - single entry)
- **Value**: Per-CPU struct with 14 uint64 fields (112 bytes per CPU)
  - Fields: rx_total, rx_gre, rx_ipip, rx_ipv6_in_ipv4, rx_ipv6_outer,
            rx_gre_ipv6_inner, rx_ipip_ipv6_inner, rx_ipv6_in_ipv6,
            decap_success, decap_failed, drop_not_whitelisted,
            drop_malformed, drop_fragmented, pass_non_tunnel
- **Type**: Per-CPU array map (1 entry)
- **Note**: Read-only from userspace, aggregated across CPUs by manager tool

## Troubleshooting

### "Map not found" error
```bash
# Check if XDP program is loaded
sudo xdp-loader status

# Check if maps are pinned
ls -l /sys/fs/bpf/tun_decap_*
```

### "Permission denied"
```bash
# Must run as root
sudo python3 xdp_tun_decap_manager.py <command>
```

### Invalid IP address format
```bash
# IPv4: Use dotted decimal notation
sudo python3 xdp_tun_decap_manager.py whitelist-add 10.200.0.20

# IPv6: Use standard notation (compressed or full)
sudo python3 xdp_tun_decap_manager.py whitelist-add 2001:db8::1
sudo python3 xdp_tun_decap_manager.py whitelist-add 2001:0db8:0000:0000:0000:0000:0000:0001
```

### Check if changes applied
```bash
# For whitelist changes, use check command
sudo python3 xdp_tun_decap_manager.py whitelist-check 10.200.0.20

# For config changes, dump the .bss map
sudo bpftool map dump name tun_decap_b.bss

# For statistics, watch for changes
watch -n 1 'sudo python3 xdp_tun_decap_manager.py stats'
```

## Integration with Scripts

### Bash Integration

```bash
#!/bin/bash
# Whitelist management script

MANAGER="sudo python3 xdp_tun_decap_manager.py"

# Add CDN IPs
cdn_ips=(
    "10.200.0.1"
    "10.200.0.2"
    "2001:db8::100:1"
)

for ip in "${cdn_ips[@]}"; do
    $MANAGER whitelist-add "$ip"
done

# Show stats
$MANAGER stats
```

### Ansible Integration

```yaml
- name: Add IP to XDP whitelist
  command: python3 /path/to/xdp_tun_decap_manager.py whitelist-add {{ tunnel_ip }}
  become: true

- name: Check configuration
  command: python3 /path/to/xdp_tun_decap_manager.py config-show
  become: true
  register: config_output
```

## Security Considerations

- **Root required**: Map operations require root privileges
- **No validation**: Tool doesn't validate if IPs are appropriate to whitelist
- **Direct manipulation**: Changes apply immediately, no confirmation
- **No audit log**: Consider wrapping with logging for production use

## Performance Notes

- Map operations are O(1) for hash maps
- Per-CPU maps provide lock-free access
- No performance impact on data plane
- Tool overhead: ~5-10ms per operation

## See Also

- [README.md](README.md) - Prometheus exporter
- [CLAUDE.md](../CLAUDE.md) - Project overview
- bpftool(8) - Alternative CLI tool for BPF maps
