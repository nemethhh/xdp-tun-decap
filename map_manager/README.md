# XDP Tunnel Decapsulation Map Manager

Python tool to manage BPF maps for the xdp-tun-decap program.

## Features

- **IPv4 Whitelist**: Add/remove/check IPv4 addresses
- **IPv6 Whitelist**: Add/remove/check IPv6 addresses
- **Configuration**: Enable/disable processing at runtime
- **Statistics**: View aggregated packet statistics

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

**Show current configuration:**
```bash
sudo python3 xdp_tun_decap_manager.py config-show
# Current configuration:
#   All processing:  enabled
#   GRE processing:  enabled
#   IPIP processing: enabled
#   Statistics:      enabled
```

**Disable all processing:**
```bash
sudo python3 xdp_tun_decap_manager.py config-disable-all
# ✓ Configuration updated:
#   All processing:  DISABLED
#   GRE processing:  enabled
#   IPIP processing: enabled
#   Statistics:      enabled
```

**Enable all processing:**
```bash
sudo python3 xdp_tun_decap_manager.py config-enable-all
# ✓ Configuration updated:
#   All processing:  enabled
#   GRE processing:  enabled
#   IPIP processing: enabled
#   Statistics:      enabled
```

**Disable only GRE:**
```bash
sudo python3 xdp_tun_decap_manager.py config-disable-gre
# ✓ Configuration updated:
#   All processing:  enabled
#   GRE processing:  DISABLED
#   IPIP processing: enabled
#   Statistics:      enabled
```

**Enable GRE:**
```bash
sudo python3 xdp_tun_decap_manager.py config-enable-gre
```

**Disable only IPIP:**
```bash
sudo python3 xdp_tun_decap_manager.py config-disable-ipip
```

**Enable IPIP:**
```bash
sudo python3 xdp_tun_decap_manager.py config-enable-ipip
```

**Disable statistics collection:**
```bash
sudo python3 xdp_tun_decap_manager.py config-disable-stats
# ✓ Configuration updated:
#   All processing:  enabled
#   GRE processing:  enabled
#   IPIP processing: enabled
#   Statistics:      DISABLED
```

**Enable statistics collection:**
```bash
sudo python3 xdp_tun_decap_manager.py config-enable-stats
# ✓ Configuration updated:
#   All processing:  enabled
#   GRE processing:  enabled
#   IPIP processing: enabled
#   Statistics:      enabled
```

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
#   decap_success            :          70,000
#   decap_failed             :              10
#   drop_not_whitelisted     :           3,446
#   drop_malformed           :               0
#   pass_non_tunnel          :          50,000
```

**Note**: Statistics collection is enabled by default. You can disable it to reduce overhead in high-throughput environments where monitoring is handled externally:
```bash
sudo python3 xdp_tun_decap_manager.py config-disable-stats
```

## Command Reference

```bash
# Whitelist operations (auto-detects IPv4 vs IPv6)
whitelist-add IP          Add IP to whitelist
whitelist-remove IP       Remove IP from whitelist
whitelist-check IP        Check if IP is whitelisted

# Configuration operations
config-show               Show current configuration
config-disable-all        Disable all processing
config-enable-all         Enable all processing
config-disable-gre        Disable GRE processing only
config-enable-gre         Enable GRE processing
config-disable-ipip       Disable IPIP processing only
config-enable-ipip        Enable IPIP processing
config-disable-stats      Disable statistics collection
config-enable-stats       Enable statistics collection

# Statistics
stats                     Show aggregated statistics
```

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
sudo python3 xdp_tun_decap_manager.py config-disable-all

# ... perform maintenance ...

# Re-enable
sudo python3 xdp_tun_decap_manager.py config-enable-all
```

### Debugging

```bash
# Check if traffic is being processed
sudo python3 xdp_tun_decap_manager.py stats

# Check if source IP is whitelisted
sudo python3 xdp_tun_decap_manager.py whitelist-check 10.200.0.20

# Check configuration
sudo python3 xdp_tun_decap_manager.py config-show
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
│  - tun_decap_config       (cfg) │
│  - tun_decap_stats        (ro)  │
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
- **Type**: Per-CPU hash map

### IPv6 Whitelist
- **Key**: 16 bytes (IPv6 address as 4x 32-bit words, network byte order)
- **Value**: 1 byte (allowed flag, 1 = whitelisted)
- **Type**: Per-CPU hash map

### Configuration
- **Key**: 4 bytes (index 0)
- **Value**: 4 bytes (disabled, disable_gre, disable_ipip, disable_stats)
- **Type**: Array map
- **Note**: 0 = enabled, 1 = disabled

### Statistics
- **Key**: 4 bytes (stat index 0-11)
- **Value**: Per-CPU array of uint64
- **Type**: Per-CPU array map
- **Note**: Read-only from userspace

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

# For config changes, use show command
sudo python3 xdp_tun_decap_manager.py config-show

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
