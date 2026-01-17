# Quick Start Guide - Map Manager

Manage XDP tunnel decapsulation BPF maps in under 5 minutes.

## 1. No Installation Needed

The map manager uses only Python standard library - no dependencies to install!

```bash
cd map_manager
python3 xdp_tun_decap_manager.py --help
```

## 2. Verify XDP Program is Loaded

```bash
# Check if XDP program is running
sudo xdp-loader status

# Verify maps exist
ls -l /sys/fs/bpf/tun_decap_*
```

If not loaded:
```bash
cd /home/am/Work/SRE-35412/new/xdp-tun-decap
make all
sudo xdp-loader load -m native eth0 build/tun_decap.bpf.o
```

## 3. Add IPs to Whitelist

**IPv4:**
```bash
sudo python3 xdp_tun_decap_manager.py whitelist-add 10.200.0.20
# ✓ Added 10.200.0.20 to IPv4 whitelist
```

**IPv6:**
```bash
sudo python3 xdp_tun_decap_manager.py whitelist-add 2001:db8::1
# ✓ Added 2001:db8::1 to IPv6 whitelist
```

## 4. Verify Whitelisting

```bash
sudo python3 xdp_tun_decap_manager.py whitelist-check 10.200.0.20
# ✓ 10.200.0.20 is whitelisted

sudo python3 xdp_tun_decap_manager.py whitelist-check 2001:db8::1
# ✓ 2001:db8::1 is whitelisted
```

## 5. View Statistics

```bash
sudo python3 xdp_tun_decap_manager.py stats
```

Expected output:
```
Statistics (aggregated across all CPUs):
--------------------------------------------------
  rx_total                 :         123,456
  rx_gre                   :          50,000
  rx_ipip                  :          20,000
  decap_success            :          70,000
  drop_not_whitelisted     :           3,446
  ...
```

## Common Tasks

### Bulk Add IPs
```bash
# Add multiple IPv4 addresses
for ip in 10.200.0.{1..50}; do
    sudo python3 xdp_tun_decap_manager.py whitelist-add $ip
done

# Add from file
while read ip; do
    sudo python3 xdp_tun_decap_manager.py whitelist-add $ip
done < ip_list.txt
```

### Maintenance Mode
```bash
# Disable all processing
sudo python3 xdp_tun_decap_manager.py config-disable-all

# ... perform maintenance ...

# Re-enable
sudo python3 xdp_tun_decap_manager.py config-enable-all
```

### Disable Specific Protocol
```bash
# Disable only GRE
sudo python3 xdp_tun_decap_manager.py config-disable-gre

# Disable only IPIP
sudo python3 xdp_tun_decap_manager.py config-disable-ipip
```

### Check Configuration
```bash
sudo python3 xdp_tun_decap_manager.py config-show
```

Output:
```
Current configuration:
  All processing:  enabled
  GRE processing:  enabled
  IPIP processing: enabled
```

### Remove IPs
```bash
sudo python3 xdp_tun_decap_manager.py whitelist-remove 10.200.0.20
sudo python3 xdp_tun_decap_manager.py whitelist-remove 2001:db8::1
```

## All Commands

```bash
# Whitelist operations
whitelist-add IP          Add IP to whitelist (auto-detects IPv4/IPv6)
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

# Statistics
stats                     Show aggregated statistics
```

## Troubleshooting

**"Map not found"**
- XDP program not loaded: `sudo xdp-loader status`

**"Permission denied"**
- Must run as root: `sudo python3 xdp_tun_decap_manager.py <command>`

**Invalid IP format**
- IPv4: Use dotted decimal (10.200.0.20)
- IPv6: Use standard notation (2001:db8::1)

**Changes not applying**
- Verify: `sudo python3 xdp_tun_decap_manager.py config-show`
- Check stats: `sudo python3 xdp_tun_decap_manager.py stats`

## Next Steps

- See [README.md](README.md) for full documentation
- Integrate with automation scripts
- Set up monitoring with Prometheus exporter
