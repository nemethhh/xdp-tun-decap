# XDP Tunnel Decapsulation Prometheus Exporter

A lightweight Python-based Prometheus exporter that reads statistics from the xdp-tun-decap BPF program and exposes them as Prometheus metrics.

## Features

- **Lightweight**: Uses direct BPF syscalls via ctypes (no BCC dependency)
- **Real-time metrics**: Continuously reads per-CPU statistics from pinned BPF maps
- **Automatic aggregation**: Sums per-CPU counters for accurate totals
- **Standard Prometheus format**: Exposes metrics via HTTP endpoint
- **Configurable binding**: Bind to specific IP address and port
- **Comprehensive coverage**: All 14 statistics from xdp-tun-decap

> **Note**: Statistics collection in the XDP program is enabled by default. It can be disabled via the config map for performance optimization (see map_manager documentation).

## Metrics Exposed

All metrics are prefixed with `xdp_tun_decap_`:

| Metric | Description |
|--------|-------------|
| `xdp_tun_decap_rx_total` | Total packets received |
| `xdp_tun_decap_rx_gre` | GRE tunnel packets received |
| `xdp_tun_decap_rx_ipip` | IPIP tunnel packets received |
| `xdp_tun_decap_rx_ipv6_in_ipv4` | IPv6-in-IPv4 tunnel packets |
| `xdp_tun_decap_rx_ipv6_outer` | Packets with IPv6 outer header |
| `xdp_tun_decap_rx_gre_ipv6_inner` | GRE with IPv6 inner packet |
| `xdp_tun_decap_rx_ipip_ipv6_inner` | IPIP with IPv6 inner packet |
| `xdp_tun_decap_rx_ipv6_in_ipv6` | IPv6-in-IPv6 tunnel packets |
| `xdp_tun_decap_decap_success` | Successfully decapsulated packets |
| `xdp_tun_decap_decap_failed` | Decapsulation failures |
| `xdp_tun_decap_drop_not_whitelisted` | Dropped (not whitelisted) |
| `xdp_tun_decap_drop_malformed` | Dropped (malformed packet) |
| `xdp_tun_decap_drop_fragmented` | Dropped (fragmented outer packet) |
| `xdp_tun_decap_pass_non_tunnel` | Non-tunnel traffic passed |

## Installation

### Prerequisites

1. **Python 3.7+** with pip
2. **Root privileges** to read BPF maps
3. **xdp-tun-decap** program loaded and running

### Install Dependencies

```bash
pip3 install -r requirements.txt
```

Or install directly:
```bash
pip3 install prometheus-client
```

## Usage

### Basic Usage

Run with default settings (bind to 0.0.0.0:9100, 5-second interval):
```bash
sudo python3 xdp_tun_decap_exporter.py
```

### Command-Line Options

```bash
sudo python3 xdp_tun_decap_exporter.py --help

Options:
  -a ADDRESS, --address ADDRESS
                        IP address to bind to (default: 0.0.0.0)
  -p PORT, --port PORT  Prometheus HTTP port (default: 9100)
  -i INTERVAL, --interval INTERVAL
                        Metric update interval in seconds (default: 5)
  -m MAP_PATH, --map-path MAP_PATH
                        Path to pinned BPF stats map
  -v, --verbose         Enable verbose logging
  --log-level {DEBUG,INFO,WARNING,ERROR}
                        Set logging level
```

### Examples

**Bind to localhost only:**
```bash
sudo python3 xdp_tun_decap_exporter.py --address 127.0.0.1 --port 9100
```

**Custom port and update interval:**
```bash
sudo python3 xdp_tun_decap_exporter.py --port 9200 --interval 10
```

**Listen on specific IP:**
```bash
sudo python3 xdp_tun_decap_exporter.py --address 192.168.1.100 --port 9100
```

**Verbose debug output:**
```bash
sudo python3 xdp_tun_decap_exporter.py --verbose
```

**Custom BPF map path:**
```bash
sudo python3 xdp_tun_decap_exporter.py --map-path /sys/fs/bpf/custom_stats
```

## Prometheus Configuration

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'xdp_tun_decap'
    static_configs:
      - targets: ['localhost:9100']
    scrape_interval: 15s
    scrape_timeout: 10s
```

For remote exporter:
```yaml
scrape_configs:
  - job_name: 'xdp_tun_decap'
    static_configs:
      - targets: ['192.168.1.100:9100']
```

## Systemd Service

Create `/etc/systemd/system/xdp-tun-decap-exporter.service`:

```ini
[Unit]
Description=XDP Tunnel Decapsulation Prometheus Exporter
After=network.target
Requires=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/xdp-tun-decap/prometheus_exporter
ExecStart=/usr/bin/python3 /opt/xdp-tun-decap/prometheus_exporter/xdp_tun_decap_exporter.py --address 0.0.0.0 --port 9100 --interval 5
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable xdp-tun-decap-exporter
sudo systemctl start xdp-tun-decap-exporter
sudo systemctl status xdp-tun-decap-exporter
```

View logs:
```bash
sudo journalctl -u xdp-tun-decap-exporter -f
```

## Development

### Map Management

Manage BPF maps (whitelists, configuration) via Python:
```bash
cd ../map_manager

# Whitelist management
sudo python3 xdp_tun_decap_manager.py whitelist-add 10.200.0.20
sudo python3 xdp_tun_decap_manager.py whitelist-add 2001:db8::1
sudo python3 xdp_tun_decap_manager.py whitelist-check 10.200.0.20

# View statistics
sudo python3 xdp_tun_decap_manager.py stats

# Runtime configuration (via bpftool .bss map)
# See map_manager documentation for config commands
```

See [../map_manager/README.md](../map_manager/README.md) for complete documentation.

### Linting

Run code quality checks via Docker:
```bash
make lint               # Run all linters
make lint-flake8        # PEP 8 style check
make lint-pylint        # Static analysis
make format             # Auto-format code
```

See [LINTING.md](LINTING.md) for complete linting documentation.

## Testing

### Quick Test

```bash
sudo ./test_exporter.sh
```

### Manual Test

```bash
# Start exporter
sudo python3 xdp_tun_decap_exporter.py --address 127.0.0.1 --port 9100

# In another terminal, check metrics
curl http://127.0.0.1:9100/metrics | grep xdp_tun_decap

# Expected output:
# xdp_tun_decap_rx_total 123456.0
# xdp_tun_decap_rx_gre 50000.0
# xdp_tun_decap_decap_success 50000.0
# ...
```

### Verify BPF Map Access

```bash
# Check if stats map exists
ls -l /sys/fs/bpf/tun_decap_stats

# View raw stats with bpftool
sudo bpftool map dump pinned /sys/fs/bpf/tun_decap_stats
```

## Grafana Dashboard

Example Grafana queries:

**Total packets received:**
```promql
xdp_tun_decap_rx_total
```

**Packet rate (packets/sec):**
```promql
rate(xdp_tun_decap_rx_total[1m])
```

**Decapsulation success rate:**
```promql
rate(xdp_tun_decap_decap_success[1m]) / rate(xdp_tun_decap_rx_total[1m])
```

**Drop rate by reason:**
```promql
rate(xdp_tun_decap_drop_not_whitelisted[1m]) + rate(xdp_tun_decap_drop_malformed[1m])
```

**Traffic breakdown by protocol:**
```promql
sum without (instance, job) (
  xdp_tun_decap_rx_gre,
  xdp_tun_decap_rx_ipip,
  xdp_tun_decap_pass_non_tunnel
)
```

## Troubleshooting

### "BPF stats map not found"
- Ensure xdp-tun-decap program is loaded: `sudo xdp-loader status`
- Check BPF filesystem mounted: `mount | grep bpf`
- Verify map pinned: `ls -l /sys/fs/bpf/tun_decap_stats`

### "Permission denied"
- Exporter must run as root to access BPF maps
- Check file permissions: `ls -l /sys/fs/bpf/`

### "Address already in use"
- Port is already bound
- Use different port: `--port 9200`
- Check: `sudo netstat -tlnp | grep 9100`

### No metrics updating
- Check if statistics collection is enabled (compile-time, default ON)
- Check XDP program receiving traffic: `sudo bpftool map dump pinned /sys/fs/bpf/tun_decap_stats`
- Verify interface has XDP program loaded: `sudo xdp-loader status`
- Check exporter logs: `--verbose`
- If stats disabled at runtime, enable via .bss map (see map_manager documentation)

### Cannot bind to address
- Check if IP address exists on system: `ip addr show`
- Verify no firewall blocking: `sudo iptables -L -n`
- Use `0.0.0.0` to bind to all interfaces

## Architecture

```
┌─────────────────────┐
│   Network Traffic   │
│   (GRE/IPIP/IPv6)   │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│   XDP BPF Program   │
│  (Kernel Space)     │
│  - Decapsulation    │
│  - Statistics       │
└──────────┬──────────┘
           │
           ▼ (write)
┌─────────────────────┐
│  Per-CPU BPF Maps   │
│  /sys/fs/bpf/       │
│  tun_decap_stats    │
└──────────┬──────────┘
           │
           ▼ (BPF syscall)
┌─────────────────────┐
│  Python Exporter    │
│  (User Space)       │
│  - Direct syscalls  │
│  - Aggregation      │
│  - HTTP Server      │
└──────────┬──────────┘
           │
           ▼ (scrape)
┌─────────────────────┐
│   Prometheus        │
│   (Time Series DB)  │
└─────────────────────┘
```

## Performance Considerations

- **Per-CPU maps**: Statistics are per-CPU to avoid contention
- **Direct syscalls**: Uses ctypes for minimal overhead (no BCC)
- **Aggregation**: Done in userspace, minimal CPU usage
- **Update interval**: Default 5s balances freshness vs. CPU
- **Memory footprint**: ~5MB (Python + prometheus-client)
- **CPU usage**: <0.05% on modern systems

## Security Notes

- **Root required**: Reading BPF maps requires CAP_BPF or root
- **Read-only**: Exporter only reads maps, never writes
- **Bind address**: Use `127.0.0.1` for local-only access
- **Firewall**: Configure iptables/firewalld for remote access
- **No authentication**: Consider reverse proxy (nginx) for auth

## License

SPDX-License-Identifier: GPL-2.0-or-later

Same license as the xdp-tun-decap program.
