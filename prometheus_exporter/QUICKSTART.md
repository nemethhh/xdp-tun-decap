# Quick Start Guide

Get the Prometheus exporter running in under 5 minutes.

## 1. Install Dependencies

```bash
# Install Python 3 and pip (if not already installed)
sudo apt-get install -y python3 python3-pip

# Install prometheus-client
pip3 install prometheus-client
```

## 2. Verify XDP Program is Loaded

```bash
# Check if XDP program is running
sudo xdp-loader status

# Verify stats map exists
ls -l /sys/fs/bpf/tun_decap_stats
```

If the program is not loaded, load it first:
```bash
cd /home/am/Work/SRE-35412/new/xdp-tun-decap
make all
sudo xdp-loader load -m native eth0 build/tun_decap.bpf.o
```

## 3. Run the Exporter

**Local-only (secure):**
```bash
sudo python3 xdp_tun_decap_exporter.py --address 127.0.0.1
```

**All interfaces (for remote Prometheus):**
```bash
sudo python3 xdp_tun_decap_exporter.py --address 0.0.0.0
```

**Default settings:**
- Address: 0.0.0.0 (all interfaces)
- Port: 9100
- Update interval: 5 seconds

## 4. Test the Metrics

Open another terminal and fetch metrics:
```bash
curl http://localhost:9100/metrics | grep xdp_tun_decap
```

Expected output:
```
# HELP xdp_tun_decap_rx_total Total packets received
# TYPE xdp_tun_decap_rx_total gauge
xdp_tun_decap_rx_total 0.0
# HELP xdp_tun_decap_rx_gre GRE tunnel packets received
# TYPE xdp_tun_decap_rx_gre gauge
xdp_tun_decap_rx_gre 0.0
...
```

## 5. Configure Prometheus

Add to `prometheus.yml`:
```yaml
scrape_configs:
  - job_name: 'xdp_tun_decap'
    static_configs:
      - targets: ['localhost:9100']
```

Reload Prometheus:
```bash
sudo systemctl reload prometheus
# or
curl -X POST http://localhost:9090/-/reload
```

## 6. View in Prometheus

Visit http://localhost:9090 and query:
```
xdp_tun_decap_rx_total
```

## Automated Test

Run the included test script:
```bash
sudo ./test_exporter.sh
```

## Production Deployment

Install as systemd service:
```bash
# Copy files to /opt
sudo mkdir -p /opt/xdp-tun-decap/prometheus_exporter
sudo cp *.py requirements.txt /opt/xdp-tun-decap/prometheus_exporter/

# Install systemd service
sudo cp xdp-tun-decap-exporter.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable xdp-tun-decap-exporter
sudo systemctl start xdp-tun-decap-exporter

# Check status
sudo systemctl status xdp-tun-decap-exporter
```

## Common Use Cases

**Localhost only (secure):**
```bash
sudo python3 xdp_tun_decap_exporter.py -a 127.0.0.1 -p 9100
```

**Specific network interface:**
```bash
sudo python3 xdp_tun_decap_exporter.py -a 192.168.1.100 -p 9100
```

**Custom port:**
```bash
sudo python3 xdp_tun_decap_exporter.py -a 0.0.0.0 -p 9200
```

**High-frequency updates:**
```bash
sudo python3 xdp_tun_decap_exporter.py -i 1  # 1-second interval
```

## Troubleshooting

**"Permission denied"**
- Must run as root: `sudo python3 xdp_tun_decap_exporter.py`

**"Map not found"**
- XDP program not loaded: `sudo xdp-loader status`

**"Address already in use"**
- Change port: `--port 9200`
- Check what's using it: `sudo netstat -tlnp | grep 9100`

**"Cannot assign requested address"**
- IP doesn't exist on system: `ip addr show`
- Use `0.0.0.0` or `127.0.0.1`

**"Module not found: prometheus_client"**
- Install dependencies: `pip3 install -r requirements.txt`

## Next Steps

- See [README.md](README.md) for full documentation
- Create Grafana dashboards
- Set up alerting rules
- Configure firewall for remote access
