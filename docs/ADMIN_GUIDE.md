# DDoS Protection System - Administration Guide

## Quick Start

### Installation

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y libpcap-dev libjansson-dev build-essential

# Build and install
make -j$(nproc)
sudo make install

# Configure
sudo cp config/default.conf /etc/ddos-protect/
sudo nano /etc/ddos-protect/default.conf

# Start service
sudo systemctl start ddos-protect
sudo systemctl enable ddos-protect
```

### Initial Configuration

**Minimum required configuration**:

1. Set your network interface:
```json
{
  "network": {
    "interface": "eth0"  ← Change this
  }
}
```

2. Change API token:
```json
{
  "api": {
    "auth_token": "your-secure-token-here"
  }
}
```

3. Review thresholds based on your traffic:
```json
{
  "thresholds": {
    "udp_pps": 10000,     ← Adjust for your needs
    "tcp_syn_pps": 5000,
    "http_rps": 100
  }
}
```

## Service Management

### SystemD Commands

```bash
# Start service
sudo systemctl start ddos-protect

# Stop service
sudo systemctl stop ddos-protect

# Restart service
sudo systemctl restart ddos-protect

# View status
sudo systemctl status ddos-protect

# Enable on boot
sudo systemctl enable ddos-protect

# Disable auto-start
sudo systemctl disable ddos-protect
```

### Viewing Logs

```bash
# Follow live logs
sudo journalctl -u ddos-protect -f

# View last 100 lines
sudo journalctl -u ddos-protect -n 100

# View logs from today
sudo journalctl -u ddos-protect --since today

# View logs with specific priority
sudo journalctl -u ddos-protect -p warning
```

## Configuration Management

### Hot Reload

Change configuration without downtime:

```bash
# Edit configuration
sudo nano /etc/ddos-protect/default.conf

# Reload (send HUP signal)
sudo systemctl reload ddos-protect

# Or via API
curl -X POST -H "Authorization: Bearer your-token" \
     http://localhost:8080/api/config/reload
```

### Configuration Validation

Before applying changes:

```bash
# Test configuration
sudo /usr/local/bin/ddos-protect --test /etc/ddos-protect/default.conf

# Check syntax
sudo /usr/local/bin/ddos-protect --check-config /etc/ddos-protect/default.conf
```

## Monitoring

### Dashboard Access

1. Open browser: `http://your-server-ip:8081`
2. Monitor real-time statistics
3. View attack alerts
4. Check system health

### Command Line Monitoring

```bash
# Watch statistics
watch -n 1 'curl -s -H "Authorization: Bearer your-token" http://localhost:8080/api/stats | jq'

# Monitor attacks
curl -H "Authorization: Bearer your-token" http://localhost:8080/api/attacks

# Check current connections
curl -H "Authorization: Bearer your-token" http://localhost:8080/api/connections
```

### Performance Monitoring

```bash
# CPU usage
top -p $(pgrep ddos-protect)

# Memory usage
ps aux | grep ddos-protect

# Network statistics
sudo iftop -i eth0

# System resources
sudo netstat -s | grep -i drop
```

## IP Management

### Whitelist Management

**Add IP to whitelist**:
```bash
curl -X POST -H "Authorization: Bearer your-token" \
     -H "Content-Type: application/json" \
     -d '{"ip":"192.168.1.100"}' \
     http://localhost:8080/api/whitelist
```

**Add CIDR range**:
```bash
curl -X POST -H "Authorization: Bearer your-token" \
     -H "Content-Type: application/json" \
     -d '{"cidr":"192.168.1.0/24"}' \
     http://localhost:8080/api/whitelist
```

**Remove from whitelist**:
```bash
curl -X DELETE -H "Authorization: Bearer your-token" \
     http://localhost:8080/api/whitelist/192.168.1.100
```

### Blacklist Management

**Add IP to blacklist (1 hour)**:
```bash
curl -X POST -H "Authorization: Bearer your-token" \
     -H "Content-Type: application/json" \
     -d '{"ip":"1.2.3.4","duration":3600}' \
     http://localhost:8080/api/blacklist
```

**Permanent blacklist**:
```bash
curl -X POST -H "Authorization: Bearer your-token" \
     -H "Content-Type: application/json" \
     -d '{"ip":"1.2.3.4","duration":0}' \
     http://localhost:8080/api/blacklist
```

**List blacklisted IPs**:
```bash
curl -H "Authorization: Bearer your-token" \
     http://localhost:8080/api/blacklist
```

**Remove from blacklist**:
```bash
curl -X DELETE -H "Authorization: Bearer your-token" \
     http://localhost:8080/api/blacklist/1.2.3.4
```

## Attack Response

### When Attack is Detected

1. **Verify the attack**:
   - Check dashboard for attack type
   - Review logs for patterns
   - Confirm source IPs

2. **Immediate response**:
   ```bash
   # Block attacking IP
   curl -X POST -H "Authorization: Bearer your-token" \
        -H "Content-Type: application/json" \
        -d '{"ip":"attacker-ip","duration":7200}' \
        http://localhost:8080/api/blacklist

   # Or block entire network
   curl -X POST -H "Authorization: Bearer your-token" \
        -H "Content-Type: application/json" \
        -d '{"cidr":"attacker-network/24","duration":7200}' \
        http://localhost:8080/api/blacklist
   ```

3. **Adjust thresholds if needed**:
   - Edit `/etc/ddos-protect/default.conf`
   - Lower thresholds for stricter filtering
   - Reload configuration

4. **Enable stricter mode**:
   ```json
   {
     "auto_blacklist": {
       "enabled": true,
       "duration": 1800  ← Reduce duration
     }
   }
   ```

### Common Attack Scenarios

#### SYN Flood

**Symptoms**:
- High number of SYN packets
- Many half-open connections
- Server unresponsive

**Response**:
```bash
# Check SYN backlog
sudo netstat -an | grep SYN_RECV | wc -l

# Enable SYN cookies (kernel level)
sudo sysctl -w net.ipv4.tcp_syncookies=1

# Lower SYN threshold in config
"tcp_syn_pps": 2000  # More aggressive
```

#### UDP Amplification

**Symptoms**:
- Large UDP packets from DNS/NTP/SSDP servers
- High bandwidth consumption
- Unusual traffic to server

**Response**:
```bash
# Block amplification sources at firewall
sudo iptables -I INPUT -p udp --sport 53 -m length --length 512: -j DROP
sudo iptables -I INPUT -p udp --sport 123 -m length --length 400: -j DROP
```

#### HTTP Flood

**Symptoms**:
- High request rate from few IPs
- Unusual User-Agents
- Repetitive requests

**Response**:
```json
{
  "http_protection": {
    "enabled": true,
    "js_challenge": true,     ← Enable
    "http_rps": 50            ← Lower threshold
  }
}
```

## Tuning and Optimization

### Performance Tuning

**For high-traffic servers (>1Gbps)**:

1. Increase connection table:
```json
{
  "connection_table_size": 2097152  # 2M entries
}
```

2. Enable XDP:
```json
{
  "xdp": {
    "enabled": true,
    "program": "/usr/share/ddos-protect/ebpf/xdp_filter.o"
  }
}
```

3. CPU pinning:
```json
{
  "cpu_affinity": true,
  "workers": 8  # Match CPU cores
}
```

4. Kernel tuning:
```bash
# Increase network buffers
sudo sysctl -w net.core.rmem_max=134217728
sudo sysctl -w net.core.wmem_max=134217728

# Increase connection tracking
sudo sysctl -w net.netfilter.nf_conntrack_max=2097152

# Enable TCP fast open
sudo sysctl -w net.ipv4.tcp_fastopen=3
```

### Memory Optimization

**For memory-constrained systems**:

```json
{
  "connection_table_size": 262144,   # 256K (instead of 1M)
  "lru_cache_size": 131072           # 128K (instead of 512K)
}
```

### Latency Optimization

**Minimize added latency**:

1. Disable features you don't need:
```json
{
  "geoip": {"enabled": false},
  "http_protection": {"enabled": false}  # If not needed
}
```

2. Use XDP for fast path
3. Reduce logging verbosity:
```json
{
  "logging": {"level": "warn"}
}
```

## Troubleshooting

### Service Won't Start

**Check logs**:
```bash
sudo journalctl -u ddos-protect -n 50
```

**Common issues**:

1. **Permission denied on network interface**:
   ```bash
   # Run as root or grant capabilities
   sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/ddos-protect
   ```

2. **Port already in use**:
   ```bash
   # Check what's using the port
   sudo netstat -tulpn | grep 8080

   # Change port in configuration
   "api": {"port": 8090}
   ```

3. **Configuration syntax error**:
   ```bash
   # Validate JSON
   cat /etc/ddos-protect/default.conf | jq .
   ```

### High False Positive Rate

**Symptoms**: Legitimate traffic being blocked

**Solutions**:

1. **Increase thresholds**:
```json
{
  "thresholds": {
    "udp_pps": 20000,  # Double the values
    "tcp_syn_pps": 10000
  }
}
```

2. **Add trusted IPs to whitelist**:
```bash
# Whitelist your application servers
curl -X POST ... -d '{"cidr":"10.0.0.0/24"}'
```

3. **Disable auto-blacklist temporarily**:
```json
{
  "auto_blacklist": {"enabled": false}
}
```

### Memory Usage Too High

**Check memory usage**:
```bash
sudo pmap -x $(pgrep ddos-protect)
```

**Reduce memory footprint**:
```json
{
  "connection_table_size": 131072,  # Reduce from 1M
  "lru_cache_size": 65536           # Reduce from 512K
}
```

**Enable periodic cleanup**:
```json
{
  "cleanup_interval": 60  # Cleanup every 60 seconds
}
```

## Best Practices

### Security Hardening

1. **Restrict API access**:
```json
{
  "api": {
    "bind_address": "127.0.0.1"  # Localhost only
  }
}
```

2. **Enable authentication**:
```json
{
  "api": {
    "auth_token": "use-strong-random-token-here"
  }
}
```

3. **Enable audit logging**:
```json
{
  "logging": {
    "syslog": true,
    "level": "info"
  }
}
```

4. **Drop privileges**:
```json
{
  "security": {
    "drop_user": "ddos-protect",
    "drop_group": "ddos-protect"
  }
}
```

### Regular Maintenance

**Weekly tasks**:
- Review attack logs
- Check false positive rate
- Update whitelists/blacklists
- Monitor resource usage

**Monthly tasks**:
- Update GeoIP database
- Review and tune thresholds
- Check for software updates
- Backup configuration

**Quarterly tasks**:
- Security audit
- Performance review
- Capacity planning

## Emergency Procedures

### System Under Heavy Attack

1. **Enable strictest mode**:
```bash
# Edit config
{
  "thresholds": {
    "udp_pps": 1000,
    "tcp_syn_pps": 500,
    "icmp_pps": 100,
    "http_rps": 10
  },
  "auto_blacklist": {
    "enabled": true,
    "duration": 300
  }
}

# Hot reload
sudo systemctl reload ddos-protect
```

2. **Enable XDP immediately**:
```bash
sudo ip link set dev eth0 xdp obj /usr/share/ddos-protect/ebpf/xdp_filter.o
```

3. **Add upstream filtering**:
   - Contact ISP for upstream filtering
   - Enable Cloudflare/AWS Shield
   - Activate DDoS mitigation service

### Complete Service Failure

1. **Fallback to firewall**:
```bash
# Block all except essential
sudo iptables -P INPUT DROP
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT  # SSH
```

2. **Restart service**:
```bash
sudo systemctl restart ddos-protect
```

3. **Check system resources**:
```bash
# CPU, memory, disk
top
free -h
df -h
```

---

**Document Version**: 1.0
**Last Updated**: 2025-01-17
