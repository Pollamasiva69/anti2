# DDoS Protection System - Architecture Documentation

## System Overview

The DDoS Protection System is designed as a multi-layered defense system with each layer specialized for different types of attacks and operating at different levels of the network stack.

## Core Components

### 1. Packet Capture Layer

**File**: `src/packet/capture.c`

**Technology**: libpcap with AF_PACKET sockets

**Responsibilities**:
- Raw packet capture from network interface
- Zero-copy packet handling where possible
- Packet distribution to worker threads
- Promiscuous mode management

**Performance**:
- Supports 10Gbps+ with proper hardware
- ~1M packets per second processing
- Minimal memory copying

### 2. Packet Parser

**File**: `src/packet/parser.c`

**Supported Protocols**:
- Ethernet (802.3)
- IPv4/IPv6
- TCP/UDP/ICMP
- HTTP/HTTPS (application layer)

**Features**:
- Zero-allocation parsing
- Malformed packet detection
- Fragment handling
- Header validation

### 3. Connection Tracking

**Files**:
- `src/storage/hashtable.c` - Lock-free hash table
- `src/storage/lru_cache.c` - LRU eviction cache

**Data Structures**:
```c
Hash Table:
- Size: 1M buckets (configurable)
- Collision handling: Chaining
- Locking: Per-bucket RW locks
- Hash function: MurmurHash3

LRU Cache:
- Size: 512K entries (configurable)
- Eviction: Least recently used
- Timeouts: Protocol-specific
- Thread-safe: Global RW lock
```

**Connection States**:
- TCP: SYN_SENT, SYN_RECEIVED, ESTABLISHED, FIN_WAIT, CLOSE_WAIT, CLOSED
- UDP: Stateless with timeout tracking
- ICMP: Echo request/reply correlation

### 4. Traffic Analyzer

**File**: `src/detection/analyzer.c`

**Analysis Methods**:
1. **Statistical Analysis**:
   - Packet rate (PPS)
   - Bandwidth utilization (BPS)
   - Connection rate
   - Protocol distribution

2. **Behavioral Analysis**:
   - Baseline establishment
   - Anomaly detection
   - Traffic entropy calculation
   - Pattern matching

3. **Reputation Scoring**:
   - Per-IP reputation (0-100)
   - Dynamic adjustment based on behavior
   - Auto-blacklist on low scores

4. **Machine Learning**:
   - Simple decision tree classification
   - K-means clustering (planned)
   - Feature extraction from packets

### 5. Protection Modules

#### UDP Protection
**File**: `src/detection/udp_protect.c`

**Detects**:
- UDP floods (high PPS)
- DNS amplification (large responses from port 53)
- NTP amplification (monlist responses)
- SSDP reflection (port 1900)
- Memcached amplification (VALUE responses)
- Fragmentation attacks

**Mitigation**:
- Rate limiting per source IP
- Response size validation
- Port-based filtering
- Auto-blacklisting

#### TCP Protection
**File**: `src/detection/tcp_protect.c`

**Detects**:
- SYN flood (high SYN rate)
- ACK flood (ACK without established connection)
- RST/FIN flood
- PSH+ACK flood
- Slowloris (slow connections)
- Sockstress
- Invalid flag combinations
- Port scanning (NULL, XMAS scans)

**Mitigation**:
- SYN cookies (OS-level)
- Connection rate limiting
- Slow connection timeout
- Invalid packet dropping

#### ICMP Protection
**File**: `src/detection/icmp_protect.c`

**Detects**:
- ICMP flood (ping flood)
- Ping of Death (oversized packets)
- Smurf attack (broadcast replies)
- ICMP fragmentation
- ICMP redirect abuse

**Mitigation**:
- ICMP rate limiting
- Size validation
- Redirect blocking
- Fragment dropping

#### HTTP Protection
**File**: `src/detection/http_protect.c`

**Detects**:
- HTTP GET flood
- HTTP POST flood
- Slow POST attacks
- Header anomalies
- Bot traffic (User-Agent analysis)
- Missing required headers

**Mitigation**:
- Request rate limiting
- JavaScript challenge (planned)
- CAPTCHA (planned)
- User-Agent blacklisting
- Reputation-based blocking

### 6. Rate Limiting Engine

**File**: `src/filter/ratelimit.c`

**Algorithms**:
1. **Token Bucket**: Burst handling
2. **Sliding Window**: Precise rate limiting

**Features**:
- Per-IP rate limits
- Configurable PPS and BPS limits
- Multiple time windows (1s, 10s, 60s)
- Automatic cleanup

**Implementation**:
```c
Rate Limit Structure:
- Buckets per second (sliding window)
- Current token count
- Last update timestamp
- Lock per IP bucket
```

### 7. Firewall Integration

**File**: `src/filter/firewall.c`

**Backends**:
- iptables (legacy)
- nftables (modern)

**Operations**:
- Dynamic rule insertion
- IP blocking with TTL
- Rate limit rules
- Rule cleanup

**Integration**:
```bash
# Chain structure
iptables -N DDOS_PROTECT
iptables -I INPUT -j DDOS_PROTECT

# Block IP
iptables -I DDOS_PROTECT -s 1.2.3.4 -j DROP

# Rate limit
iptables -I DDOS_PROTECT -s 1.2.3.4 -m limit --limit 100/sec -j ACCEPT
```

### 8. eBPF/XDP Layer

**Files**:
- `ebpf/xdp_filter.c` - XDP program
- `src/filter/ebpf_loader.c` - Loader

**Advantages**:
- Kernel-level filtering
- Pre-routing packet drop
- 10x performance improvement
- Zero userspace overhead

**XDP Program Flow**:
```
Packet arrives → XDP program runs → Decision (XDP_PASS/XDP_DROP)
                                           ↓
                            Blacklist check → Drop if found
                            Whitelist check → Pass if found
                            Protocol check → Basic filtering
                            Anomaly detection → Drop if suspicious
```

**BPF Maps**:
- `blacklist`: IPv4 → timestamp
- `whitelist`: IPv4 → dummy
- `stats`: Per-CPU statistics

### 9. GeoIP Integration

**File**: `src/geoip/geoip.c`

**Database**: MaxMind GeoIP2 (optional)

**Features**:
- Country code lookup
- ASN lookup
- Country-based blocking
- ASN-based filtering

### 10. IP Set Management

**File**: `src/storage/ipset.c`

**Features**:
- Efficient IP storage
- CIDR range support
- Automatic expiration
- File persistence
- Fast lookup (hash-based)

**Use Cases**:
- Whitelist management
- Blacklist with TTL
- Permanent blocks
- Network ranges

### 11. Management API

**File**: `src/api/rest_server.c`

**Framework**: libmicrohttpd

**Endpoints**:
```
GET  /api/stats              - Global statistics
GET  /api/attacks            - Recent attacks
GET  /api/blacklist          - Blacklisted IPs
POST /api/blacklist          - Add IP to blacklist
DELETE /api/blacklist/:ip    - Remove from blacklist
GET  /api/whitelist          - Whitelisted IPs
POST /api/whitelist          - Add to whitelist
GET  /api/config             - Current configuration
PUT  /api/config             - Update configuration
POST /api/config/reload      - Hot reload
GET  /api/connections        - Active connections
```

**Security**:
- Token-based authentication
- Rate limiting on API calls
- Input validation
- HTTPS support (planned)

### 12. WebSocket Dashboard

**File**: `src/api/websocket.c`

**Features**:
- Real-time statistics updates
- Attack alerts
- Live connection monitoring
- System logs streaming

**Message Format**:
```json
{
  "type": "stats",
  "total_packets": 1234567,
  "total_bytes": 9876543210,
  "dropped_packets": 123,
  "current_connections": 456
}

{
  "type": "attack",
  "attack_type": "TCP SYN Flood",
  "source_ip": "1.2.3.4",
  "timestamp": 1234567890
}
```

## Multi-Threading Architecture

### Thread Model

```
Main Thread:
  ├─ Initialization
  ├─ Signal handling
  └─ Cleanup

Worker Threads (configurable):
  ├─ Packet capture
  ├─ Packet processing
  └─ Analysis pipeline

Statistics Thread:
  └─ Periodic stats logging

Cleanup Thread:
  └─ Expired connection cleanup

API Server Thread:
  └─ HTTP request handling

WebSocket Thread:
  └─ Client connections
```

### Synchronization

**Lock Types**:
- `pthread_rwlock_t`: Reader-writer locks for statistics
- `pthread_mutex_t`: Mutual exclusion for critical sections
- Atomic operations: `__sync_fetch_and_add()` for counters

**Lock-Free Structures**:
- Per-bucket locking in hash table
- RCU-like patterns for read-heavy workloads

### CPU Affinity

```c
// Pin worker thread to CPU core
cpu_set_t cpuset;
CPU_ZERO(&cpuset);
CPU_SET(worker_id % num_cpus, &cpuset);
pthread_setaffinity_np(thread, sizeof(cpuset), &cpuset);
```

## Memory Management

### Allocation Strategy

1. **Pre-allocation**:
   - Connection table: Allocated at startup
   - LRU cache: Fixed size allocation
   - Per-thread buffers: Avoid malloc in hot path

2. **Memory Pools**:
   - Packet structures
   - IP statistics entries
   - Connection entries

3. **Automatic Cleanup**:
   - Expired connections
   - LRU eviction
   - Periodic GC

### Memory Footprint

```
Base system:           ~100 MB
Connection table:      ~400 MB (1M entries)
LRU cache:            ~200 MB (512K entries)
IP statistics:         ~50 MB (65K entries)
Per connection:        ~1 KB

Total (typical):       ~750 MB
```

## Performance Optimizations

### Compiler Optimizations

```makefile
CFLAGS = -O3                    # Maximum optimization
         -march=native          # CPU-specific instructions
         -mtune=native          # CPU-specific tuning
         -flto                  # Link-time optimization
         -funroll-loops         # Loop unrolling
         -ftree-vectorize       # Auto-vectorization
```

### Cache Optimization

- **Cache-aligned structures**: 64-byte alignment
- **Data locality**: Related data grouped
- **Prefetching**: `__builtin_prefetch()`

### SIMD Usage

```c
// Planned: AVX2 for bulk operations
#include <immintrin.h>

// Example: Compare 8 IPs simultaneously
__m256i ip_vec = _mm256_loadu_si256((__m256i*)ip_array);
__m256i result = _mm256_cmpeq_epi32(ip_vec, target);
```

### NUMA Awareness

```c
// Bind memory to NUMA node
numa_set_preferred(node_id);
void *mem = numa_alloc_onnode(size, node_id);
```

## Configuration Management

### Hot Reload

Process:
1. Load new configuration from file
2. Validate new configuration
3. Acquire global write lock
4. Swap configuration atomically
5. Release lock
6. Old config still accessible during transition

### Configuration Validation

- Schema validation
- Range checking
- Dependency verification
- Backward compatibility

## Logging and Monitoring

### Log Levels

```
DEBUG:    Detailed debug information
INFO:     Normal operations
WARN:     Warning conditions
ERROR:    Error conditions
CRITICAL: System-critical errors
```

### Log Rotation

- Automatic rotation at 100 MB
- Timestamp-based file naming
- Configurable retention

### Syslog Integration

```c
openlog("ddos-protection", LOG_PID | LOG_CONS, LOG_DAEMON);
syslog(LOG_WARNING, "Attack detected: %s", attack_type);
```

## Deployment Architecture

### Single-Server Deployment

```
Internet → Router → DDoS Protection → Application Server
```

### Inline Mode

```
Internet → DDoS Protection (bridge mode) → LAN
```

### High-Availability Setup

```
Internet → Load Balancer
              ├─ DDoS Protection #1 (active)
              └─ DDoS Protection #2 (standby)
                      ↓
                Application Servers
```

## Future Enhancements

1. **Advanced ML**:
   - Neural network classifier
   - Real-time model training
   - Feature engineering

2. **Distributed Mode**:
   - Multi-node coordination
   - Shared blacklist
   - Load distribution

3. **Enhanced XDP**:
   - Map-in-map for complex rules
   - BTF support
   - BPF-to-BPF calls

4. **Additional Protocols**:
   - QUIC/HTTP3
   - gRPC
   - WebSocket attacks

5. **Cloud Integration**:
   - AWS Shield integration
   - Cloudflare API
   - Azure DDoS Protection

---

**Document Version**: 1.0
**Last Updated**: 2025-01-17
