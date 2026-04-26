# l4-balancer-xdp

A high-performance Layer 4 load balancer built on Linux XDP (eXpress Data Path). Packets are processed in the kernel at the earliest possible hook point — before socket buffer allocation — achieving near line-rate forwarding with minimal CPU overhead.

The balancer uses **L2 DSR (Direct Server Return)**: only the destination MAC address is rewritten; IP/TCP headers are left intact. Backend servers reply directly to clients, so return traffic never passes through the load balancer. This halves the load on the LB and eliminates the NAT state bottleneck.

## Features

- **L2 DSR forwarding** — only dst MAC is rewritten; backends reply directly to clients
- **Three load balancing algorithms**
  - Round-robin (`rr`)
  - Weighted round-robin (`wrr`)
  - Consistent hash (`ch`) — Maglev-based with dual lookup tables (curr + prev) for minimal session state
- **TCP session tracking** — per-flow state with 60-second timeout; connection counters increase on SYN, decrease on FIN/RST
- **DDoS protection**
  - Per-IP SYN rate limiting with configurable time window (10 s)
  - SYN/ACK ratio anomaly detection (half-open flood)
  - Global per-VIP SYN rate threshold (distributed flood, random source IPs)
  - Blacklist with configurable ban duration
- **Prometheus metrics** — per-backend and per-service packet/byte counters, PPS/BPS rates, active connections, DDoS dropped totals, blacklist size
- **Grafana dashboards** — pre-built dashboard JSON shipped in `grafana/`
- **gRPC management API** — live config reload, backend enable/disable, blacklist query
- **Go CLI** (`l4-balancer-cli`) — human-friendly wrapper over the gRPC API


## Requirements

### Build-time

| Dependency | Min version | Notes |
|---|---|---|
| CMake | 3.18 | |
| Clang | 12+ | BPF target compilation (`-target bpf`) |
| libbpf | 0.8+ | `pkg-config libbpf` |
| bpftool | any | generates `vmlinux.h` from running kernel |
| GCC / G++ | C++20 | controlplane binary |
| nlohmann/json | 3.x | JSON config parsing |
| Boost | 1.74+ | `program_options` |
| gRPC | 1.50+ | management API |
| opentelemetry-cpp | 1.9+ | Prometheus exporter (build with `WITH_PROMETHEUS=ON`, `WITH_ABI_VERSION_2=ON`) |
| Go | 1.24+ | CLI only |

### Runtime

- Linux kernel **5.15+** (XDP native mode; `BPF_MAP_TYPE_LRU_HASH` support)
- Network interface with native XDP driver support (e.g. `i40e`, `mlx5`, `virtio_net`)
- `CAP_NET_ADMIN` / root for XDP program attachment
- Backends must have VIP configured on `lo` — see [Backend setup](#backend-setup-for-l2-dsr)

## Build

```bash
# 1. Clone
git clone https://github.com/Dmitriy-M1319/l4-balancer-xdp.git
cd l4-balancer-xdp

# 2. Configure
cmake -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DOPENTELEMETRY_ABI_VERSION_NO=2 \
  -DWITH_PROMETHEUS=ON \
  -DWITH_ABI_VERSION_2=ON \
  -DWITH_ABI_VERSION_1=OFF \
  -DBUILD_TESTING=OFF \
  -DWITH_EXAMPLES=OFF

# 3. Build (BPF object + controlplane binary)
cmake --build build -j$(nproc)

# 4. Build CLI (optional)
cd l4-balancer-cli
go build -o l4-balancer-cli ./cmd/l4-balancer-cli
```

## Configuration

The controlplane reads a JSON config file on startup and on every `UpdateConfig` gRPC call.

### Minimal configuration (round-robin, TCP)

```json
{
  "services": [
    {
      "name": "web",
      "vip": "10.0.0.1",
      "port": 80,
      "protocol": "tcp",
      "ip_version": 4,
      "algorithm": "rr",
      "backends": [
        { "ip": "192.168.1.10", "port": 80, "weight": 1, "enabled": true, "ip_version": 4 },
        { "ip": "192.168.1.11", "port": 80, "weight": 1, "enabled": true, "ip_version": 4 }
      ]
    }
  ]
}
```

### Configuration with DDoS protection

```json
{
  "services": [
    {
      "name": "web",
      "vip": "10.0.0.1",
      "port": 80,
      "protocol": "tcp",
      "ip_version": 4,
      "algorithm": "ch",
      "backends": [
        { "ip": "192.168.1.10", "port": 80, "weight": 1, "enabled": true, "ip_version": 4 },
        { "ip": "192.168.1.11", "port": 80, "weight": 2, "enabled": true, "ip_version": 4 },
        { "ip": "192.168.1.12", "port": 80, "weight": 1, "enabled": true, "ip_version": 4 }
      ]
    }
  ],
  "ddos_config": {
    "syn_threshold": 1000,
    "syn_ack_ratio": 500,
    "global_syn_threshold": 50000,
    "ban_duration_ms": 300000
  }
}
```

#### DDoS parameters

| Parameter | Unit | Description |
|---|---|---|
| `syn_threshold` | SYN packets / 10 s window | Per-source-IP limit; exceeding it adds the IP to the blacklist |
| `syn_ack_ratio` | SYN×100 / ACK | Triggers after >10 SYN from a single IP; ratio >500 means 5 SYN per 1 ACK |
| `global_syn_threshold` | SYN packets / 10 s window | Total SYN rate across all sources for the VIP; drop without per-IP ban (covers random-source floods) |
| `ban_duration_ms` | milliseconds | How long a banned IP is blocked |

Omitting `ddos_config` disables all DDoS checks. Setting a threshold to `0` disables that specific check.

#### Supported algorithms

| Value | Description |
|---|---|
| `rr` | Round-robin — equal distribution in order |
| `wrr` | Weighted round-robin — distribution proportional to backend `weight` |
| `ch` | Consistent hash — flow-pinning using dual Maglev lookup tables; minimises session state on backend pool changes |

## Running

```bash
sudo ./build/controlplane/l4-controlplane \
  --config-file config.json \
  --format json \
  --xdp-binary build/xdp/xdp.bpf.o \
  --iface eth0
```

| Flag | Default | Description |
|---|---|---|
| `--config-file` | — | Path to JSON config (required) |
| `--format` | — | `json` (required) |
| `--xdp-binary` | — | Path to compiled `xdp.bpf.o` (required) |
| `--iface` | `eth0` | Network interface to attach the XDP program |

The process exposes:
- **gRPC API** on `0.0.0.0:52001`
- **Prometheus scrape endpoint** on `0.0.0.0:9464`

## Backend setup for L2 DSR

Every backend server must have the VIP configured on its loopback and must not answer ARP for the VIP on its physical interface:

```bash
# Add VIP to loopback (backend accepts packets with dst=VIP)
sudo ip addr add <VIP>/32 dev lo

# Suppress ARP for VIP on the physical interface
# (prevents MAC table confusion on the bridge/switch)
sudo sysctl -w net.ipv4.conf.eth0.arp_ignore=1
sudo sysctl -w net.ipv4.conf.eth0.arp_announce=2
```

To persist across reboots add the `ip addr` line to a network config and the `sysctl` values to `/etc/sysctl.d/`.

## CLI usage

See [l4-balancer-cli/README.md](l4-balancer-cli/README.md) for full command reference.

```bash
# Check connectivity
l4-balancer-cli ping -a <LB_IP>:52001

# Show running config
l4-balancer-cli config get -a <LB_IP>:52001

# Push new config
l4-balancer-cli config update --file config.json -a <LB_IP>:52001

# List services with live metrics
l4-balancer-cli services --backends --metrics -a <LB_IP>:52001

# Disable a backend
l4-balancer-cli backends disable \
  --service web --backend-ip 192.168.1.11 --backend-port 80 \
  -a <LB_IP>:52001

# Show current DDoS blacklist
l4-balancer-cli blacklist -a <LB_IP>:52001
```

## Monitoring

### Prometheus

Add the following scrape config to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: l4-balancer
    static_configs:
      - targets: ['<LB_IP>:9464']
    scrape_interval: 5s
```

### Metrics reference

| Metric | Type | Description |
|---|---|---|
| `lb_backend_packets_total` | counter | Total packets forwarded to backend |
| `lb_backend_bytes_total` | counter | Total bytes forwarded to backend |
| `lb_backend_tcp_syn_packets_total` | counter | TCP SYN packets to backend |
| `lb_backend_prepared_packets_total` | counter | Packets prepared (post-select) for backend |
| `lb_backend_connections_active` | gauge | Active TCP connections to backend |
| `lb_backend_packets_per_second` | gauge | Current PPS to backend |
| `lb_backend_bytes_per_second` | gauge | Current BPS to backend |
| `lb_backend_syn_per_second` | gauge | Current SYN rate to backend |
| `lb_service_packets_total` | counter | Total packets for service |
| `lb_service_bytes_total` | counter | Total bytes for service |
| `lb_service_connections_active` | gauge | Active connections for service |
| `lb_service_packets_per_second` | gauge | Current PPS for service |
| `lb_ddos_dropped_packets_total` | counter | Cumulative packets dropped by DDoS filter |
| `lb_ddos_blacklist_size` | gauge | Number of currently banned source IPs |

All backend metrics carry labels: `backend`, `port`, `ip_version`.  
All service metrics carry labels: `service`, `vip`, `port`, `ip_version`.

### Grafana

A pre-built dashboard JSON is located at `grafana/dashboards/l4-balancer.json`.

To use with Docker Compose add a Grafana service mounting the `grafana/` directory:

```yaml
services:
  prometheus:
    image: prom/prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml

  grafana:
    image: grafana/grafana
    volumes:
      - ./grafana/provisioning:/etc/grafana/provisioning
      - ./grafana/dashboards:/var/lib/grafana/dashboards
    ports:
      - "3000:3000"
```

The provisioning directory configures the Prometheus datasource and dashboard automatically on first start.

## DDoS testing

```bash
# Single-source SYN flood (tests syn_threshold → per-IP ban)
hping3 -S --flood -p 80 <VIP>

# Distributed flood with random source IPs (tests global_syn_threshold)
hping3 -S --flood --rand-source -p 80 <VIP>

# Observe bans in real time
cat /sys/kernel/debug/tracing/trace_pipe

# Inspect blacklist
bpftool map dump name blacklist

# Inspect global SYN counter and dropped_total
bpftool map dump name global_syn
```

## Project structure

```
l4-balancer-xdp/
├── xdp/                    # BPF kernel program
│   ├── balancer.bpf.c      # XDP entry point, all packet processing logic
│   ├── vmlinux.h           # kernel type definitions (generated at build time)
│   └── CMakeLists.txt
├── controlplane/           # Userspace daemon
│   ├── include/            # Public headers (config, manager, metrics, server, algorithm)
│   ├── src/                # Implementations
│   ├── api/                # Generated gRPC stubs
│   ├── proto/              # Protobuf definitions
│   ├── tests/              # Unit tests
│   └── CMakeLists.txt
├── l4-balancer-cli/        # Go management CLI
│   ├── cmd/                # CLI entry point
│   ├── internal/           # Commands, client, output formatting
│   └── api/                # Generated Go gRPC stubs
├── grafana/                # Grafana provisioning and dashboard
│   ├── provisioning/       # Datasource and dashboard config
│   └── dashboards/         # l4-balancer.json
└── CMakeLists.txt
```
