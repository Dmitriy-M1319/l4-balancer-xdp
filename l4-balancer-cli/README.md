# l4-balancer-cli

CLI for L4 XDP Load Balancer management

## Global flags

| Flag | Default | Description |
|---|---|---|
| `-a`, `--address` | `localhost:52001` | Balancer gRPC address |
| `-t`, `--timeout` | `10s` | Request timeout |

## Commands

### ping

Check balancer availability and measure latency.

```bash
l4-balancer-cli ping
l4-balancer-cli ping -a 10.0.0.5:52001
```

### config get

Print the current balancer configuration.

```bash
# Table output
l4-balancer-cli config get

# JSON output
l4-balancer-cli config get --json
```

### config update

Apply a new configuration from a JSON file.

```bash
l4-balancer-cli config update --file config.json
```

**config.json example:**
```json
{
  "services": [
    {
      "name": "web-svc",
      "vip": "10.0.0.1",
      "port": 80,
      "protocol": "tcp",
      "ip_version": 4,
      "algorithm": "rr",
      "backends": [
        { "ip": "192.168.1.10", "port": 8080, "weight": 1, "enabled": true, "ip_version": 4 },
        { "ip": "192.168.1.11", "port": 8080, "weight": 2, "enabled": true, "ip_version": 4 }
      ]
    }
  ]
}
```

Supported algorithms: `rr` (round-robin), `wrr` (weighted round-robin), `ch` (consistent hash).

### services

List services with optional filtering.

```bash
# All services (summary)
l4-balancer-cli services

# With backends
l4-balancer-cli services --backends

# With backends and metrics
l4-balancer-cli services --backends --metrics

# Filter by protocol
l4-balancer-cli services --protocol tcp

# Filter by IP version
l4-balancer-cli services --ip-version 4

# Only services with at least one enabled backend
l4-balancer-cli services --enabled-only
```

### backends list

List all backends across all services.

```bash
l4-balancer-cli backends list
l4-balancer-cli backends list --metrics
```

### backends enable / disable

Enable or disable a specific backend.

```bash
# By service name
l4-balancer-cli backends enable --service web-svc --backend-ip 192.168.1.10 --backend-port 8080
l4-balancer-cli backends disable --service web-svc --backend-ip 192.168.1.10 --backend-port 8080

# By VIP + port (when service name is unknown)
l4-balancer-cli backends enable \
  --vip 10.0.0.1 --service-port 80 \
  --backend-ip 192.168.1.10 --backend-port 8080
```