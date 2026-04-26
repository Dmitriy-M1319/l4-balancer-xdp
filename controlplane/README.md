# Controlplane

The userspace daemon responsible for:

- Loading and validating the JSON configuration
- Resolving backend MAC addresses via ARP/NDP
- Populating XDP BPF maps via `libbpf`
- Exposing a gRPC management API
- Scraping BPF map counters and publishing them to Prometheus via OpenTelemetry

## Component overview

```
controlplane/
├── main.cpp                  Entry point — CLI parsing, wiring, lifecycle
├── include/
│   ├── config/               Config data model and parsing
│   ├── manager/              Dataplane abstraction and XDP implementation
│   ├── algorithm/            Consistent hash (Maglev) implementation
│   ├── metrics/              Prometheus scraping and OpenTelemetry wiring
│   ├── netutils/             ARP / NDP helpers (MAC resolution)
│   └── server/               gRPC server
└── src/                      Corresponding .cpp files
```

---

## Module: config

**Headers:** `include/config/`

| File | Responsibility |
|---|---|
| `baseconfig.h` | Core data types: `BalancerService`, `BalancerReal`, `DDoSConfig`, `BaseConfig` |
| `baseconfigparser.h` | Abstract parser interface: `BaseConfigParser::Parse(string) → variant<BaseConfig, string>` |
| `jsonparser.h` | Concrete JSON parser using `nlohmann/json` |
| `configloader.h` | Abstract source interface: `ConfigLoader::LoadConfig() → string` |
| `fileconfigloader.h` | Concrete file-based loader |
| `validator.h` | `ConfigValidator::Validate(BaseConfig) → optional<string>` — validates VIPs, port ranges, algorithm names |

Config is immutable after parsing. A full reload replaces the entire `BaseConfig` struct.

---

## Module: manager

**Headers:** `include/manager/`

### IDataplane

Abstract interface separating the config manager from the concrete XDP implementation. All BPF map writes go through this interface, which makes unit testing possible without an actual XDP program.

```cpp
class IDataplane {
    virtual optional<string> ReloadConfig(const BaseConfig&) = 0;
    virtual map<string, unsigned long> GetBlackList() const = 0;
};
```

### XdpDataplane

Concrete implementation using `libbpf`. Lifecycle:

1. **`RunProgram(binPath)`** — opens and loads the BPF object file, attaches the XDP program to the interface, opens all BPF map file descriptors
2. **`ReloadConfig(cfg)`** — resolves MACs for all backends, builds `xdp::Backend` / `xdp::ServiceKey` / `xdp::ServiceInfo` vectors, writes them into the double-buffered service/backend maps, flips the atomic index, updates DDoS config map
3. **`ChPeriodicMaintenance()`** — called every second from a dedicated thread; drives consistent hash merge timers (curr → prev table consolidation)
4. **`GetBackendsCurrentMetrics()` / `GetServicesCurrentMetrics()`** — reads per-CPU `summary_packets_data` arrays, sums across CPUs, converts IPs with `inet_ntop`
5. **`GetDdosStats()`** — reads `global_syn_stats` + counts blacklist entries

#### Double-buffered BPF maps

To allow atomic config updates without briefly serving inconsistent data, services and backends are stored in two sets of maps (`_first` / `_second`). An `atomic_index` map selects which set is currently active. The XDP program reads `atomic_index` on every packet; the controlplane writes the inactive set then flips the index.

```
BPF maps in use:
  services_map_first  / services_map_second   — service_key → service_info
  backends_map_first  / backends_map_second   — index → backend
  atomic_index_map                            — 0 → {0|1}
  rr_index_map                                — service_key → current RR position
  session_state_map                           — session_state_key → session_state_val
  wrr_state_map                               — service_key → wrr state
  backends_stats_map                          — index → summary_packets_data (per-CPU)
  services_stats_map                          — service_key → summary_packets_data (per-CPU)
  ch_curr_lookup_map                          — slot → backend_index (current CH ring)
  ch_prev_lookup_map                          — slot → backend_index (previous CH ring)
  ch_backends_map                             — index → backend
  ch_config_map                               — service_key → ch_config (ring size)
  ddos_cfg_map                                — 0 → ddos_config
  blacklist_map                               — src_ipv4 → ban_timestamp_ns
  global_syn_map                              — 0 → global_syn_stats
```

### ConfigManager

Thin orchestration layer. Holds the current `BaseConfig` and delegates map writes to `IDataplane`. Handles gRPC commands:

- `LoadConfig` — validates and pushes to dataplane
- `SetRealState` — enables/disables a single backend, rebuilds the dataplane config
- `ListServices` / `ListBackends` — read-only queries against the in-memory config
- `GetBlackList` — delegates to dataplane

### xdpstructs.h

Mirrors the BPF-side C structs in C++ for use in `bpf_map_update_elem` calls. Structs must have identical layout (alignment, padding) to their BPF counterparts.

---

## Module: algorithm

**Headers:** `include/algorithm/`

Maglev-based consistent hash with dual lookup tables.

### ConsistentHashInstance

One instance per service. Internally maintains:

- `curr_lookup` — active backend-index array of size `hashring_size`
- `prev_lookup` — previous backend-index array (kept until `merge_timeout_ticks` seconds pass with no backend changes)
- `merge_timeout_ticks` counter — decremented every `tickMergeTimer()` call (1/s); when it reaches zero, `merge()` copies `curr` → `prev`

#### Dual lookup semantics

When the backend pool changes, `updateBackends()` rebuilds `curr_lookup`. Flows that already exist in the session table keep their backend assignment. New flows that hash to a slot where `curr[slot] == prev[slot]` are "stable" — they need no session entry. Flows where the two tables disagree are "unstable" and do require a session record during the transition window.

This minimises the number of session state entries at the cost of a 1-second periodic maintenance tick.

### ConsistentHashManager

`std::map<ServiceKey, ConsistentHashInstance>` — one instance per CH service. `XdpDataplane` holds a `ConsistentHashManager` and calls `ChPeriodicMaintenance()` which iterates all instances and calls `tickMergeTimer()`.

After every backend update `updateChBpfMaps()` writes both `curr_lookup` and `prev_lookup` into the corresponding BPF maps.

---

## Module: metrics

**Headers:** `include/metrics/`

### IMetricsProvider

Interface on `XdpDataplane`:

```cpp
virtual map<BackendInfo, MetricsData> GetBackendsCurrentMetrics() = 0;
virtual map<ServiceInfo,  MetricsData> GetServicesCurrentMetrics() = 0;
virtual DdosStats GetDdosStats() = 0;
```

### MetricsServer

Runs a background thread that calls `scrapMetrics()` every `scrape_interval` (default 5 s).

- Counters (`total_packets`, `total_bytes`, `tcp_syn_packets`, `prepared_packets`) are delta-tracked: the difference between the current and previous sample is added to the OpenTelemetry `Counter`. This converts ever-growing BPF per-CPU sums into correct Prometheus counters.
- Gauges (`connections_active`, `*_per_second`, `blacklist_size`) are recorded directly.
- Rates (`pps`, `bps`, `syn/s`) are computed as `Δvalue / elapsed_seconds` and recorded as `Gauge<double>`.
- DDoS: `dropped_total` delta is added to a counter; `blacklist_size` is a gauge.

OpenTelemetry Prometheus exporter binds to `0.0.0.0:9464` and serves metrics on `/metrics`.

---

## Module: netutils

**Headers:** `include/netutils/`

| File | Responsibility |
|---|---|
| `arp.h` / `arp.cpp` | `resolveArp(iface, ip) → optional<mac>` — sends ARP request and waits for reply |
| `ndp.h` / `ndp.cpp` | ICMPv6 Neighbor Discovery for IPv6 backends |

MAC resolution is called in `XdpDataplane::ReloadConfig` for every enabled backend before writing to BPF maps. Backends whose MAC cannot be resolved are skipped with a warning.

---

## Module: server

**Headers:** `include/server/`

gRPC server implementing `L4BalancerApi` (defined in `proto/api/controlplane-api.proto`).

Listens on `0.0.0.0:52001`.

| RPC | Behaviour |
|---|---|
| `GetConfig` | Returns full current config as protobuf |
| `UpdateConfig` | Validates and calls `ConfigManager::LoadConfig` |
| `ListServices` | Supports filtering by protocol, ip_version, enabled-only |
| `ListBackends` | Optionally includes per-backend metrics |
| `SetBackendStatus` | Enables or disables one backend by service name or VIP+port |
| `Ping` | Health check — returns empty message immediately |
| `GetBlackList` | Returns current DDoS blacklist with ban timestamps |

Generated stubs live in `api/` (committed to avoid requiring `protoc` at build time).

---

## Startup sequence

```
main()
  │
  ├─ parse CLI flags
  ├─ FileConfigLoader::openFile()
  ├─ XdpDataplane::RunProgram()   ← load BPF, attach to iface, open all map fds
  ├─ JsonBaseConfigParser::Parse()
  ├─ ConfigValidator::Validate()
  ├─ ConfigManager::LoadConfig()  ← ARP resolve + BPF map population
  ├─ MetricsServer::Serve()       ← start scrape thread
  ├─ GrpcServer::init()           ← start gRPC in blocking mode
  └─ CH maintenance thread        ← tickMergeTimer every 1 s
```
