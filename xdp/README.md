# XDP BPF Program

The kernel-side half of the load balancer. Compiled to a BPF object file (`xdp.bpf.o`) and loaded by the controlplane via `libbpf`. The single `SEC("xdp") balancer_handler` entry point is called for every ingress packet on the attached interface.

## Packet processing pipeline

```
balancer_handler(ctx)
        │
        ├─ parse Ethernet header
        │         │
        │         ├─ ETH_P_ARP  → XDP_PASS  (let kernel handle ARP)
        │         ├─ ETH_P_IPV6 → (IPv6 path — mirrors IPv4)
        │         └─ ETH_P_IP   → parse IPv4
        │                   │
        │                   ├─ UDP → find_udp_backend()
        │                   │           └─ udp_balancer_handle_v4()
        │                   │                   └─ XDP_TX
        │                   │
        │                   └─ TCP → ddos_check_v4()
        │                              │  XDP_DROP (banned / threshold)
        │                              └─ XDP_PASS
        │                                   └─ find_tcp_backend()
        │                                         └─ tcp_balancer_handle_v4()
        │                                               └─ XDP_TX
        │
        └─ anything else → XDP_PASS
```

`XDP_TX` re-transmits the modified packet out of the same interface.  
`XDP_PASS` hands the packet to the normal kernel network stack.  
`XDP_DROP` discards the packet without any further processing.

---

## BPF maps

### Service / backend maps (double-buffered)

Two identical sets of maps allow atomic config updates without a read window where the XDP program sees inconsistent data:

| Map | Type | Key | Value | Capacity |
|---|---|---|---|---|
| `services_first` / `services_second` | `HASH` | `service_key` (VIP + port + protocol + ip_version) | `service_info` (backend_count, backend_start_idx, algorithm) | 256 |
| `backends_first` / `backends_second` | `ARRAY` | `__u32` index | `backend` (IP, port, MAC, weight, active flag) | 1024 |
| `atomic_index` | `ARRAY` | `0` | `__u64` (0 or 1) | 1 |

The controlplane writes the inactive set and then flips `atomic_index`. The XDP program reads `atomic_index` on each packet to select which set to use.

### Balancing algorithm state

| Map | Type | Purpose |
|---|---|---|
| `rr_index` | `HASH` | Per-service round-robin cursor (`__u32`) |
| `wrr_state_map` | `HASH` | Per-service WRR state (`current_index`, `current_weight_counter`) |
| `ch_curr_lookup` | `ARRAY` | Current Maglev lookup table: slot → backend index | 
| `ch_prev_lookup` | `ARRAY` | Previous Maglev lookup table (kept during transitions) |
| `ch_backends` | `ARRAY` | Backend array used exclusively by the CH path |
| `ch_config` | `ARRAY` | CH ring size per slot index |
| `ch_merge_control` | `ARRAY` | Merge readiness flag (set by controlplane) |
| `ch_stats_map` | `ARRAY` | CH diagnostic counters (total/stable/unstable lookups, merges) |

### TCP session state

| Map | Type | Key | Value | Capacity |
|---|---|---|---|---|
| `tcp_session_state` | `HASH` | `session_state_key` (src_ip, dst_ip, src_port, dst_port) | `session_state_val` (backend_idx, created_ns, timeout_ns) | 65536 |

Sessions are created on SYN and expire after 60 seconds (`TCP_STATE_TIMEOUT`). FIN/RST packets delete the entry immediately. The CH path only creates a session for "unstable" flows (those where `curr_lookup[slot] ≠ prev_lookup[slot]`); stable flows are re-hashed on each packet without touching the session table.

### Statistics

| Map | Type | Key | Value |
|---|---|---|---|
| `backends_packets_stats` | `PERCPU_ARRAY` | backend index | `summary_packets_data` |
| `services_packets_stats` | `PERCPU_HASH` | `service_key` | `summary_packets_data` |

`summary_packets_data`:
```c
struct summary_packets_data {
    __u64 total_packets;
    __u64 tcp_syn_packets;
    __u64 prepared_packets;
    __s32 connections;   // signed: SYN/FIN can land on different CPUs
    __u32 _pad;
    __u64 total_bytes;
};
```

`connections` is `__s32` (signed) because per-CPU copies are summed by the controlplane. A FIN on CPU 1 decrements that CPU's copy from 0 to -1; a SYN on CPU 0 increments CPU 0's copy. The sum across CPUs is correct. An unsigned type would wrap to `UINT32_MAX`.

### DDoS protection

| Map | Type | Key | Value | Capacity |
|---|---|---|---|---|
| `syn_tracker` | `LRU_HASH` | source IPv4 | `syn_counter` (syn_count, ack_count, window_start, total_packets) | 65536 |
| `blacklist` | `HASH` | source IPv4 | ban timestamp (ns) | 16384 |
| `ddos_cfg` | `ARRAY` | `0` | `ddos_config` | 1 |
| `global_syn` | `ARRAY` | `0` | `global_syn_stats` (syn_count, window_start, dropped_total) | 1 |

`syn_tracker` uses `LRU_HASH` so old entries are evicted automatically when the table fills up — no explicit cleanup needed.

---

## Balancing algorithms

All three algorithms share the same lookup path:

1. Read `atomic_index` → select active `services_*` / `backends_*` map pair
2. Look up `service_key` (VIP + port + protocol) → get `service_info`
3. For TCP: check `tcp_session_state` first — if a session exists, use the stored `backend_idx`
4. If no session: run the algorithm to select a backend
5. For TCP: write or update session state

### Round-robin (`BALANCER_RR = 0x00`)

`rr_balancer_handle()` reads the per-service cursor from `rr_index`, scans forward (with wrapping) until it finds an `active` backend, increments the cursor, and returns the backend pointer.

### Weighted round-robin (`BALANCER_WRR = 0x01`)

`wrr_balancer_handle()` reads `wrr_state` for the service. Uses the classic deficit-counter WRR approach: advances through backends, decrementing `current_weight_counter`; when the counter hits zero it moves to the next backend and resets the counter to that backend's weight.

### Consistent hash (`BALANCER_CH = 0x02`)

`ch_balancer_handle()`:

1. Computes a 32-bit flow hash from `(src_ip XOR dst_ip XOR src_port XOR dst_port)` using a Murmur2-like mix
2. Calls `consistent_hash_is_stable(hash)` — returns true when `curr_lookup[hash % ring_size] == prev_lookup[hash % ring_size]`
3. **Stable flow**: return `ch_backends[curr_lookup[hash % ring_size]]` — no session table write
4. **Unstable flow**: return backend from `curr_lookup`, write a session entry so future packets follow the same backend until the merge window closes

`consistent_hash_lookup(hash, use_prev)` implements the slot lookup for either the current or previous table.

---

## DDoS protection (`ddos_check_v4`)

Called for every inbound TCP packet before backend selection. Returns `XDP_DROP` or `XDP_PASS`.

```
ddos_check_v4(ip, tcp)
    │
    ├─ blacklist lookup → if banned and ban not expired → XDP_DROP
    │                     if expired → remove from blacklist
    │
    ├─ syn_tracker lookup / insert for src_ip
    │
    ├─ window reset if now - window_start > 10 s
    │
    ├─ if pure SYN (syn=1, ack=0):
    │       syn_count++
    │       global_syn.syn_count++
    │       if global_syn.syn_count > global_syn_threshold:
    │           global_syn.dropped_total++
    │           XDP_DROP   ← no per-IP ban (distributed flood)
    │
    ├─ if ACK (ack=1, syn=0): ack_count++
    │
    ├─ if syn_count > syn_threshold:
    │       add src_ip to blacklist
    │       dropped_total++
    │       XDP_DROP
    │
    └─ if syn_count > 10 and (syn_count*100)/ack_count > syn_ack_ratio:
            add src_ip to blacklist
            dropped_total++
            XDP_DROP
```

**Three independent detection mechanisms:**

| Mechanism | Config field | Targets |
|---|---|---|
| Per-IP SYN rate | `syn_threshold` | Single-source flood |
| SYN/ACK ratio | `syn_ack_ratio` | Half-open flood (incomplete handshakes) |
| Global SYN rate | `global_syn_threshold` | Distributed flood with random source IPs |

The global mechanism drops without creating a blacklist entry because in a distributed flood the source IPs are spoofed and a per-IP ban would just fill the blacklist map with useless entries.

---

## L2 DSR forwarding

After a backend is selected, `tcp_balancer_handle_v4` (and the UDP equivalent) rewrites only the Ethernet destination MAC:

```c
/* L2 DSR: only rewrite dst_MAC → backend MAC; all IP/TCP headers stay unchanged. */
__u8 my_mac[6];
__builtin_memcpy(my_mac, l2_header->h_dest, 6);
__builtin_memcpy(l2_header->h_dest, backend->mac, 6);
__builtin_memcpy(l2_header->h_source, my_mac, 6);
return 0;  // XDP_TX
```

The source IP remains the client's IP. The destination IP remains the VIP. Backend servers must:
1. Have the VIP assigned to `lo` (`ip addr add <VIP>/32 dev lo`)
2. Suppress ARP replies for the VIP on the physical interface (`arp_ignore=1`, `arp_announce=2` on `eth0`)

Return traffic (backend → client, src=VIP, dst=client) is routed by the kernel directly — it does not pass through the load balancer.

### Restoring Full NAT

All Full NAT code is preserved in `/* FULL_NAT_BEGIN ... FULL_NAT_END */` comment blocks. To revert:

1. In `balancer.bpf.c`: uncomment the `reverse_nat_key/val/map` and `lb_config_val/lb_config` declarations at the top, and the IP rewrite blocks in `tcp_balancer_handle_v4`, `udp_balancer_handle_v4`, and `balancer_handler`
2. In `controlplane/src/manager/xdpdataplane.cpp`: uncomment the `openBpfMap("lb_config")` call and the `bpf_map_update_elem` call in `ReloadConfig`
3. In `controlplane/include/manager/xdpdataplane.h`: uncomment `m_lbConfigMap` and `m_lbConfigMapFd`

---

## Build

The XDP program is compiled by the CMake custom target in `xdp/CMakeLists.txt`:

```bash
# Step 1: generate vmlinux.h from the running kernel's BTF data
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Step 2: compile BPF object
clang -O2 -g -target bpf -c balancer.bpf.c -o xdp.bpf.o
```

Running `cmake --build build` from the project root runs both steps automatically.

**Requirements:**
- `clang` 12+ with BPF target support
- `bpftool` (for `vmlinux.h` generation)
- Linux kernel 5.15+ with BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`)
- `libbpf` headers (included transitively via `vmlinux.h`)
