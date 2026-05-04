#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define ETH_P_ARP   0x0806

#define BALANCER_RR 0x00
#define BALANCER_WRR 0x01
#define BALANCER_CH 0x02

#define TCP_STATE_TIMEOUT 60000000000ULL // 1 minute (in ns)
#define DDOS_WINDOW_NS      10000000000ULL // 10 sec
#define DDOS_CLEANUP_NS     60000000000ULL // 1 minute


// Key: composition VIP + protocol + port
struct service_key {
    union {
        __u32 vip4;       
        __u8  vip6[16];
    };    
    __u16 port;       
    __u8 protocol;
    __u8 ip_version;  
    __u8 _pad[4];        
};

// Service configuration
struct service_info {
    __u32 backend_count;
    __u32 backend_start_idx;
    __u8  algorithm;
    __u8  _pad[3];
    __u32 service_idx;   // index into services_packets_stats PERCPU_ARRAY
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);  
    __type(key, struct service_key);
    __type(value, struct service_info);
} services_first SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);  
    __type(key, struct service_key);
    __type(value, struct service_info);
} services_second SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64); 
} atomic_index SEC(".maps");

// Real Backend for balancing
struct backend {
    union {
        __u32 ipv4;
        __u8  ipv6[16];
    };                
    __u16 port;              
    unsigned char mac[6];    
    __u8 active;
    __u8 ip_version;             
    __u8 weight;
    __u8 pad[2];         
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1024);  
    __type(key, __u32);         
    __type(value, struct backend);
} backends_first SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1024);  
    __type(key, __u32);         
    __type(value, struct backend);
} backends_second SEC(".maps");


// ======================== BALANCER ALGORITHMS DATA ============================

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);  
    __type(key, struct service_key);
    __type(value,__u32);
} rr_index SEC(".maps");

// WRR Balancing Algorithm
struct wrr_state {
    __u32 current_index;
    __u32 current_weight_counter;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct service_key);
    __type(value, struct wrr_state);
} wrr_state_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65537);
    __type(key, __u32);
    __type(value, __s32);
} ch_curr_lookup SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65537);
    __type(key, __u32);
    __type(value, __s32);
} ch_prev_lookup SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 257);
    __type(key, __u32);
    __type(value, struct backend);
} ch_backends SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} ch_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} ch_merge_control SEC(".maps");

struct ch_stats_data {
    __u64 total_lookups;
    __u64 stable_lookups;
    __u64 unstable_lookups;
    __u64 merge_count;
    __u64 update_count;
    __u64 last_update_time;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ch_stats_data);
} ch_stats_map SEC(".maps");

// =================== TCP Session State (lives 1 minute) ======================
struct session_state_key {
    union {
        __u32 src_ipv4;
        __u8 src_ipv6[16];
    };
    union {
        __u32 dst_ipv4;
        __u8 dst_ipv6[16];
    };     
    __u16 src_port;              
    __u16 dst_port; 
};

struct session_state_val {
    __u32 backend_idx;
    __u32 service_idx;   // cached for single-lookup stats update
    __u64 created;
    __u64 timeout;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);  
    __type(key, struct session_state_key);
    __type(value, struct session_state_val);
} tcp_session_state SEC(".maps");


// =================== STATISTICS DATA ========================
struct summary_packets_data {
    __u64 total_packets;
    __u64 tcp_syn_packets;
    __u64 prepared_packets;
    __s32 connections; // signed: SYN/FIN may land on different CPUs, must cancel correctly
    __u32 _pad;
    __u64 total_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1024);  
    __type(key, __u32);         
    __type(value, struct summary_packets_data);
} backends_packets_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct summary_packets_data);
} services_packets_stats SEC(".maps");


// ================== DDOS PROTECTION STRUCTURES ===============

struct syn_counter {
    __u64 syn_count;         
    __u64 ack_count;         
    __u64 window_start; // timestamp of packets' count beginning 
    __u64 total_packets;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);                    // source IPv4
    __type(value, struct syn_counter);
} syn_tracker SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);                    // source IPv4
    __type(value, __u64);                  // timestamp has been blocked
} blacklist SEC(".maps");


struct ddos_config {
    __u32 syn_threshold;       // max of syn packets by windows
    __u32 syn_ack_ratio;       
    __u32 global_syn_threshold; // global SYN per second for VIP
    __u64 ban_duration_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ddos_config);
} ddos_cfg SEC(".maps");

struct global_syn_stats {
    __u64 syn_count;    // windowed counter (resets every DDOS_WINDOW_NS)
    __u64 window_start;
    __u64 dropped_total; // cumulative dropped packets (never resets)
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_syn_stats);
} global_syn SEC(".maps");


// =================== CHECKSUM HELPERS ========================

static __always_inline __u16 csum_fold(__u32 sum) {
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (__u16)~sum;
}

static __always_inline __u16 csum_replace16(__u16 check, __u16 old_val, __u16 new_val) {
    __u32 c = (~check & 0xffff) + (~old_val & 0xffff) + new_val;
    c = (c >> 16) + (c & 0xffff);
    return (__u16)~c;
}

static __always_inline __u16 csum_replace32(__u16 check, __u32 old_val, __u32 new_val) {
    __u32 c = (~check & 0xffff);
    c += (~old_val >> 16) + (~old_val & 0xffff);
    c += (new_val >> 16) + (new_val & 0xffff);
    c = (c >> 16) + (c & 0xffff);
    c += (c >> 16);
    return (__u16)~c;
}

static __always_inline __u16 csum_replace_ipv6(__u16 check,
                                                const __u8 *old_addr,
                                                const __u8 *new_addr) {
    __u32 o, n;
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        __builtin_memcpy(&o, old_addr + i * 4, 4);
        __builtin_memcpy(&n, new_addr + i * 4, 4);
        check = csum_replace32(check, o, n);
    }
    return check;
}

static __always_inline __u16 ip_checksum(struct iphdr *ip) {
    __u32 sum = 0;
    __u16 *ptr = (__u16 *)ip;
    
    #pragma unroll
    for (int i = 0; i < sizeof(struct iphdr) / 2; i++) {
        sum += ptr[i];
    }
    
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

static __always_inline void update_tcp_checksum_v4(
    struct tcphdr *tcph,
    __u32 old_daddr, __u32 new_daddr,
    __u16 old_dport, __u16 new_dport)
{
    tcph->check = csum_replace32(tcph->check, old_daddr, new_daddr);
    tcph->check = csum_replace16(tcph->check, old_dport, new_dport);
}

static __always_inline void update_tcp_checksum_v6(
    struct tcphdr *tcph,
    const __u8 *old_daddr, const __u8 *new_daddr,
    __u16 old_dport, __u16 new_dport)
{
    tcph->check = csum_replace_ipv6(tcph->check, old_daddr, new_daddr);
    tcph->check = csum_replace16(tcph->check, old_dport, new_dport);
}

static __always_inline void update_udp_checksum_v4(
    struct udphdr *udph,
    __u32 old_daddr, __u32 new_daddr,
    __u16 old_dport, __u16 new_dport)
{
    if (udph->check == 0) return;
    udph->check = csum_replace32(udph->check, old_daddr, new_daddr);
    udph->check = csum_replace16(udph->check, old_dport, new_dport);
    if (udph->check == 0) udph->check = 0xFFFF;
}

static __always_inline void update_udp_checksum_v6(
    struct udphdr *udph,
    const __u8 *old_daddr, const __u8 *new_daddr,
    __u16 old_dport, __u16 new_dport)
{
    udph->check = csum_replace_ipv6(udph->check, old_daddr, new_daddr);
    udph->check = csum_replace16(udph->check, old_dport, new_dport);
    if (udph->check == 0) udph->check = 0xFFFF;
}


// ======================== CH FUNCTION HELPERS =============================
static __always_inline __u32 hash_key_consistent(__u32 key, __u32 seed) {
    __u32 hash = seed;
    hash ^= key;
    hash *= 0x9e3779b9;
    hash = (hash << 13) | (hash >> 19);
    hash ^= (hash >> 17);
    hash *= 0x85ebca6b;
    return hash;
}

static __always_inline __s32 consistent_hash_lookup(__u32 key_hash, bool use_prev) {
    __u32 config_key = 0;
    __u32* hashring_size = (__u32*)bpf_map_lookup_elem(&ch_config, &config_key);
    if (!hashring_size || *hashring_size == 0)
        return -1;
    
    __u32 index = key_hash % *hashring_size;
    __s32* backend_idx;
    
    if (use_prev)
        backend_idx = (__s32*)bpf_map_lookup_elem(&ch_prev_lookup, &index);
    else
        backend_idx = (__s32*)bpf_map_lookup_elem(&ch_curr_lookup, &index);
    
    if (!backend_idx || *backend_idx < 0)
        return -1;
    
    __u32 stats_key = 0;
    struct ch_stats_data* stats = (struct ch_stats_data*)bpf_map_lookup_elem(&ch_stats_map, &stats_key);
    if (stats) {
        stats->total_lookups++;
        if (!use_prev) {
            __s32* prev_idx = (__s32*)bpf_map_lookup_elem(&ch_prev_lookup, &index);
            if (prev_idx && *prev_idx == *backend_idx)
                stats->stable_lookups++;
            else
                stats->unstable_lookups++;
        }
    }
    
    return *backend_idx;
}

static __always_inline bool consistent_hash_is_stable(__u32 key_hash) {
    __u32 config_key = 0;
    __u32* hashring_size = (__u32*)bpf_map_lookup_elem(&ch_config, &config_key);
    if (!hashring_size || *hashring_size == 0)
        return true;
    
    __u32 index = key_hash % *hashring_size;
    __s32* curr = (__s32*)bpf_map_lookup_elem(&ch_curr_lookup, &index);
    __s32* prev = (__s32*)bpf_map_lookup_elem(&ch_prev_lookup, &index);
    
    if (!curr || !prev)
        return true;
    
    return *curr == *prev;
}

static __always_inline struct backend *ch_balancer_handle(
    struct service_key *key, 
    __u32 key_hash,
    __u32 packet_len,
    __u32 *last_index) 
{
    __s32 backend_idx = consistent_hash_lookup(key_hash, false);
    if (backend_idx < 0)
        return (struct backend *)0;
    
    __u32 bid = (__u32)backend_idx;
    struct backend *backend = (struct backend *)bpf_map_lookup_elem(&ch_backends, &bid);
    if (!backend || !backend->active)
        return (struct backend *)0;
    
    if (last_index)
        *last_index = bid;
    
    struct summary_packets_data *pkts_stats = 
        (struct summary_packets_data *)bpf_map_lookup_elem(&backends_packets_stats, &bid);
    if(pkts_stats) {
        pkts_stats->total_packets++;
        pkts_stats->prepared_packets++;
        pkts_stats->total_bytes += packet_len;
    }
    
    struct summary_packets_data *service_pkts_stats = 
        (struct summary_packets_data *)bpf_map_lookup_elem(&services_packets_stats, key);
    if(service_pkts_stats) {
        service_pkts_stats->total_packets++;
        service_pkts_stats->prepared_packets++;
        service_pkts_stats->total_bytes += packet_len;
    }
    
    return backend;
}

// ======================== BALANCER ALGORITHM HANDLERS =============================

static __always_inline struct backend *rr_balancer_handle(void *current_back_map, 
                                                            struct service_info *info, 
                                                            struct service_key *key, 
                                                            __u32 *last_index) 
{
    __u32 *current_index = (__u32 *)bpf_map_lookup_elem(&rr_index, key);
    if(current_index) {
        __u32 new_index = *current_index + 1;
        if(new_index >= info->backend_count)
            new_index = 0;
        __u32 backend_search_index = info->backend_start_idx + new_index;
        struct backend *back = (struct backend *)bpf_map_lookup_elem(current_back_map, &backend_search_index);
        bpf_map_update_elem(&rr_index, key, &new_index, BPF_ANY);
        *last_index = backend_search_index;
        return back;
    } else {
        return (struct backend *)0;
    }
}

static __always_inline struct backend *wrr_balancer_handle(void *current_back_map, 
                                                            struct service_info *info, 
                                                            struct service_key *key, 
                                                            __u32 *last_index) 
{
    struct wrr_state *state = (struct wrr_state *)bpf_map_lookup_elem(&wrr_state_map, key);
    if (!state) {
        struct wrr_state new_state = {
            .current_index = 0,
            .current_weight_counter = 0
        };
        bpf_map_update_elem(&wrr_state_map, key, &new_state, BPF_ANY);
        state = (struct wrr_state *)bpf_map_lookup_elem(&wrr_state_map, key);
        if (!state)
            return (struct backend *)0;
    }
    
    for (int attempts = 0; attempts < 32; attempts++) {
        if (attempts >= (int)(info->backend_count * 2))
            break;
        __u32 idx = info->backend_start_idx + state->current_index;
        struct backend *back = (struct backend *)bpf_map_lookup_elem(current_back_map, &idx);

        if (back && back->active && back->weight > 0) {
            state->current_weight_counter++;
            if (state->current_weight_counter < back->weight) {
                *last_index = idx;
                bpf_map_update_elem(&wrr_state_map, key, state, BPF_ANY);
                return back;
            } else {
                *last_index = idx;
                state->current_index = (state->current_index + 1) % info->backend_count;
                state->current_weight_counter = 0;
                bpf_map_update_elem(&wrr_state_map, key, state, BPF_ANY);
                return back;
            }
        }

        state->current_index = (state->current_index + 1) % info->backend_count;
        state->current_weight_counter = 0;
    }
    
    return (struct backend *)0;
}


// ======================== BACKEND LOOKUP (TCP) =============================

static __always_inline struct backend *find_tcp_backend(struct session_state_key *state_key,
                                                        struct service_key *key,
                                                        struct tcphdr *tcp,
                                                        __u32 packet_len)
{
    __u32 last_backend_index = 0;
    __u32 service_idx_for_stats = 0;
    __s32 conn_delta = 0;
    struct session_state_val *state_backend = (struct session_state_val *)0;
    struct backend *backend = (struct backend *)0;
    __u32 atomic_key = 0;
    __u64 *curr_index = (__u64 *)bpf_map_lookup_elem(&atomic_index, &atomic_key);
    if (!curr_index) {
        bpf_printk("xdp: invalid index for services\n");
        return (struct backend *)0;
    }

    void *services_map = (*curr_index == 0) ? (void *)&services_first : (void *)&services_second;
    void *backends_map = (*curr_index == 0) ? (void *)&backends_first : (void *)&backends_second;

    // check firstly in session state map (not only TCP SYN)
    if (!(tcp->syn && !tcp->ack)) {
        state_backend = (struct session_state_val *)bpf_map_lookup_elem(&tcp_session_state, state_key);
        if (state_backend) {
            __u64 now = bpf_ktime_get_ns();
            if (now - state_backend->created > state_backend->timeout) {
                // Session timed out: connections-- for old backend/service (separate lookups,
                // different index than the new backend that will be selected below)
                bpf_map_delete_elem(&tcp_session_state, state_key);
                struct summary_packets_data *p =
                    (struct summary_packets_data *)bpf_map_lookup_elem(&backends_packets_stats, &state_backend->backend_idx);
                if (p) p->connections--;
                __u32 old_svc = state_backend->service_idx;
                struct summary_packets_data *s =
                    (struct summary_packets_data *)bpf_map_lookup_elem(&services_packets_stats, &old_svc);
                if (s) s->connections--;
                state_backend = (struct session_state_val *)0;
            } else {
                state_backend->created = now;
                backend = (struct backend *)bpf_map_lookup_elem(backends_map, &state_backend->backend_idx);
                last_backend_index = state_backend->backend_idx;
                service_idx_for_stats = state_backend->service_idx;
            }
        }
    }

    if (!backend) {
        struct service_info *info = (struct service_info *)bpf_map_lookup_elem(services_map, key);
        __u32 attempts = 0;
        if (info) {
            switch (info->algorithm) {
                case BALANCER_RR:
                    do {
                        backend = rr_balancer_handle(backends_map, info, key, &last_backend_index);
                        if (++attempts > 4) { backend = (struct backend *)0; break; }
                    } while (backend && !(backend->active));
                    break;
                case BALANCER_WRR:
                    do {
                        backend = wrr_balancer_handle(backends_map, info, key, &last_backend_index);
                        if (++attempts > 4) { backend = (struct backend *)0; break; }
                    } while (backend && !(backend->active));
                    break;
                case BALANCER_CH:
                    {
                        __u32 ch_hash = hash_key_consistent(
                            state_key->src_ipv4 ^ state_key->dst_ipv4 ^
                            ((__u32)state_key->src_port << 16) ^ (__u32)state_key->dst_port,
                            0x5737a28c);
                        backend = ch_balancer_handle(key, ch_hash, packet_len, &last_backend_index);
                    }
                    break;
                default:
                    return (struct backend *)0;
            }

            if (!backend)
                return (struct backend *)0;

            service_idx_for_stats = info->service_idx;

            struct session_state_val new_state;
            new_state.backend_idx = last_backend_index;
            new_state.service_idx = info->service_idx;
            new_state.created = bpf_ktime_get_ns();
            new_state.timeout = TCP_STATE_TIMEOUT;
            bpf_map_update_elem(&tcp_session_state, state_key, &new_state, BPF_ANY);
            conn_delta = 1;
        } else {
            return (struct backend *)0;
        }
    }

    // FIN/RST — mark connection closing (single delete, no extra stats lookup)
    if (state_backend && (tcp->fin || tcp->rst)) {
        bpf_map_delete_elem(&tcp_session_state, state_key);
        conn_delta = -1;
    }

    // Single lookup per stats map for all updates
    struct summary_packets_data *pkts_stats =
        (struct summary_packets_data *)bpf_map_lookup_elem(&backends_packets_stats, &last_backend_index);
    if (pkts_stats) {
        pkts_stats->connections += conn_delta;
        pkts_stats->total_packets++;
        if (tcp->syn)
            pkts_stats->tcp_syn_packets++;
        pkts_stats->prepared_packets++;
        pkts_stats->total_bytes += packet_len;
    }
    struct summary_packets_data *svc_stats =
        (struct summary_packets_data *)bpf_map_lookup_elem(&services_packets_stats, &service_idx_for_stats);
    if (svc_stats) {
        svc_stats->connections += conn_delta;
        svc_stats->total_packets++;
        if (tcp->syn)
            svc_stats->tcp_syn_packets++;
        svc_stats->prepared_packets++;
    }

    return backend;
}


static __always_inline struct backend *find_udp_backend(struct service_key *key, __u32 packet_len) 
{
    struct backend *backend = (struct backend *)0;
    __u32 atomic_key = 0;
    __u64 *curr_index = (__u64 *)bpf_map_lookup_elem(&atomic_index, &atomic_key);
    if(!curr_index)
        return (struct backend *)0;

    void *services_map = (*curr_index == 0) ? (void *)&services_first : (void *)&services_second;
    void *backends_map = (*curr_index == 0) ? (void *)&backends_first : (void *)&backends_second;

    struct service_info *info = (struct service_info *)bpf_map_lookup_elem(services_map, key);
    __u32 last_backend_index;
    __u32 attempts = 0;
    if(info) {
        switch (info->algorithm) {
            case BALANCER_RR:
                do {
                    backend = rr_balancer_handle(backends_map, info, key, &last_backend_index);
                    if (++attempts > 4) { backend = (struct backend *)0; break; }
                } while(backend && !(backend->active));
                break;
            case BALANCER_WRR:
                do {
                    backend = wrr_balancer_handle(backends_map, info, key, &last_backend_index);
                    if (++attempts > 4) { backend = (struct backend *)0; break; }
                } while(backend && !(backend->active));
                break;
            default:
                return (struct backend *)0;
        }
        if(!backend)
            return (struct backend *)0;
    } else {
        return (struct backend *)0;
    }

    struct summary_packets_data *pkts_stats = 
        (struct summary_packets_data *)bpf_map_lookup_elem(&backends_packets_stats, &last_backend_index);
    if(pkts_stats) {
        pkts_stats->total_packets++;
        pkts_stats->prepared_packets++;
        pkts_stats->total_bytes += packet_len;
    }
    __u32 udp_svc_idx = info->service_idx;
    struct summary_packets_data *service_pkts_stats =
                    (struct summary_packets_data *)bpf_map_lookup_elem(&services_packets_stats, &udp_svc_idx);
    if(service_pkts_stats) {
        service_pkts_stats->total_packets++;
        service_pkts_stats->prepared_packets++;
        service_pkts_stats->total_bytes += packet_len;
    }

    return backend;
}

static __always_inline __u8 tcp_balancer_handle_v4(struct ethhdr *l2_header, 
                                                    struct iphdr *ip_header, 
                                                    struct tcphdr *tcp_header, 
                                                    void *data_end) 
{
    __u32 dst_ip = ip_header->daddr;
    __u16 dst_port = bpf_ntohs(tcp_header->dest);
    struct service_key key;
    __builtin_memset(&key, 0, sizeof(key));
    key.port = dst_port;
    key.vip4 = dst_ip;
    key.protocol = IPPROTO_TCP;
    key.ip_version = 4;

    struct session_state_key state_key;
    __builtin_memset(&state_key, 0, sizeof(state_key));
    state_key.src_ipv4 = ip_header->saddr;
    state_key.dst_ipv4 = ip_header->daddr;
    state_key.src_port = tcp_header->source;
    state_key.dst_port = tcp_header->dest;

    __u32 packet_len = (__u32)(((__u8 *)data_end) - ((__u8 *)l2_header));
    struct backend *backend = find_tcp_backend(&state_key, &key, tcp_header, packet_len);
    if(!backend)
        return 3;

    /* L2 DSR: only rewrite dst_MAC → backend MAC; all IP/TCP headers stay unchanged.
     * Backend must have VIP on lo and must not ARP-respond for VIP on eth0. */
    __u8 my_mac[6];
    __builtin_memcpy(my_mac, l2_header->h_dest, 6);
    __builtin_memcpy(l2_header->h_dest, backend->mac, 6);
    __builtin_memcpy(l2_header->h_source, my_mac, 6);

    return 0;
}


static __always_inline int udp_balancer_handle_v4(struct ethhdr *l2_header,
                                                    struct iphdr *ip_header,
                                                    struct udphdr *udp_header,
                                                    void *data_end)
{
    __u32 dst_ip = ip_header->daddr;
    __u16 dst_port = bpf_ntohs(udp_header->dest);
    struct service_key key;
    __builtin_memset(&key, 0, sizeof(key));
    key.port = dst_port;
    key.vip4 = dst_ip;
    key.protocol = IPPROTO_UDP;
    key.ip_version = 4;

    __u32 packet_len = (__u32)(((__u8 *)data_end) - ((__u8 *)l2_header));
    struct backend *backend = find_udp_backend(&key, packet_len);
    if(!backend)
        return 3;

    /* L2 DSR: only rewrite dst_MAC → backend MAC. */
    __u8 my_mac[6];
    __builtin_memcpy(my_mac, l2_header->h_dest, 6);
    __builtin_memcpy(l2_header->h_dest, backend->mac, 6);
    __builtin_memcpy(l2_header->h_source, my_mac, 6);

    return 0;
}


static __always_inline __u8 tcp_balancer_handle_v6(struct ethhdr *l2_header, 
                                                    struct ipv6hdr *ip_header, 
                                                    struct tcphdr *tcp_header, 
                                                    void *data_end) 
{
    __u16 dst_port = bpf_ntohs(tcp_header->dest);
    struct service_key key;
    __builtin_memset(&key, 0, sizeof(key));
    key.port = dst_port;
    __builtin_memcpy(key.vip6, &ip_header->daddr, 16);
    key.protocol = IPPROTO_TCP;
    key.ip_version = 6;

    struct session_state_key state_key;
    __builtin_memset(&state_key, 0, sizeof(state_key));
    __builtin_memcpy(state_key.src_ipv6, &ip_header->saddr, 16);
    __builtin_memcpy(state_key.dst_ipv6, &ip_header->daddr, 16);
    state_key.src_port = tcp_header->source;
    state_key.dst_port = tcp_header->dest;

    __u32 packet_len = (__u32)(((__u8 *)data_end) - ((__u8 *)l2_header));
    struct backend *backend = find_tcp_backend(&state_key, &key, tcp_header, packet_len);
    if(!backend)
        return 3;

    __u8 old_daddr6[16];
    __builtin_memcpy(old_daddr6, &ip_header->daddr, 16);
    __u16 old_dport6 = tcp_header->dest;

    __u8 my_mac[6];
    __builtin_memcpy(my_mac, l2_header->h_dest, 6);

    __builtin_memcpy(l2_header->h_dest, backend->mac, 6);
    __builtin_memcpy(l2_header->h_source, my_mac, 6);
    __builtin_memcpy(&ip_header->daddr, backend->ipv6, 16);
    tcp_header->dest = bpf_htons(backend->port);

    update_tcp_checksum_v6(tcp_header, old_daddr6, (__u8 *)&ip_header->daddr, old_dport6, tcp_header->dest);
    return 0;
}


static __always_inline int udp_balancer_handle_v6(struct ethhdr *l2_header,
                                                    struct ipv6hdr *ip_header,
                                                    struct udphdr *udp_header,
                                                    void *data_end)
{
    __u16 dst_port = bpf_ntohs(udp_header->dest);
    struct service_key key;
    __builtin_memset(&key, 0, sizeof(key));
    key.port = dst_port;
    __builtin_memcpy(key.vip6, &ip_header->daddr, 16);
    key.protocol = IPPROTO_UDP;
    key.ip_version = 6;

    __u32 packet_len = (__u32)(((__u8 *)data_end) - ((__u8 *)l2_header));
    struct backend *backend = find_udp_backend(&key, packet_len);
    if(!backend)
        return 3;

    __u8 old_daddr6[16];
    __builtin_memcpy(old_daddr6, &ip_header->daddr, 16);
    __u16 old_dport6 = udp_header->dest;

    __u8 my_mac[6];
    __builtin_memcpy(my_mac, l2_header->h_dest, 6);

    __builtin_memcpy(l2_header->h_dest, backend->mac, 6);
    __builtin_memcpy(l2_header->h_source, my_mac, 6);
    __builtin_memcpy(&ip_header->daddr, backend->ipv6, 16);
    udp_header->dest = bpf_htons(backend->port);

    update_udp_checksum_v6(udp_header, old_daddr6, (__u8 *)&ip_header->daddr, old_dport6, udp_header->dest);
    return 0;
}

// ===================== DDoS Protection Functions =========================
static __always_inline int ddos_check_v4(struct iphdr *ip, struct tcphdr *tcp)
{
    __u32 src_ip = ip->saddr;
    __u64 now = bpf_ktime_get_ns();

    __u32 cfg_key = 0;
    struct ddos_config *cfg = (struct ddos_config *)bpf_map_lookup_elem(&ddos_cfg, &cfg_key);
    __u64 *ban_time = (__u64*)bpf_map_lookup_elem(&blacklist, &src_ip);
    
    if (ban_time) {
        __u64 duration = cfg ? cfg->ban_duration_ns : 300000000000ULL;
        if (now - *ban_time < duration) {
            return XDP_DROP;
        }
        bpf_map_delete_elem(&blacklist, &src_ip);
    }

    struct syn_counter *cnt = (struct syn_counter *)bpf_map_lookup_elem(&syn_tracker, &src_ip);
    if (!cnt) {
        struct syn_counter new_cnt = {
            .syn_count = 0,
            .ack_count = 0,
            .window_start = now,
            .total_packets = 0
        };
        bpf_map_update_elem(&syn_tracker, &src_ip, &new_cnt, BPF_ANY);
        cnt = (struct syn_counter *)bpf_map_lookup_elem(&syn_tracker, &src_ip);
        if (!cnt)
            return XDP_PASS;
    }

    if (now - cnt->window_start > DDOS_WINDOW_NS) {
        cnt->syn_count = 0;
        cnt->ack_count = 0;
        cnt->total_packets = 0;
        cnt->window_start = now;
    }

    cnt->total_packets++;

    if (tcp->syn && !tcp->ack) { // pure TCP SYN
        cnt->syn_count++;

        __u32 gkey = 0;
        struct global_syn_stats *gs = (struct global_syn_stats *)bpf_map_lookup_elem(&global_syn, &gkey);
        if (gs) {
            if (now - gs->window_start > DDOS_WINDOW_NS) {
                gs->syn_count = 0;
                gs->window_start = now;
            }
            gs->syn_count++;

            // global SYN flood: drop immediately without per-IP ban
            if (cfg && cfg->global_syn_threshold > 0 &&
                gs->syn_count > cfg->global_syn_threshold) {
                gs->dropped_total++;
                return XDP_DROP;
            }
        }
    }

    if (tcp->ack && !tcp->syn) {
        cnt->ack_count++;
    }

    if (!cfg)
        return XDP_PASS; // empty config == bypass

    if (cfg->syn_threshold > 0 && cnt->syn_count > cfg->syn_threshold) {
        bpf_printk("xdp/ddos: BLOCKED ip=%x syn=%llu > threshold=%u",
                   bpf_ntohl(src_ip), cnt->syn_count, cfg->syn_threshold);
        __u64 ban_ts = now;
        bpf_map_update_elem(&blacklist, &src_ip, &ban_ts, BPF_ANY);
        __u32 gkey = 0;
        struct global_syn_stats *gs_drop = (struct global_syn_stats *)bpf_map_lookup_elem(&global_syn, &gkey);
        if (gs_drop)
            gs_drop->dropped_total++;
        return XDP_DROP;
    }

    if (cfg->syn_ack_ratio > 0 && cnt->syn_count > 10) {
        // syn_ack_ratio = 500 ==  5 SYN on 1 ACK
        __u64 ack = cnt->ack_count > 0 ? cnt->ack_count : 1;
        __u64 ratio = (cnt->syn_count * 100) / ack;
        if (ratio > cfg->syn_ack_ratio) {
            bpf_printk("xdp/ddos: BLOCKED ip=%x syn/ack ratio=%llu > %u",
                       bpf_ntohl(src_ip), ratio, cfg->syn_ack_ratio);
            __u64 ban_ts = now;
            bpf_map_update_elem(&blacklist, &src_ip, &ban_ts, BPF_ANY);
            __u32 gkey = 0;
            struct global_syn_stats *gs_drop = (struct global_syn_stats *)bpf_map_lookup_elem(&global_syn, &gkey);
            if (gs_drop)
                gs_drop->dropped_total++;
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}


SEC("xdp")
int balancer_handler(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (struct iphdr *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        __u8 ip_header_len = ip->ihl * 4;
        if (ip_header_len < sizeof(struct iphdr))
            return XDP_PASS;
        
        if ((__u8 *)ip + ip_header_len > (__u8 *)data_end)
            return XDP_PASS;

        void *transport_header = (__u8 *)ip + ip_header_len;
        
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)transport_header;
            if ((void *)(tcp + 1) > data_end)
                return XDP_PASS;

            // Check on DDoS Attack
            if(!(tcp->syn && !tcp->ack)) {
                int ddos_verdict = ddos_check_v4(ip, tcp);
                if (ddos_verdict == XDP_DROP)
                    return XDP_DROP;
            }


            __u8 result = tcp_balancer_handle_v4(eth, ip, tcp, data_end);
            if(result > 0)
                return XDP_PASS;
            return XDP_TX;
           
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)transport_header;
            if ((void *)(udp + 1) > data_end)
                return XDP_PASS;

            __u8 result = udp_balancer_handle_v4(eth, ip, udp, data_end);
            if(result > 0)
                return XDP_PASS;
            return XDP_TX;
        }
        return XDP_PASS;

    } else if(eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (struct ipv6hdr *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;
        
        __u8 nexthdr = ip6->nexthdr;
        void *transport = (void *)(ip6 + 1);
        
        if (nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)transport;
            if ((void *)(tcp + 1) > data_end)
                return XDP_PASS;

            __u8 result = tcp_balancer_handle_v6(eth, ip6, tcp, data_end);
            if(result > 0)
                return XDP_PASS;
            return XDP_TX;
           
        } else if (nexthdr == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)transport;
            if ((void *)(udp + 1) > data_end)
                return XDP_PASS;
            
            __u8 result = udp_balancer_handle_v6(eth, ip6, udp, data_end);
            if(result > 0)
                return XDP_PASS;
            return XDP_TX;
        }
        return XDP_PASS;
    }
    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";