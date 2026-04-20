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

// ===== Reverse NAT (for return traffic: backend → balancer) =====
struct reverse_nat_key {
    __u32 src_ip;    // backend IP (who sends the reply)
    __u32 dst_ip;    // balancer IP (reply comes to us)
    __u16 src_port;  // backend port — network byte order
    __u16 dst_port;  // client ephemeral port — network byte order
};

struct reverse_nat_val {
    __u32 client_ip;    // original client IP to restore in dst
    __u32 vip;          // original VIP to restore in src
    __u16 vip_port;     // original VIP port — network byte order
    __u8  client_mac[6]; // client MAC for L2 rewrite
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct reverse_nat_key);
    __type(value, struct reverse_nat_val);
} reverse_nat SEC(".maps");

struct lb_config_val {
    __u32 ipv4;
    __u8  mac[6];
    __u8  _pad[2];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct lb_config_val);
} lb_config SEC(".maps");

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
    __u8 algorithm;          
    __u8 _pad[3];
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
    __u32 connections;
    __u64 total_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1024);  
    __type(key, __u32);         
    __type(value, struct summary_packets_data);
} backends_packets_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 256);  
    __type(key, struct service_key);         
    __type(value, struct summary_packets_data);
} services_packets_stats SEC(".maps");


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
    __u32* hashring_size = bpf_map_lookup_elem(&ch_config, &config_key);
    if (!hashring_size || *hashring_size == 0)
        return -1;
    
    __u32 index = key_hash % *hashring_size;
    __s32* backend_idx;
    
    if (use_prev)
        backend_idx = bpf_map_lookup_elem(&ch_prev_lookup, &index);
    else
        backend_idx = bpf_map_lookup_elem(&ch_curr_lookup, &index);
    
    if (!backend_idx || *backend_idx < 0)
        return -1;
    
    __u32 stats_key = 0;
    struct ch_stats_data* stats = bpf_map_lookup_elem(&ch_stats_map, &stats_key);
    if (stats) {
        stats->total_lookups++;
        if (!use_prev) {
            __s32* prev_idx = bpf_map_lookup_elem(&ch_prev_lookup, &index);
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
    __u32* hashring_size = bpf_map_lookup_elem(&ch_config, &config_key);
    if (!hashring_size || *hashring_size == 0)
        return true;
    
    __u32 index = key_hash % *hashring_size;
    __s32* curr = bpf_map_lookup_elem(&ch_curr_lookup, &index);
    __s32* prev = bpf_map_lookup_elem(&ch_prev_lookup, &index);
    
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
        return NULL;
    
    __u32 bid = (__u32)backend_idx;
    struct backend *backend = bpf_map_lookup_elem(&ch_backends, &bid);
    if (!backend || !backend->active)
        return NULL;
    
    if (last_index)
        *last_index = bid;
    
    struct summary_packets_data *pkts_stats = 
        bpf_map_lookup_elem(&backends_packets_stats, &bid);
    if(pkts_stats) {
        pkts_stats->total_packets++;
        pkts_stats->prepared_packets++;
        pkts_stats->total_bytes += packet_len;
    }
    
    struct summary_packets_data *service_pkts_stats = 
        bpf_map_lookup_elem(&services_packets_stats, key);
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
    struct session_state_val *state_backend = (struct session_state_val *)0;
    struct backend *backend = (struct backend *)0;
    __u32 atomic_key = 0;
    __u64 *curr_index = (__u64 *)bpf_map_lookup_elem(&atomic_index, &atomic_key);
    if(!curr_index) {
        bpf_printk("xdp: invalid index for services\n");
        return (struct backend *)0;
    }

    void *services_map = 0;
    void *backends_map = 0;
    if(*curr_index == 0) {
        services_map = (void *)&services_first;
        backends_map = (void *)&backends_first;
    } else {
        services_map = (void *)&services_second;
        backends_map = (void *)&backends_second;
    }

    // check firstly in session state map (not only TCP SYN)
    if(!(tcp->syn && !tcp->ack)) {
        state_backend = (struct session_state_val *)bpf_map_lookup_elem(&tcp_session_state, state_key);
        if(state_backend) {
            __u64 now = bpf_ktime_get_ns();
            if (now - state_backend->created > state_backend->timeout) {
                bpf_map_delete_elem(&tcp_session_state, state_key);
                struct summary_packets_data *pkts_stats =
                    (struct summary_packets_data *)bpf_map_lookup_elem(&backends_packets_stats, &state_backend->backend_idx);
                if(pkts_stats)
                    pkts_stats->connections--;
                struct summary_packets_data *service_pkts_stats =
                    (struct summary_packets_data *)bpf_map_lookup_elem(&services_packets_stats, key);
                if(service_pkts_stats)
                    service_pkts_stats->connections--;
            } else {
                state_backend->created = now;
                backend = (struct backend *)bpf_map_lookup_elem(backends_map, &state_backend->backend_idx);
                last_backend_index = state_backend->backend_idx;
            }
        }
    }

    if(!backend) {
        struct service_info *info = (struct service_info *)bpf_map_lookup_elem(services_map, key);
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

            if(!backend)
                return (struct backend *)0;
        } else {
            return (struct backend *)0;
        }

        // new session
        struct session_state_val new_state;
        new_state.backend_idx = last_backend_index;
        new_state.created = bpf_ktime_get_ns();
        new_state.timeout = TCP_STATE_TIMEOUT;

        struct summary_packets_data *pkts_stats = (struct summary_packets_data *)bpf_map_lookup_elem(&backends_packets_stats, &last_backend_index);
        if(pkts_stats)
            pkts_stats->connections++;
        struct summary_packets_data *service_pkts_stats =
                    (struct summary_packets_data *)bpf_map_lookup_elem(&services_packets_stats, key);
        if(service_pkts_stats)
            service_pkts_stats->connections++;

        bpf_map_update_elem(&tcp_session_state, state_key, &new_state, BPF_ANY);
    }

    // FIN/RST — delete session
    if(state_backend && (tcp->fin || tcp->rst)) {
        bpf_map_delete_elem(&tcp_session_state, state_key);
        struct summary_packets_data *pkts_stats = 
            (struct summary_packets_data *)bpf_map_lookup_elem(&backends_packets_stats, &state_backend->backend_idx);
        if(pkts_stats)
            pkts_stats->connections--;
        struct summary_packets_data *service_pkts_stats =
                    (struct summary_packets_data *)bpf_map_lookup_elem(&services_packets_stats, key);
        if(service_pkts_stats)
            service_pkts_stats->connections--;
    }

    // stats
    struct summary_packets_data *pkts_stats =
        (struct summary_packets_data *)bpf_map_lookup_elem(&backends_packets_stats, &last_backend_index);
    if(pkts_stats) {
        pkts_stats->total_packets++;
        if(tcp->syn)
            pkts_stats->tcp_syn_packets++;
        pkts_stats->prepared_packets++;
        pkts_stats->total_bytes += packet_len;
    }
    struct summary_packets_data *service_pkts_stats =
                    (struct summary_packets_data *)bpf_map_lookup_elem(&services_packets_stats, key);
    if(service_pkts_stats) {
        service_pkts_stats->total_packets++;
        if(tcp->syn)
            service_pkts_stats->tcp_syn_packets++;
        service_pkts_stats->prepared_packets++;
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
    struct summary_packets_data *service_pkts_stats =
                    (struct summary_packets_data *)bpf_map_lookup_elem(&services_packets_stats, key);
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

    // Get balancer's own IP for full NAT
    __u32 cfg_key = 0;
    struct lb_config_val *cfg = bpf_map_lookup_elem(&lb_config, &cfg_key);
    if (!cfg || cfg->ipv4 == 0)
        return 3;

    __u32 old_saddr = ip_header->saddr;
    __u32 old_daddr = ip_header->daddr;
    __u16 old_dport = tcp_header->dest;

    __u8 client_mac[6];
    __builtin_memcpy(client_mac, l2_header->h_source, 6);

    __u8 my_mac[6];
    __builtin_memcpy(my_mac, l2_header->h_dest, 6);

    __builtin_memcpy(l2_header->h_dest, backend->mac, 6);
    __builtin_memcpy(l2_header->h_source, my_mac, 6);

    ip_header->saddr = cfg->ipv4;       // src: client → balancer
    ip_header->daddr = backend->ipv4;   // dst: VIP → backend
    tcp_header->dest = bpf_htons(backend->port);

    ip_header->check = 0;
    ip_header->check = ip_checksum(ip_header);
    tcp_header->check = csum_replace32(tcp_header->check, old_saddr, ip_header->saddr);
    tcp_header->check = csum_replace32(tcp_header->check, old_daddr, ip_header->daddr);
    tcp_header->check = csum_replace16(tcp_header->check, old_dport, tcp_header->dest);

    struct reverse_nat_key rkey;
    __builtin_memset(&rkey, 0, sizeof(rkey));
    rkey.src_ip   = backend->ipv4;          // backend replies from this
    rkey.dst_ip   = cfg->ipv4;              // to balancer (our IP)
    rkey.src_port = bpf_htons(backend->port); // from backend port
    rkey.dst_port = tcp_header->source;     // to client's ephemeral port (unchanged)

    struct reverse_nat_val rval;
    __builtin_memset(&rval, 0, sizeof(rval));
    rval.client_ip = old_saddr;             // restore dst to original client
    rval.vip       = old_daddr;             // restore src to VIP
    rval.vip_port  = old_dport;             // restore sport to VIP port
    __builtin_memcpy(rval.client_mac, client_mac, 6);

    bpf_map_update_elem(&reverse_nat, &rkey, &rval, BPF_ANY);

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

    __u32 cfg_key = 0;
    struct lb_config_val *cfg = bpf_map_lookup_elem(&lb_config, &cfg_key);
    if (!cfg || cfg->ipv4 == 0)
        return 3;

    __u32 old_saddr = ip_header->saddr;
    __u32 old_daddr = ip_header->daddr;
    __u16 old_dport = udp_header->dest;

    __u8 client_mac[6];
    __builtin_memcpy(client_mac, l2_header->h_source, 6);
    __u8 my_mac[6];
    __builtin_memcpy(my_mac, l2_header->h_dest, 6);

    __builtin_memcpy(l2_header->h_dest, backend->mac, 6);
    __builtin_memcpy(l2_header->h_source, my_mac, 6);

    ip_header->saddr = cfg->ipv4;
    ip_header->daddr = backend->ipv4;
    udp_header->dest = bpf_htons(backend->port);

    ip_header->check = 0;
    ip_header->check = ip_checksum(ip_header);
    if (udp_header->check != 0) {
        udp_header->check = csum_replace32(udp_header->check, old_saddr, ip_header->saddr);
        udp_header->check = csum_replace32(udp_header->check, old_daddr, ip_header->daddr);
        udp_header->check = csum_replace16(udp_header->check, old_dport, udp_header->dest);
        if (udp_header->check == 0) udp_header->check = 0xFFFF;
    }

    struct reverse_nat_key rkey;
    __builtin_memset(&rkey, 0, sizeof(rkey));
    rkey.src_ip   = backend->ipv4;
    rkey.dst_ip   = cfg->ipv4;
    rkey.src_port = bpf_htons(backend->port);
    rkey.dst_port = udp_header->source;

    struct reverse_nat_val rval;
    __builtin_memset(&rval, 0, sizeof(rval));
    rval.client_ip = old_saddr;
    rval.vip       = old_daddr;
    rval.vip_port  = old_dport;
    __builtin_memcpy(rval.client_mac, client_mac, 6);

    bpf_map_update_elem(&reverse_nat, &rkey, &rval, BPF_ANY);

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


SEC("xdp")
int balancer_handler(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
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

            struct reverse_nat_key rkey;
            __builtin_memset(&rkey, 0, sizeof(rkey));
            rkey.src_ip   = ip->saddr;    // backend IP
            rkey.dst_ip   = ip->daddr;    // balancer IP (our IP)
            rkey.src_port = tcp->source;  // backend port (nbo)
            rkey.dst_port = tcp->dest;    // client ephemeral port (nbo)

            struct reverse_nat_val *rval = bpf_map_lookup_elem(&reverse_nat, &rkey);
            if (rval) {
                __u32 old_saddr = ip->saddr;
                __u32 old_daddr = ip->daddr;
                __u16 old_sport = tcp->source;

                __u8 my_mac[6];
                __builtin_memcpy(my_mac, eth->h_dest, 6);
                __builtin_memcpy(eth->h_dest, rval->client_mac, 6);
                __builtin_memcpy(eth->h_source, my_mac, 6);

                ip->saddr   = rval->vip;
                ip->daddr   = rval->client_ip;
                tcp->source = rval->vip_port;

                ip->check = 0;
                ip->check = ip_checksum(ip);
                tcp->check = csum_replace32(tcp->check, old_saddr, ip->saddr);
                tcp->check = csum_replace32(tcp->check, old_daddr, ip->daddr);
                tcp->check = csum_replace16(tcp->check, old_sport, tcp->source);

                if (tcp->fin || tcp->rst)
                    bpf_map_delete_elem(&reverse_nat, &rkey);

                // Send back to client via the tap it came from originally
                // XDP_TX sends it back out the interface it arrived on (virbr0)
                // Bridge will forward by dst MAC to the correct tap
                return XDP_TX;
            }

            __u8 result = tcp_balancer_handle_v4(eth, ip, tcp, data_end);
            if(result > 0)
                return XDP_PASS;
            return XDP_TX;
           
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)transport_header;
            if ((void *)(udp + 1) > data_end)
                return XDP_PASS;

            struct reverse_nat_key rkey_u;
            __builtin_memset(&rkey_u, 0, sizeof(rkey_u));
            rkey_u.src_ip   = ip->saddr;
            rkey_u.dst_ip   = ip->daddr;
            rkey_u.src_port = udp->source;
            rkey_u.dst_port = udp->dest;

            struct reverse_nat_val *rval_u = bpf_map_lookup_elem(&reverse_nat, &rkey_u);
            if (rval_u) {
                __u32 old_saddr = ip->saddr;
                __u32 old_daddr = ip->daddr;
                __u16 old_sport = udp->source;

                __u8 my_mac[6];
                __builtin_memcpy(my_mac, eth->h_dest, 6);
                __builtin_memcpy(eth->h_dest, rval_u->client_mac, 6);
                __builtin_memcpy(eth->h_source, my_mac, 6);

                ip->saddr   = rval_u->vip;
                ip->daddr   = rval_u->client_ip;
                udp->source = rval_u->vip_port;

                ip->check = 0;
                ip->check = ip_checksum(ip);
                if (udp->check != 0) {
                    udp->check = csum_replace32(udp->check, old_saddr, ip->saddr);
                    udp->check = csum_replace32(udp->check, old_daddr, ip->daddr);
                    udp->check = csum_replace16(udp->check, old_sport, udp->source);
                    if (udp->check == 0) udp->check = 0xFFFF;
                }

                return XDP_TX;
            }

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