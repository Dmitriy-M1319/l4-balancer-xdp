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



// =================== TCP Session State (lives 1 minute) ======================
// Connection Key
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

// State value (previous balanced backend)
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



// =================== STATICSTICS DATA ========================
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


static __always_inline __u32 csum_add_block(const void *data,
                                             __u32 len) {
    __u32 sum = 0;
    const __u16 *ptr = (const __u16 *)data;

    for (int i = 0; i < 750; i++) {
        if (len < 2) break;
        sum += *ptr++;
        len -= 2;
    }

    if (len == 1) {
        sum += *(__u8 *)ptr;
    }

    return sum;
}



static __always_inline __u16 csum_fold(__u32 sum) {
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (__u16)~sum;
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



static __always_inline __u32 ipv4_pseudo_csum(__u32 saddr,
                                               __u32 daddr,
                                               __u8  proto,
                                               __u16 l4_len) {
    struct {
        __u32 saddr;
        __u32 daddr;
        __u8  zero;
        __u8  proto;
        __u16 len;
    } __attribute__((packed)) pseudo = {
        .saddr = saddr,
        .daddr = daddr,
        .zero  = 0,
        .proto = proto,
        .len   = bpf_htons(l4_len),
    };

    return csum_add_block(&pseudo, sizeof(pseudo));
}



static __always_inline __u32 ipv6_pseudo_csum(const __u8 *saddr,
                                               const __u8 *daddr,
                                               __u8  nexthdr,
                                               __u32 l4_len) {
    struct {
        __u8  saddr[16];
        __u8  daddr[16];
        __u32 len;
        __u8  zeros[3];
        __u8  nexthdr;
    } __attribute__((packed)) pseudo;

    __builtin_memcpy(pseudo.saddr, saddr, 16);
    __builtin_memcpy(pseudo.daddr, daddr, 16);
    pseudo.len     = bpf_htonl(l4_len);
    pseudo.zeros[0] = 0;
    pseudo.zeros[1] = 0;
    pseudo.zeros[2] = 0;
    pseudo.nexthdr  = nexthdr;

    return csum_add_block(&pseudo, sizeof(pseudo));
}



static __always_inline void update_tcp_checksum_v4(
    struct tcphdr *tcph,
    struct iphdr  *iph,
    void          *data_end)
{
    __u32 tcp_len = (__u32)((void *)data_end - (void *)tcph);

    if (tcp_len > 1500) return;

    tcph->check = 0;
    __u32 sum = ipv4_pseudo_csum(iph->saddr, iph->daddr,
                                  IPPROTO_TCP, tcp_len);
    sum += csum_add_block(tcph, tcp_len);

    tcph->check = csum_fold(sum);
}



static __always_inline void update_tcp_checksum_v6(
    struct tcphdr  *tcph,
    struct ipv6hdr *ip6h,
    void           *data_end)
{
    __u32 tcp_len = (__u32)((void *)data_end - (void *)tcph);

    if (tcp_len > 1500) return;

    tcph->check = 0;


    __u32 sum = ipv6_pseudo_csum(
        (__u8 *)&ip6h->saddr,
        (__u8 *)&ip6h->daddr,
        IPPROTO_TCP,
        tcp_len);
    sum += csum_add_block(tcph, tcp_len);

    tcph->check = csum_fold(sum);
}



static __always_inline void update_udp_checksum_v4(
    struct udphdr *udph,
    struct iphdr  *iph,
    void          *data_end)
{
    if (udph->check == 0) return;

    __u32 udp_len = bpf_ntohs(udph->len);
    if (udp_len > 1500) return;

    udph->check = 0;

    __u32 sum = ipv4_pseudo_csum(iph->saddr, iph->daddr,
                                  IPPROTO_UDP, udp_len);
    sum += csum_add_block(udph, udp_len);

    udph->check = csum_fold(sum);

    if (udph->check == 0) {
        udph->check = 0xFFFF;
    }
}



static __always_inline void update_udp_checksum_v6(
    struct udphdr  *udph,
    struct ipv6hdr *ip6h,
    void           *data_end)
{
    __u32 udp_len = bpf_ntohs(udph->len);
    if (udp_len > 1500) return;

    udph->check = 0;

    __u32 sum = ipv6_pseudo_csum(
        (__u8 *)&ip6h->saddr,
        (__u8 *)&ip6h->daddr,
        IPPROTO_UDP,
        udp_len);
    sum += csum_add_block(udph, udp_len);

    udph->check = csum_fold(sum);
    if (udph->check == 0) {
        udph->check = 0xFFFF;
    }
}



static __always_inline void update_tcp_checksum(
    struct tcphdr *tcph,
    void          *iph,
    __u8           ip_version,
    void          *data_end)
{
    if (ip_version == 4) {
        update_tcp_checksum_v4(tcph, (struct iphdr *)iph, data_end);
    } else if (ip_version == 6) {
        update_tcp_checksum_v6(tcph, (struct ipv6hdr *)iph, data_end);
    }
}



static __always_inline void update_udp_checksum(
    struct udphdr *udph,
    void          *iph,
    __u8           ip_version,
    void          *data_end)
{
    if (ip_version == 4) {
        update_udp_checksum_v4(udph, (struct iphdr *)iph, data_end);
    } else if (ip_version == 6) {
        update_udp_checksum_v6(udph, (struct ipv6hdr *)iph, data_end);
    }
}



static __always_inline struct backend *rr_balancer_handle(void *current_back_map, 
                                                            struct service_info *info, 
                                                            struct service_key *key, 
                                                            __u32 *last_index) 
{
    __u32 *current_index = (__u32 *)bpf_map_lookup_elem(&rr_index, key);
    if(current_index) {
        __u32 new_index = *current_index + 1;
        if(new_index >= info->backend_count) {
            new_index = 0;
        }
        __u32 backend_search_index = info->backend_start_idx + new_index;
        struct backend *back = (struct backend *)bpf_map_lookup_elem(&current_back_map, &backend_search_index);
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
        if (!state) {
            return (struct backend *)0;
        }
    }
    
    int attempts = 0;
    while (attempts < info->backend_count * 2) {
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
        attempts++;
    }
    
    return (struct backend *)0;
}



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


    // check firstly in session state map (not TCP SYN)
    if(!tcp->syn) {
        state_backend = (struct session_state_val *)bpf_map_lookup_elem(&tcp_session_state, &state_key);
        if(state_backend) {
            // state finded
            __u64 now = bpf_ktime_get_ns();
            if (now - state_backend->created > state_backend->timeout) {
                // state expired
                bpf_map_delete_elem(&tcp_session_state, &state_key);

                // backend stats block
                struct summary_packets_data *pkts_stats = 
                    (struct summary_packets_data *)bpf_map_lookup_elem(&backends_packets_stats, &state_backend->backend_idx);
                if(pkts_stats) {
                    pkts_stats->connections--;
                }

                // service state block
                struct summary_packets_data *service_pkts_stats = 
                    (struct summary_packets_data *)bpf_map_lookup_elem(&services_packets_stats, &key);
                if(service_pkts_stats) {
                    service_pkts_stats->connections--;
                }
            } else {
                state_backend->created = now;
                backend = (struct backend *)bpf_map_lookup_elem(backends_map, &state_backend->backend_idx);
                last_backend_index = state_backend->backend_idx;
            }
        } 
    }
    if(!backend) {
        struct service_info *info = (struct service_info *)bpf_map_lookup_elem(&services_map, key);
        __u32 attempts = 0;
        if(info) {
            switch (info->algorithm) {
                case BALANCER_RR:
                    do {
                        backend = rr_balancer_handle(backends_map, info, key, &last_backend_index);
                        if (++attempts > info->backend_count) {
                            backend = (struct backend *)0;
                            break;
                        }
                    } while(backend && !(backend->active));
                    break;
                case BALANCER_WRR:
                    do {
                        backend = wrr_balancer_handle(backends_map, info, key, &last_backend_index);
                        if (++attempts > info->backend_count) {
                            backend = (struct backend *)0;
                            break;
                        }
                    } while(backend && !(backend->active));
                    break;
                default:
                    return (struct backend *)0;
            }

            if(!backend) {
                bpf_printk("xdp: failed to get backend for vip + dst port\n");
                return (struct backend *)0;
            }
        } else {
            return (struct backend *)0;
        }

        // new state create
        struct session_state_val new_state;
        new_state.backend_idx = last_backend_index;
        new_state.created = bpf_ktime_get_ns();
        new_state.timeout = TCP_STATE_TIMEOUT;

        // backend stats
        struct summary_packets_data *pkts_stats = (struct summary_packets_data *)bpf_map_lookup_elem(&backends_packets_stats, &state_backend->backend_idx);
        if(pkts_stats) {
            pkts_stats->connections++;
        }

        // service stats
        struct summary_packets_data *service_pkts_stats = 
                    (struct summary_packets_data *)bpf_map_lookup_elem(&services_packets_stats, &key);
        if(service_pkts_stats) {
            service_pkts_stats->connections++;
        }

        bpf_map_update_elem(&tcp_session_state, &state_key, &new_state, BPF_ANY);
    }

    // check if TCP FIN or TCP RST (delete session state)
    if(state_backend && (tcp->fin || tcp->rst)) {
        bpf_map_delete_elem(&tcp_session_state, &state_key);
        // backend stats block
        struct summary_packets_data *pkts_stats = 
            (struct summary_packets_data *)bpf_map_lookup_elem(&backends_packets_stats, &state_backend->backend_idx);
        if(pkts_stats) {
            pkts_stats->connections--;
        } 

        // service stats block
        struct summary_packets_data *service_pkts_stats = 
                    (struct summary_packets_data *)bpf_map_lookup_elem(&services_packets_stats, &key);
        if(service_pkts_stats) {
            service_pkts_stats->connections--;
        }
    }

    // backend stats block
    struct summary_packets_data *pkts_stats = 
        (struct summary_packets_data *)bpf_map_lookup_elem(&backends_packets_stats, &last_backend_index);
    if(pkts_stats) {
        pkts_stats->total_packets++;
        if(tcp->syn) {
            pkts_stats->tcp_syn_packets++;
        }
        pkts_stats->prepared_packets++;
        pkts_stats->total_bytes += packet_len;
    }

    // service stats block
    struct summary_packets_data *service_pkts_stats = 
                    (struct summary_packets_data *)bpf_map_lookup_elem(&services_packets_stats, &key);
    if(service_pkts_stats) {
        service_pkts_stats->total_packets++;
        if(tcp->syn) {
            service_pkts_stats->tcp_syn_packets++;
        }
        service_pkts_stats->prepared_packets++;
    }

    return backend;
}



static __always_inline struct backend *find_udp_backend(struct service_key *key, __u32 packet_len) 
{
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

    // no sessions for UDP traffic
    struct service_info *info = (struct service_info *)bpf_map_lookup_elem(&services_map, key);
    __u32 last_backend_index;
    __u32 attempts = 0;
    if(info) {
        switch (info->algorithm) {
            case BALANCER_RR:
                do {
                    backend = rr_balancer_handle(backends_map, info, key, &last_backend_index);
                    if (++attempts > info->backend_count) {
                        backend = (struct backend *)0;
                        break;
                    }
                } while(backend && !(backend->active));
                break;
            case BALANCER_WRR:
                do {
                    backend = wrr_balancer_handle(backends_map, info, key, &last_backend_index);
                    if (++attempts > info->backend_count) {
                        backend = (struct backend *)0;
                        break;
                    }
                } while(backend && !(backend->active));
                break;
            default:
                return (struct backend *)0;
        }

        if(!backend) {
            bpf_printk("xdp: failed to get backend for vip + dst port\n");
            return (struct backend *)0;
        }
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
                    (struct summary_packets_data *)bpf_map_lookup_elem(&services_packets_stats, &key);
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
    // find service data for balancing
    __u32 dst_ip = ip_header->daddr;
    __u16 dst_port = bpf_ntohs(tcp_header->dest);
    struct service_key key;
    key.port = dst_port;
    key.vip4 = dst_ip;
    key.protocol = IPPROTO_TCP;
    key.ip_version = 4;

    struct backend *backend = (struct backend *)0;
    struct session_state_val *state_backend = (struct session_state_val *)0;
    struct session_state_key state_key;

    state_key.src_ipv4 = ip_header->saddr;
    state_key.dst_ipv4 = ip_header->daddr;
    state_key.src_port = tcp_header->source;
    state_key.dst_port = tcp_header->dest;

    __u32 packet_len = (__u32)(data_end - (void *)l2_header); 
    backend = find_tcp_backend(&state_key, &key, tcp_header, packet_len);
    if(!backend) {
        return 3;
    }

    // Prepare Layers
    __builtin_memcpy(l2_header->h_dest, backend->mac, 6);
    ip_header->daddr = backend->ipv4;
    tcp_header->dest = bpf_htons(backend->port);

    // Calculate checksums
    ip_header->check = 0;
    ip_header->check = ip_checksum(ip_header);
    update_tcp_checksum_v4(tcp_header, ip_header, data_end);
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
    key.port = dst_port;
    key.vip4 = dst_ip;
    key.protocol = IPPROTO_UDP;
    key.ip_version = 4;

    __u32 packet_len = (__u32)(data_end - (void *)l2_header); 

    struct backend *backend = find_udp_backend(&key, packet_len);
    if(!backend) {
        return 3;
    }

     // Prepare Layers
    __builtin_memcpy(l2_header->h_dest, backend->mac, 6);
    ip_header->daddr = backend->ipv4;
    udp_header->dest = bpf_htons(backend->port);

    // Calculate checksums
    ip_header->check = 0;
    ip_header->check = ip_checksum(ip_header);
    update_udp_checksum_v4(udp_header, ip_header, data_end);
    return 0;
}


static __always_inline __u8 tcp_balancer_handle_v6(struct ethhdr *l2_header, 
                                                    struct ipv6hdr *ip_header, 
                                                    struct tcphdr *tcp_header, 
                                                    void *data_end) 
{
    // find service data for balancing
    __u16 dst_port = bpf_ntohs(tcp_header->dest);
    struct service_key key;
    key.port = dst_port;
    __builtin_memcpy(key.vip6, &ip_header->daddr, 16);

    key.protocol = IPPROTO_TCP;
    key.ip_version = 6;

    struct backend *backend = (struct backend *)0;
    struct session_state_val *state_backend = (struct session_state_val *)0;
    struct session_state_key state_key;

    __builtin_memcpy(state_key.src_ipv6, &ip_header->saddr, 16);
    __builtin_memcpy(state_key.dst_ipv6, &ip_header->daddr, 16);
    state_key.src_port = tcp_header->source;
    state_key.dst_port = tcp_header->dest;

    __u32 packet_len = (__u32)(data_end - (void *)l2_header); 
    backend = find_tcp_backend(&state_key, &key, tcp_header, packet_len);
    if(!backend) {
        return 3;
    }

    // Prepare Layers
    __builtin_memcpy(l2_header->h_dest, backend->mac, 6);
    __builtin_memcpy(&ip_header->daddr, backend->ipv6, 16);
    tcp_header->dest = bpf_htons(backend->port);

    // Calculate checksums
    update_tcp_checksum_v6(tcp_header, ip_header, data_end);
    return 0;
}



static __always_inline int udp_balancer_handle_v6(struct ethhdr *l2_header, 
                                                    struct ipv6hdr *ip_header, 
                                                    struct udphdr *udp_header, 
                                                    void *data_end) 
{
    __u16 dst_port = bpf_ntohs(udp_header->dest);
    struct service_key key;
    key.port = dst_port;
    __builtin_memcpy(key.vip6, &ip_header->daddr, 16);
    key.protocol = IPPROTO_UDP;
    key.ip_version = 6;

    __u32 packet_len = (__u32)(data_end - (void *)l2_header); 
    struct backend *backend = find_udp_backend(&key, packet_len);
    if(!backend) {
        return 3;
    }

    // Prepare Layers
    __builtin_memcpy(l2_header->h_dest, backend->mac, 6);
    __builtin_memcpy(&ip_header->daddr, backend->ipv6, 16);
    udp_header->dest = bpf_htons(backend->port);

    // Calculate checksums
    update_udp_checksum_v6(udp_header, ip_header, data_end);
    return 0;
}



SEC("xdp")
int balancer_handler(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    // Ethernet II
    
    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)(eth + 1) > data_end) {
        bpf_printk("xdp: failed to parse eth hdr\n");
        return XDP_PASS;
    }
    
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        // IP Header
        
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) {
             bpf_printk("xdp: failed to parse ip hdr\n");
            return XDP_PASS;
        }

        __u8 ip_header_len = ip->ihl * 4;
        if (ip_header_len < sizeof(struct iphdr)) {
             bpf_printk("xdp: invalid ip hdr length\n");
            return XDP_PASS;
        }
        
        if ((void *)ip + ip_header_len > data_end) {
            bpf_printk("xdp: invalid ip hdr\n");
            return XDP_PASS;
        }


        // TCP/UDP Headers
        void *transport_header = (void *)ip + ip_header_len;
        
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)transport_header;
            if ((void *)(tcp + 1) > data_end) {
                bpf_printk("xdp: failed to parse tcp hdr\n");
                return XDP_PASS;
            }

            __u8 result = tcp_balancer_handle_v4(eth, ip, tcp, data_end);
            if(result > 0) {
                bpf_printk("xdp: failed to redirect TCP packet\n");
                return XDP_PASS;
            } else {
                return XDP_TX;
            }
           
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)transport_header;
            if ((void *)(udp + 1) > data_end) {
                bpf_printk("xdp: failed to parse udp hdr\n");
                return XDP_PASS;
            }
            
            __u8 result = udp_balancer_handle_v4(eth, ip, udp, data_end);
            if(result > 0) {
                bpf_printk("xdp: failed to redirect UDP packet\n");
                return XDP_PASS;
            } else {
                return XDP_TX;
            }
        } else {            
            return XDP_PASS;
        }
    } else if(eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) {
            bpf_printk("xdp: failed to parse ipv6 hdr\n");
            return XDP_PASS;
        }
        
        __u8 nexthdr = ip6->nexthdr;
        void *transport = (void *)(ip6 + 1);
        
        if (nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)transport;
            if ((void *)(tcp + 1) > data_end) {
                bpf_printk("xdp: failed to parse tcp hdr\n");
                return XDP_PASS;
            }

            __u8 result = tcp_balancer_handle_v6(eth, ip6, tcp, data_end);
            if(result > 0) {
                bpf_printk("xdp: failed to redirect TCP packet\n");
                return XDP_PASS;
            } else {
                return XDP_TX;
            }
           
        } else if (nexthdr == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)transport;
            if ((void *)(udp + 1) > data_end) {
                bpf_printk("xdp: failed to parse udp hdr\n");
                return XDP_PASS;
            }
            
            __u8 result = udp_balancer_handle_v6(eth, ip6, udp, data_end);
            if(result > 0) {
                bpf_printk("xdp: failed to redirect UDP packet\n");
                return XDP_PASS;
            } else {
                return XDP_TX;
            }
        } else {            
            return XDP_PASS;
        }
    }
    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";