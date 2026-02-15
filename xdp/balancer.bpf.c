#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define ETH_P_ARP   0x0806

#define BALANCER_RR 0x00
#define BALANCER_WRR 0x01
#define BALANCER_CH 0x02

#define TCP_STATE_TIMEOUT 60000000000ULL

// Key: composition VIP + protocol + port
struct service_key {
    __u32 vip;        
    __u16 port;       
    __u8 protocol;    
    __u8 _pad;        
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
    __u32 ip;                
    __u16 port;              
    unsigned char mac[6];    
    __u8 active;             
    __u8 weight;            
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


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);  
    __type(key, struct service_key);
    __type(value,__u32);
} rr_index SEC(".maps");


// TCP Session State (lives 1 minute)
// Connection Key
struct session_state_key {
    __u32 src_ip;                
    __u16 src_port;
    __u32 dst_ip;                
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
    __uint(max_entries, 1024);  
    __type(key, struct session_state_key);
    __type(value, struct session_state_val);
} tcp_session_state SEC(".maps");

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

static __always_inline __u16 tcp_udp_checksum(void *data, __u32 len, __u32 saddr, __u32 daddr, __u8 proto) {
    __u32 sum = 0;
    __u16 *ptr = (__u16 *)data;
    int datalen = len;
    
    struct pseudo_header {
        __u32 saddr;
        __u32 daddr;
        __u8 zero;
        __u8 proto;
        __u16 len;
    } __attribute__((packed)) pseudo;
    
    pseudo.saddr = saddr;
    pseudo.daddr = daddr;
    pseudo.zero = 0;
    pseudo.proto = proto;
    pseudo.len = bpf_htons(len);
    
    ptr = (__u16 *)&pseudo;
    for (int i = 0; i < sizeof(pseudo) / 2; i++) {
        sum += ptr[i];
    }
    
    ptr = (__u16 *)data;
    while (datalen > 1) {
        sum += *ptr++;
        datalen -= 2;
    }
    
    if (datalen == 1)
        sum += *(__u8 *)ptr;
    
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    return (__u16)~sum;
}

static __always_inline void update_tcp_checksum(struct tcphdr *tcph, struct iphdr *iph, void *data_end) {
    void *tcp_data = (void *)tcph + (tcph->doff * 4);
    __u32 tcp_len = (void *)data_end - (void *)tcph;

    tcph->check = 0;
    tcph->check = tcp_udp_checksum(tcph, tcp_len, 
                                   iph->saddr, iph->daddr, 
                                   IPPROTO_TCP);
}

static __always_inline void update_udp_checksum(struct udphdr *udph, struct iphdr *iph, void *data_end) {
    __u32 udp_len = bpf_ntohs(udph->len);
    if (udph->check == 0)
        return;
    
    udph->check = 0;
    udph->check = tcp_udp_checksum(udph, udp_len,
                                   iph->saddr, iph->daddr,
                                   IPPROTO_UDP);
    if (udph->check == 0)
        udph->check = 0xFFFF;
}


static __always_inline struct backend *rr_balancer_handle(void *current_back_map, struct service_info *info, struct service_key *key, __u32 *last_index) {
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


static __always_inline __u8 tcp_balancer_handle(struct ethhdr *l2_header, struct iphdr *ip_header, struct tcphdr *tcp_header, void *data_end) {
    // find service data for balancing
    __u32 dst_ip = ip_header->daddr;
    __u16 dst_port = bpf_ntohs(tcp_header->dest);
    struct service_key key;
    key.port = dst_port;
    key.vip = dst_ip;
    key.protocol = IPPROTO_TCP;

    struct backend *backend = (struct backend *)0;
    struct session_state_val *state_backend = (struct session_state_val *)0;
    struct session_state_key state_key;

    state_key.src_ip = ip_header->saddr;
    state_key.dst_ip = ip_header->daddr;
    state_key.src_port = tcp_header->source;
    state_key.dst_port = tcp_header->dest;

    
    __u32 atomic_key = 0;
    __u64 *curr_index = (__u64 *)bpf_map_lookup_elem(&atomic_index, &atomic_key);
    if(!curr_index) {
        bpf_printk("xdp: invalid index for services\n");
        return 3;
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
    if(!tcp_header->syn) {
        state_backend = (struct session_state_val *)bpf_map_lookup_elem(&tcp_session_state, &state_key);
        if(state_backend) {
            // state finded
            __u64 now = bpf_ktime_get_ns();
            if (now - state_backend->created > state_backend->timeout) {
                // state expired
                bpf_map_delete_elem(&tcp_session_state, &state_key);
            } else {
                state_backend->created = now;
                backend = (struct backend *)bpf_map_lookup_elem(backends_map, &state_backend->backend_idx);
            }
        } 
    }
    if(!backend) {
        struct service_info *info = (struct service_info *)bpf_map_lookup_elem(&services_map, &key);
        __u32 state_index;
        __u32 attempts = 0;
        if(info) {
            switch (info->algorithm) {
                case BALANCER_RR:
                    do {
                        backend = rr_balancer_handle(backends_map, info, &key, &state_index);
                        if (++attempts > info->backend_count) {
                            backend = (struct backend *)0;
                            break;
                        }
                    } while(backend && !(backend->active));
                    break;
                default:
                    return 2;
            }

            if(!backend) {
                bpf_printk("xdp: failed to get backend for vip + dst port\n");
                return 2;
            }
        } else {
            return 2;
        }

        // new state create
        struct session_state_val new_state;
        new_state.backend_idx = state_index;
        new_state.created = bpf_ktime_get_ns();
        new_state.timeout = TCP_STATE_TIMEOUT;

        bpf_map_update_elem(&tcp_session_state, &state_key, &new_state, BPF_ANY);
    }

    // check if TCP FIN or TCP RST (delete session state)
    if(state_backend && (tcp_header->fin || tcp_header->rst)) {
        bpf_map_delete_elem(&tcp_session_state, &state_key);
    }

    // Prepare Layers
    __builtin_memcpy(l2_header->h_dest, backend->mac, 6);
    ip_header->daddr = backend->ip;
    tcp_header->dest = bpf_htons(backend->port);

    // Calculate checksums
    ip_header->check = 0;
    ip_header->check = ip_checksum(ip_header);
    update_tcp_checksum(tcp_header, ip_header, data_end);
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

            __u8 result = tcp_balancer_handle(eth, ip, tcp, data_end);
            if(result > 0) {
                bpf_printk("xdp: failed to redirect TCP packet\n");
                return XDP_PASS;
            } else {
                return XDP_TX;
            }
           
        } else if (ip->protocol == IPPROTO_UDP) {
            // struct udphdr *udp = transport_header;
            // if ((void *)(udp + 1) > data_end) {
            //     bpf_printk("xdp: failed to parse udp hdr\n");
            //     return XDP_PASS;
            // }
            return XDP_PASS;
        } else {            
            return XDP_PASS;
        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";