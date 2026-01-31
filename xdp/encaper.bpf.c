#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define ETH_P_ARP   0x0806

typedef struct {
    __u32 ip;
    unsigned char mac[6];
    __u8 active;  // 1 = active, 0 = non active
} backend;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, backend);
    __uint(max_entries, 1024);
} backends SEC(".maps");

SEC("xdp")
int decapsulation(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    // Ethernet II
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        bpf_printk("Failed to parse eth hdr\n");
        return XDP_PASS;
    }
    
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        // IP Header
        
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) {
             bpf_printk("Failed to parse ip hdr\n");
            return XDP_PASS;
        }

        __u8 ip_header_len = ip->ihl * 4;
        if (ip_header_len < sizeof(struct iphdr)) {
             bpf_printk("Invalid ip hdr length\n");
            return XDP_PASS;
        }
        
        if ((void *)ip + ip_header_len > data_end) {
            bpf_printk("Invalid ip hdr\n");
            return XDP_PASS;
        }


        // TCP/UDP Headers
        void *transport_header = (void *)ip + ip_header_len;
        
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = transport_header;
            if ((void *)(tcp + 1) > data_end) {
                bpf_printk("Failed to parse tcp hdr\n");
                return XDP_PASS;
            }

        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = transport_header;
            if ((void *)(udp + 1) > data_end) {
                bpf_printk("Failed to parse udp hdr\n");
                return XDP_PASS;
            }
        } else {            
            return XDP_PASS;
        }
        return XDP_PASS;
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";