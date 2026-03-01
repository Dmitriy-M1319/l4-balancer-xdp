#pragma once
#include <bpf/bpf.h>
#include <cstring>
#include <compare>

namespace blncr::manager {

namespace xdp {

/// Real server
struct Backend {
    union {
        __u32 ipv4;
        __u8 ipv6[16];  
    };
                  
    __u16 port;              
    unsigned char mac[6]; 
    __u8 active;
    __u8 ip_version;           
    __u8 weight;       
    __u8 pad[2];  

    auto operator<=>(const Backend& other) const {
        if (auto cmp = ip_version <=> other.ip_version; cmp != 0)
            return cmp;
        
        if (ip_version == 4) {
            if (auto cmp = ipv4 <=> other.ipv4; cmp != 0)
                return cmp;
        } else {
            int cmp = std::memcmp(ipv6, other.ipv6, 16);
            if (cmp != 0)
                return cmp <=> 0;
        }
        
        if (auto cmp = port <=> other.port; cmp != 0)
            return cmp;
        
        int mac_cmp = std::memcmp(mac, other.mac, 6);
        if (mac_cmp != 0)
            return mac_cmp <=> 0;
        
        if (auto cmp = active <=> other.active; cmp != 0)
            return cmp;
        
        return weight <=> other.weight;
    }
    
};

/// Map key: composition VIP + protocol + port
struct ServiceKey {
    union {
        __u32 vip4;
        __u8 vip6[16];  
    };       
    __u16 port;       
    __u8 protocol;  
    __u8 ip_version;  
    __u8 _pad[4];        // Aligment

    auto operator <=>(const ServiceKey& other) const {
        if (auto cmp = ip_version <=> other.ip_version; cmp != 0)
            return cmp;
        
        if (ip_version == 4) {
            if (auto cmp = vip4 <=> other.vip4; cmp != 0)
                return cmp;
        } else {
            int cmp = std::memcmp(vip6, other.vip6, 16);
            if (cmp != 0)
                return cmp <=> 0;
        }
        
        if (auto cmp = port <=> other.port; cmp != 0)
            return cmp;
        
        return protocol <=> other.protocol;
    }
};


/// Map value: service config
struct ServiceInfo {
    __u32 backend_count;     
    __u32 backend_start_idx; 
    __u8 algorithm;         
    __u8 _pad[3];               // Aligment
};

struct PacketsData {
    __u64 total_packets;
    __u64 tcp_syn_packets;
    __u64 prepared_packets;
    __u32 connections;
    __u64 total_bytes;
} __attribute__((packed));

}
}