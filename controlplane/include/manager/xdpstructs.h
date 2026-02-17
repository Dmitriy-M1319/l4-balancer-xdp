#pragma once
#include <bpf/bpf.h>

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
};


/// Map value: service config
struct ServiceInfo {
    __u32 backend_count;     
    __u32 backend_start_idx; 
    __u8 algorithm;         
    __u8 _pad[3];               // Aligment
};
}
}