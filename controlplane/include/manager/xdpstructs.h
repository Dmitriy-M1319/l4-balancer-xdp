#pragma once
#include <bpf/bpf.h>

namespace blncr::manager {

namespace xdp {

/// Real server
struct Backend {
    __u32 ip;                
    __u16 port;              
    unsigned char mac[6]; 
    __u8 active;             
    __u8 weight;         
};

/// Map key: composition VIP + protocol + port
struct ServiceKey {
    __u32 vip;        
    __u16 port;       
    __u8 protocol;    
    __u8 _pad;        // Aligment
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