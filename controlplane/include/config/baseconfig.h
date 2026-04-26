#pragma once

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>
#include <optional>

namespace blncr {

namespace config {

enum class BalancerType {
    RR,
    WRR,
    CH
};


inline std::optional<BalancerType> fromString(const std::string& data) {
    if(data == "rr") {
        return BalancerType::RR;
    } else if(data == "wrr") {
        return BalancerType::WRR;
    } else if(data == "ch") {
        return BalancerType::CH;
    } else {
        return std::nullopt;
    }
}

struct BalancerReal {
    std::string ip;
    bool enabled;
    uint8_t weight = 1;
    uint8_t ip_version = 4;
    unsigned int port;

    bool operator==(const BalancerReal& real) const {
        return ip == real.ip && weight == real.weight && real.port == port;
    }
};

struct BalancerService {
    std::vector<BalancerReal> reals;
    std::string name;
    std::string vip;
    std::string protocol;
    uint32_t port;
    BalancerType type;
    uint8_t ip_version = 4;

    bool operator==(const BalancerService& srv) const{
        return std::equal(reals.begin(), reals.end(), srv.reals.begin()) 
            && (name == srv.name) && (vip == srv.vip) && (protocol == srv.protocol)&& (port == srv.port) && (type == srv.type);
    }

    bool operator==(BalancerService&& srv) const {
        return std::equal(reals.begin(), reals.end(), srv.reals.begin()) 
            && (name == srv.name) && (vip == srv.vip) && (protocol == srv.protocol)&& (port == srv.port) && (type == srv.type);
    }
};

struct DDoSConfig {
    unsigned int syn_threshold; // max of syn packets by windows
    unsigned int syn_ack_ratio;       
    unsigned int global_syn_threshold; // global SYN per second for VIP
    unsigned int ban_duration_ms; // milliseconds
};

struct BaseConfig {
    std::vector<BalancerService> services;
    std::optional<DDoSConfig> ddosConf = std::nullopt;

    bool operator==(const BaseConfig& conf) const {
        return std::equal(services.begin(), services.end(), conf.services.begin()); 
    }

    bool operator==(BaseConfig&& conf) const {
        return std::equal(services.begin(), services.end(), conf.services.begin()); 
    }

    std::optional<BalancerService> FindServiceByVipAndPort(const std::string& vip, uint32_t port) const {
        auto srv = std::find_if(services.begin(), services.end(), [&](const BalancerService& s) {
            return s.vip == vip && s.port == port;
        });

        if(srv == services.end())
            return std::nullopt;
        return *srv;
    }
};

} // config
} // blncr