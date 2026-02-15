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

    bool operator==(const BalancerReal& real) const {
        return ip == real.ip && weight == real.weight;
    }
};

struct BalancerService {
    std::vector<BalancerReal> reals;
    std::string name;
    std::string vip;
    std::string protocol;
    uint32_t port;
    BalancerType type;

    bool operator==(const BalancerService& srv) const{
        return std::equal(reals.begin(), reals.end(), srv.reals.begin()) 
            && (name == srv.name) && (vip == srv.vip) && (protocol == srv.protocol)&& (port == srv.port) && (type == srv.type);
    }

    bool operator==(BalancerService&& srv) const {
        return std::equal(reals.begin(), reals.end(), srv.reals.begin()) 
            && (name == srv.name) && (vip == srv.vip) && (protocol == srv.protocol)&& (port == srv.port) && (type == srv.type);
    }
};

struct BaseConfig {
    std::vector<BalancerService> services;


    bool operator==(const BaseConfig& conf) const {
        return std::equal(services.begin(), services.end(), conf.services.begin()); 
    }

    bool operator==(BaseConfig&& conf) const {
        return std::equal(services.begin(), services.end(), conf.services.begin()); 
    }
};

} // config
} // blncr