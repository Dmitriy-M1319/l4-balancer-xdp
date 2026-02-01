#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace blncr {

namespace config {

enum class BalancerType {
    RR,
    WRR,
    CH
};

struct BalancerReal {
    std::string ip;
    bool enabled;
};

struct BalancerService {
    std::vector<BalancerReal> reals;
    std::string vip;
    std::string protocol;
    uint32_t port;
    BalancerType type;
};

struct BaseConfig {
    std::vector<BalancerService> services;
};

} // config
} // blncr