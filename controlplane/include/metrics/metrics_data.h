#pragma once 

#include <string>
#include <compare>
#include <map>
#include <cstdint>

namespace blncr {

namespace metrics {

struct BackendInfo {
    std::string ip_address;
    unsigned int port;
    short ip_version;

    auto operator<=>(const BackendInfo& other) const {
        if (auto cmp = ip_version <=> other.ip_version; cmp != 0)
            return cmp;
        if (auto cmp = ip_address <=> other.ip_address; cmp != 0)
            return cmp;
        
        return port <=> other.port;
    }
};

struct ServiceInfo {
    std::string name;
    std::string vip_address;
    unsigned int port;
    short ip_version;

    auto operator<=>(const ServiceInfo& other) const {
        if (auto cmp = ip_version <=> other.ip_version; cmp != 0)
            return cmp;
        if (auto cmp = vip_address <=> other.vip_address; cmp != 0)
            return cmp;

        if (auto cmp = name <=> other.name; cmp != 0)
            return cmp;
        
        return port <=> other.port;
    }
};

struct MetricsData {
    uint64_t total_packets;
    uint64_t tcp_syn_packets;
    uint64_t prepared_packets;
    int32_t connections;
    uint64_t total_bytes;
};

struct RateMetrics {
    double packets_per_sec;
    double bytes_per_sec;
    double syn_per_sec;
};

class IMetricsProvider {
public:
    virtual std::map<BackendInfo, MetricsData> GetBackendsCurrentMetrics() = 0;
    virtual std::map<ServiceInfo, MetricsData> GetServicesCurrentMetrics() = 0;
};

}
}