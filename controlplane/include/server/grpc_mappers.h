#pragma once

#include "api/controlplane-api.pb.h"
#include "baseconfig.h"
#include "metrics_data.h"
#include <string>
#include <optional>
#include <variant>

namespace blncr::server::mappers {

inline std::string ToProtoAlgorithm(config::BalancerType type) {
    switch (type) {
        case config::BalancerType::RR:  return "rr";
        case config::BalancerType::WRR: return "wrr";
        case config::BalancerType::CH:  return "ch";
        default:                        return "rr";
    }
}

inline api::Backend ToProtoBackend(const config::BalancerReal& real) {
    api::Backend proto;
    proto.set_ip(real.ip);
    proto.set_port(0);
    proto.set_weight(real.weight);
    proto.set_enabled(real.enabled);
    proto.set_ip_version(real.ip_version);
    return proto;
}

inline api::BackendInfo ToProtoBackendInfo(const config::BalancerReal& real) {
    api::BackendInfo info;
    info.set_ip(real.ip);
    info.set_port(real.port);
    info.set_weight(real.weight);
    info.set_enabled(real.enabled);
    return info;
}

inline api::BackendInfo ToProtoBackendInfo(const config::BalancerReal& real,
                                            const metrics::MetricsData& metricsData) {
    api::BackendInfo info = ToProtoBackendInfo(real);
    auto* m = info.mutable_metrics();
    m->set_total_packets(metricsData.total_packets);
    m->set_tcp_syn_packets(metricsData.tcp_syn_packets);
    m->set_prepared_packets(metricsData.prepared_packets);
    m->set_active_connections(metricsData.connections);
    m->set_total_bytes(metricsData.total_bytes);
    return info;
}

inline api::ServiceMetrics ToProtoServiceMetrics(const metrics::MetricsData& data) {
    api::ServiceMetrics m;
    m.set_total_packets(data.total_packets);
    m.set_tcp_syn_packets(data.tcp_syn_packets);
    m.set_prepared_packets(data.prepared_packets);
    m.set_active_connections(data.connections);
    m.set_total_bytes(data.total_bytes);
    return m;
}

inline api::Service toProtoService(const config::BalancerService& service) {
    api::Service proto;
    proto.set_name(service.name);
    proto.set_vip(service.vip);
    proto.set_port(service.port);
    proto.set_protocol(service.protocol);
    proto.set_ip_version(service.ip_version);
    proto.set_algorithm(ToProtoAlgorithm(service.type));
    for (const auto& real : service.reals) {
        *proto.add_backends() = ToProtoBackend(real);
    }
    return proto;
}

inline api::ServiceInfo ToProtoServiceInfo(const config::BalancerService& service,
                                            bool includeBackends,
                                            bool includeMetrics,
                                            const std::optional<metrics::MetricsData>& svcMetrics,
                                            const std::map<std::string, metrics::MetricsData>& backendMetricsMap) {
    api::ServiceInfo info;
    info.set_name(service.name);
    info.set_vip(service.vip);
    info.set_port(service.port);
    info.set_protocol(service.protocol);

    if (includeBackends) {
        for (const auto& real : service.reals) {
            if (includeMetrics) {
                auto it = backendMetricsMap.find(real.ip);
                if (it != backendMetricsMap.end()) {
                    *info.add_backends() = ToProtoBackendInfo(real, it->second);
                } else {
                    *info.add_backends() = ToProtoBackendInfo(real);
                }
            } else {
                *info.add_backends() = ToProtoBackendInfo(real);
            }
        }
    }

    if (includeMetrics && svcMetrics.has_value()) {
        *info.mutable_metrics() = ToProtoServiceMetrics(svcMetrics.value());
    }

    return info;
}

inline api::Configuration ToProtoConfiguration(const std::vector<config::BalancerService>& services) {
    api::Configuration cfg;
    for (const auto& svc : services) {
        *cfg.add_services() = toProtoService(svc);
    }
    return cfg;
}

inline std::optional<config::BalancerType> FromProtoAlgorithm(const std::string& algorithm) {
    return config::fromString(algorithm);
}

inline config::BalancerReal FromProtoBackend(const api::Backend& proto) {
    config::BalancerReal real;
    real.ip         = proto.ip();
    real.enabled    = proto.enabled();
    real.weight     = static_cast<uint8_t>(proto.weight());
    real.ip_version = static_cast<uint8_t>(proto.ip_version());
    return real;
}

inline std::variant<config::BalancerService, std::string> FromProtoService(const api::Service& proto) {
    auto algo = FromProtoAlgorithm(proto.algorithm());
    if (!algo.has_value()) {
        return "unknown algorithm: " + proto.algorithm();
    }

    config::BalancerService svc;
    svc.name       = proto.name();
    svc.vip        = proto.vip();
    svc.port       = proto.port();
    svc.protocol   = proto.protocol();
    svc.ip_version = static_cast<uint8_t>(proto.ip_version());
    svc.type       = algo.value();

    for (const auto& backend : proto.backends()) {
        svc.reals.push_back(FromProtoBackend(backend));
    }

    return svc;
}

inline std::pair<config::BaseConfig, std::vector<std::string>> FromProtoConfiguration(const api::Configuration& proto) {
    config::BaseConfig cfg;
    std::vector<std::string> errors;

    for (const auto& svc : proto.services()) {
        auto result = FromProtoService(svc);
        if (std::holds_alternative<std::string>(result)) {
            errors.push_back("service '" + svc.name() + "': " + std::get<std::string>(result));
        } else {
            cfg.services.push_back(std::get<config::BalancerService>(result));
        }
    }

    return {std::move(cfg), std::move(errors)};
}

} // namespace blncr::server::mappers