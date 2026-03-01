#include "xdpdataplane.h"
#include "arp.h"
#include "metrics_data.h"
#include "ndp.h"
#include "xdpstructs.h"
#include <algorithm>
#include <array>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <format>
#include <linux/bpf.h>
#include <netinet/in.h>
#include <optional>
#include <arpa/inet.h>
#include <string>
#include <sys/socket.h>
#include <utility>
#include <variant>


using namespace blncr;

manager::XdpDataplane::XdpDataplane(const std::string& name, const std::string& iface) 
    : m_progName(name), m_progInterface(iface) {}

manager::XdpDataplane::~XdpDataplane() {
    if (m_interfaceIdx > 0) {
        bpf_xdp_detach(m_interfaceIdx, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
        printf("XDP program detached\n");
    }
    
    if (m_xdpObject) {
        bpf_object__close(m_xdpObject);
    }
}

std::optional<std::string> manager::XdpDataplane::RunProgram(const std::string& binName) {
    m_xdpObject = bpf_object__open_file(binName.c_str(), NULL);
    if (libbpf_get_error(m_xdpObject)) {
        return std::format("failed to open bpf: {}", std::move(strerror(errno)));
    }

    int err = bpf_object__load(m_xdpObject);
    if (err) {
        if (m_xdpLink) {
            bpf_link__destroy(m_xdpLink);
        }
        if (m_xdpObject) {
            bpf_object__close(m_xdpObject);
        }
        return std::format("failed to load bpf: {}", std::move(strerror(errno)));
    }

    bpf_program *prog_struct = bpf_object__find_program_by_name(m_xdpObject, m_progName.c_str());
    int prog_fd = bpf_program__fd(prog_struct);

    int ifindex = if_nametoindex(m_progInterface.c_str());
    if(!ifindex) {
        if (m_xdpLink) {
            bpf_link__destroy(m_xdpLink);
        }
        if (m_xdpObject) {
            bpf_object__close(m_xdpObject);
        }
        return std::format("failed to find interface {}", m_progInterface);
    }
    if(bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL) != 0) {
        if (m_xdpLink) {
            bpf_link__destroy(m_xdpLink);
        }
        if (m_xdpObject) {
            bpf_object__close(m_xdpObject);
        }
        return std::format("failed to attach to program {}", m_progName);
    }
    
    auto backendsFirst = openBpfMap("backends_first");
    if(std::get_if<std::string>(&backendsFirst)) {
        return std::get<std::string>(backendsFirst);
    } else {
        m_backendsMapFirst = std::get<bpf_map*>(backendsFirst);
        m_backendsMapFirstFd = bpf_map__fd(m_backendsMapFirst);    
    }

    auto backendsSecond = openBpfMap("backends_second");
    if(std::get_if<std::string>(&backendsSecond)) {
        return std::get<std::string>(backendsSecond);
    } else {
        m_backendsMapSecond = std::get<bpf_map*>(backendsSecond);
        m_backendsMapSecondFd = bpf_map__fd(m_backendsMapSecond);    
    }

    auto servicesFirst = openBpfMap("services_first");
    if(std::get_if<std::string>(&servicesFirst)) {
        return std::get<std::string>(servicesFirst);
    } else {
        m_servicesMapFirst = std::get<bpf_map*>(servicesFirst);
        m_servicesMapFirstFd = bpf_map__fd(m_servicesMapFirst);    
    }

    auto servicesSecond = openBpfMap("services_second");
    if(std::get_if<std::string>(&servicesSecond)) {
        return std::get<std::string>(servicesSecond);
    } else {
        m_servicesMapSecond = std::get<bpf_map*>(servicesSecond);
        m_servicesMapSecondFd = bpf_map__fd(m_servicesMapSecond);    
    }

    auto atomicIndex = openBpfMap("atomic_index");
    if(std::get_if<std::string>(&atomicIndex)) {
        return std::get<std::string>(atomicIndex);
    } else {
        m_atomicIndexMap = std::get<bpf_map*>(atomicIndex);
        m_atomicIndexMapFd = bpf_map__fd(m_atomicIndexMap);    
    }

    auto rrIndex = openBpfMap("rr_index");
    if(std::get_if<std::string>(&rrIndex)) {
        return std::get<std::string>(rrIndex);
    } else {
        m_rrIndexMap = std::get<bpf_map*>(rrIndex);
        m_rrIndexMapFd = bpf_map__fd(m_rrIndexMap);    
    }

    auto sessionState = openBpfMap("tcp_session_state");
    if(std::get_if<std::string>(&sessionState)) {
        return std::get<std::string>(sessionState);
    } else {
        m_sessionStateMap = std::get<bpf_map*>(sessionState);
        m_sessionStateMapFd = bpf_map__fd(m_sessionStateMap);    
    }

    auto wrrState = openBpfMap("wrr_state_map");
    if(std::get_if<std::string>(&wrrState)) {
        return std::get<std::string>(wrrState);
    } else {
        m_wrrStateMap = std::get<bpf_map*>(wrrState);
        m_wrrStateMapFd = bpf_map__fd(m_wrrStateMap);    
    }

    auto backendsStates = openBpfMap("backends_packets_stats");
    if(std::get_if<std::string>(&backendsStates)) {
        return std::get<std::string>(backendsStates);
    } else {
        m_backendsStatsMap = std::get<bpf_map*>(backendsStates);
        m_backendsStatsMapFd = bpf_map__fd(m_backendsStatsMap);    
    }

    auto servicesStates = openBpfMap("services_packets_stats");
    if(std::get_if<std::string>(&servicesStates)) {
        return std::get<std::string>(servicesStates);
    } else {
        m_servicesStatsMap = std::get<bpf_map*>(servicesStates);
        m_servicesStatsMapFd = bpf_map__fd(m_servicesStatsMap);    
    }


    return std::nullopt;
}

std::variant<bpf_map *, std::string> manager::XdpDataplane::openBpfMap(std::string_view mapName)
{
    bpf_map *map = bpf_object__find_map_by_name(m_xdpObject, mapName.data());
    if(!map) {
        if (m_xdpLink) {
            bpf_link__destroy(m_xdpLink);
        }
        if (m_xdpObject) {
            bpf_object__close(m_xdpObject);
        }
        return std::format("failed to find map \"{}\"", mapName);
    }
    return map;
}

bool manager::XdpDataplane::isValidBpfState() const noexcept {
    return m_backendsMapFirst && m_backendsMapSecond && m_atomicIndexMap && m_servicesMapFirst && m_servicesMapSecond;
}

std::optional<std::string> manager::XdpDataplane::ReloadConfig(const config::BaseConfig& config) {
    if(isValidBpfState()) {
        int currentBackendIdx = 0;
        m_xdpBackends.clear();
        m_xdpKeys.resize(config.services.size());
        m_xdpServices.resize(config.services.size());

        for(const auto& service: config.services) {
            // 1. Key preparing
            xdp::ServiceKey key {
                .port = __u16(service.port),
                .protocol = __u8(service.protocol == "tcp" ? IPPROTO_TCP : IPPROTO_UDP),
                .ip_version = 4
            };

            if(service.ip_version == 4) {
                struct in_addr addr;
                if(inet_aton(service.vip.c_str(), &addr) == 0) {
                    return std::format("failed to prepare VIP {} into bytes", service.vip); // предусмотреть везде debug режим
                }
                key.vip4 = addr.s_addr;
                key.ip_version = 4;
            } else {
                struct in6_addr addr;
                if(inet_pton(AF_INET6, service.vip.c_str(), &addr) == 0) {
                    return std::format("failed to prepare VIP {} into bytes", service.vip);
                }
                memcpy(key.vip6, &addr, 16);
                key.ip_version = 6;
            }

            m_xdpKeys.push_back(std::move(key));

            // 2. Balancers Preparing
            int count = 0;
            for(const auto& real: service.reals) {
                xdp::Backend back;

                if(real.ip_version == 4) {
                    struct in_addr addr;
                    if(inet_aton(real.ip.c_str(), &addr) == 0) {
                        return std::format("failed to prepare real IP {} into bytes", real.ip);
                    }
                    back.ipv4 = addr.s_addr;
                    back.ip_version = 4;
                } else {
                    struct in6_addr addr;
                    if(inet_pton(AF_INET6, real.ip.c_str(), &addr) == 0) {
                        return std::format("failed to prepare real IP {} into bytes", real.ip);
                    }
                    memcpy(back.ipv6, &addr, 16);
                    back.ip_version = 6;
                }

                back.port = service.port;
                back.weight = real.weight;

                std::optional<std::array<uint8_t, 6>> mac;
                if(real.ip_version == 4) {
                    mac = netutils::Arp::Lookup(real.ip, m_progInterface);
                } else {
                    mac = netutils::Ndp::Lookup(real.ip, m_progInterface);
                }
                
                if(mac.has_value()) {
                    std::copy(mac->begin(), mac->end(), std::begin(back.mac));
                } else {
                     return std::format("failed to get MAC address for real IP {} ", real.ip);
                }
                back.active = static_cast<unsigned char>(real.enabled);
                m_xdpBackends.push_back(std::move(back));
                ++count;
            }

            // 3. Service Info Preparing
            xdp::ServiceInfo info;
            info.backend_start_idx = currentBackendIdx;
            info.backend_count = count;
            info.algorithm = static_cast<int>(service.type);
            m_xdpServices.push_back(std::move(info));
            currentBackendIdx += count;
        }


        uint8_t currentIndex{};
        uint32_t key = 0;
        if(m_isFirstRun) {
            currentIndex = 0;
            m_isFirstRun = false;
        } else {
            if(bpf_map_lookup_elem(m_atomicIndexMapFd, &key, &currentIndex) != 0) {
                return "failed to load current index for reload config";
            }
        }

        int currServicesMapFd = (currentIndex == 0 ? m_servicesMapSecondFd : m_servicesMapFirstFd);
        int currBackendMapFd = (currentIndex == 0 ? m_backendsMapSecondFd : m_backendsMapFirstFd);

        // Load Backends
        std::vector<__u32> backendKeys(m_xdpBackends.size());
        for (size_t i = 0; i < backendKeys.size(); i++) {
            backendKeys[i] = static_cast<__u32>(i);
        }

        __u32 backendCount = static_cast<__u32>(m_xdpBackends.size());
        bpf_map_batch_opts opts;
        opts.flags = BPF_ANY; 
        int ret = bpf_map_update_batch(currBackendMapFd, 
                                       backendKeys.data(), 
                                       m_xdpBackends.data(),
                                       &backendCount, 
                                       &opts);
        if(ret != 0) {
            return std::format("failed to update batch of backends: {}", strerror(errno));
        }

        __u32 serviceCount = static_cast<__u32>(m_xdpKeys.size());
        
        ret = bpf_map_update_batch(currServicesMapFd,
                                       m_xdpKeys.data(),
                                       m_xdpServices.data(),
                                       &serviceCount,
                                       &opts);
        if(ret != 0) {
            return std::format("failed to update batch of services: {}", strerror(errno));
        }
        
        // atomic index change
        int newIndex = 1 - currentIndex;
        if(bpf_map_update_elem(m_atomicIndexMapFd, &key, &newIndex, BPF_ANY) != 0) {
            return std::format("failed to update atomic pointer on config: {}", strerror(errno));
        }

        // rr index reload
        std::vector<uint32_t> zeros(m_xdpKeys.size(), 0);
        if(bpf_map_update_batch(m_rrIndexMapFd, m_xdpKeys.data(), zeros.data(), &serviceCount,&opts) != 0) {
            return std::format("failed to update rr index on config: {}", strerror(errno));
        }

        // wrr index reload
        if(bpf_map_delete_batch(m_wrrStateMapFd, NULL, NULL, NULL) != 0) {
            return std::format("failed to reload wrr index on config: {}", strerror(errno));
        }

        // clear sessions state map
        if(bpf_map_delete_batch(m_sessionStateMapFd, NULL, NULL, NULL) != 0) {
            return std::format("failed to clear session states on config: {}", strerror(errno));
        }

        // reset backend stats
        std::vector<xdp::PacketsData> zeroPercpuData(m_cpusNumber);
        std::ranges::fill(zeroPercpuData, xdp::PacketsData{});
        for (uint32_t backend_idx = 0; backend_idx < backendCount; backend_idx++) {
            int ret = bpf_map_update_elem(m_backendsStatsMapFd,
                                      &backend_idx,
                                      zeroPercpuData.data(),
                                      BPF_ANY);
            if (ret != 0) {
                return std::format("Failed to reset backend {} stats: {}", backend_idx, strerror(errno));
            }
        }

        // reset services stats
        for (const auto& key : m_xdpKeys) {
            int ret = bpf_map_update_elem(m_servicesStatsMapFd,
                                      &key,
                                      zeroPercpuData.data(),
                                      BPF_ANY);
            if (ret != 0) {
                return std::format("Failed to reset service stats: {}", strerror(errno));
            }
        }

        return std::nullopt;
    } else {
        return "invalid maps configuration";
    }
}

void manager::XdpDataplane::StopProgram() {
    if (m_xdpLink) {
        bpf_link__destroy(m_xdpLink);
    }
    if (m_xdpObject) {
        bpf_object__close(m_xdpObject);
    }
}

std::map<manager::xdp::Backend, manager::xdp::PacketsData> manager::XdpDataplane::GetBackendsMetrics() const {
    std::map<xdp::Backend, xdp::PacketsData> results;
    
    std::vector<xdp::PacketsData> percpu_stats(m_cpusNumber);
    
    for (uint32_t backend_idx = 0; backend_idx < m_xdpBackends.size(); backend_idx++) {
        int ret = bpf_map_lookup_elem(m_backendsStatsMapFd,
                                      &backend_idx,
                                      percpu_stats.data());
        if (ret != 0) {
            continue;
        }
        
        xdp::PacketsData stats{};
        
        for (const auto& cpu_stats : percpu_stats) {
            stats.total_packets += cpu_stats.total_packets;
            stats.total_bytes += cpu_stats.total_bytes;
            stats.connections += cpu_stats.connections;
            stats.tcp_syn_packets += cpu_stats.tcp_syn_packets;
            stats.prepared_packets += cpu_stats.prepared_packets;
        }
        
        results[m_xdpBackends[backend_idx]] = stats;
    }
    
    return results;
}

std::map<manager::xdp::ServiceKey, manager::xdp::PacketsData> manager::XdpDataplane::GetServicesMetrics() const {
    std::map<xdp::ServiceKey, xdp::PacketsData> results;
    
    std::vector<xdp::PacketsData> percpu_stats(m_cpusNumber);
    
    for (const auto& key: m_xdpKeys) {
        int ret = bpf_map_lookup_elem(m_servicesStatsMapFd,
                                      &key,
                                      percpu_stats.data());
        if (ret != 0) {
            continue;
        }
        
        xdp::PacketsData stats{};
        
        for (const auto& cpu_stats : percpu_stats) {
            stats.total_packets += cpu_stats.total_packets;
            stats.total_bytes += cpu_stats.total_bytes;
            stats.connections += cpu_stats.connections;
            stats.tcp_syn_packets += cpu_stats.tcp_syn_packets;
            stats.prepared_packets += cpu_stats.prepared_packets;
        }
        
        results[key] = stats;
    }
    
    return results;
}

// TODO: ip_address

std::map<metrics::BackendInfo, metrics::MetricsData> manager::XdpDataplane::GetBackendsCurrentMetrics() {
    auto backendsStats = GetBackendsMetrics();
    std::map<metrics::BackendInfo, metrics::MetricsData> result;

    for(const auto&[backend, stats]: backendsStats) {
        result[metrics::BackendInfo{.port=backend.port, .ip_version=backend.ip_version}] = metrics::MetricsData{
                .total_packets = stats.total_packets,
                .tcp_syn_packets = stats.tcp_syn_packets,
                .prepared_packets = stats.prepared_packets,
                .connections = stats.connections,
                .total_bytes = stats.total_bytes
            };
    }
    
    return result;
}

// TODO: ip_address and name
std::map<metrics::ServiceInfo, metrics::MetricsData> manager::XdpDataplane::GetServicesCurrentMetrics() {
    auto servicesStats = GetServicesMetrics();
    std::map<metrics::ServiceInfo, metrics::MetricsData> result;

    for(const auto&[service, stats]: servicesStats) {
        result[metrics::ServiceInfo{.port=service.port, .ip_version=service.ip_version}] = metrics::MetricsData{
                .total_packets = stats.total_packets,
                .tcp_syn_packets = stats.tcp_syn_packets,
                .prepared_packets = stats.prepared_packets,
                .connections = stats.connections,
                .total_bytes = stats.total_bytes
            };
    }
    
    return result;
}
