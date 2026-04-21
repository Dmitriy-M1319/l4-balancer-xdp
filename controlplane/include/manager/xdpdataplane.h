#pragma once

#include "baseconfig.h"
#include "idataplane.h"
#include "xdpstructs.h"
#include "metrics_data.h"
#include "consistent_hash.h"
#include <variant>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <map>

namespace blncr::manager {

class XdpDataplane : public IDataplane, public blncr::metrics::IMetricsProvider {
    bpf_object *m_xdpObject = nullptr;
    bpf_program *m_xdpProgram = nullptr;
    bpf_link *m_xdpLink= nullptr;

    bpf_map *m_backendsMapFirst = nullptr;
    bpf_map *m_servicesMapFirst = nullptr;
    int m_servicesMapFirstFd{};
    int m_backendsMapFirstFd{};

    bpf_map *m_backendsMapSecond = nullptr;
    bpf_map *m_servicesMapSecond = nullptr;
    int m_servicesMapSecondFd{};
    int m_backendsMapSecondFd{};

    bpf_map *m_atomicIndexMap = nullptr;
    int m_atomicIndexMapFd{};

    // rr/wrr balancer algorithms
    bpf_map *m_rrIndexMap = nullptr;
    int m_rrIndexMapFd{};

    bpf_map *m_sessionStateMap = nullptr;
    int m_sessionStateMapFd{};

    bpf_map * m_wrrStateMap = nullptr;
    int m_wrrStateMapFd{};

    // statistics
    bpf_map *m_backendsStatsMap = nullptr;
    int m_backendsStatsMapFd{};

    bpf_map *m_servicesStatsMap = nullptr;
    int m_servicesStatsMapFd{};

    // ch part
    bpf_map *m_chCurrLookupMap = nullptr;
    int m_chCurrLookupMapFd{};
 
    bpf_map *m_chPrevLookupMap = nullptr;
    int m_chPrevLookupMapFd{};
 
    bpf_map *m_chBackendsMap = nullptr;
    int m_chBackendsMapFd{};
 
    bpf_map *m_chConfigMap = nullptr;
    int m_chConfigMapFd{};

    bpf_map *m_lbConfigMap = nullptr;
    int m_lbConfigMapFd{};
    algorithm::ConsistentHashManager m_chManager;
 
 


    std::string m_progName;
    std::string m_progInterface;
    int m_interfaceIdx{};
    uint32_t m_xdpFlags{};

    bool m_isFirstRun = true;
    int m_cpusNumber = libbpf_num_possible_cpus();
    std::vector<xdp::Backend> m_xdpBackends;
    std::vector<xdp::ServiceKey> m_xdpKeys;
    std::vector<xdp::ServiceInfo> m_xdpServices;
    config::BaseConfig m_currConfig;

public:
    explicit XdpDataplane(const std::string& name, const std::string& iface);
    ~XdpDataplane();

    std::optional<std::string> RunProgram(const std::string& binName);
    std::optional<std::string> ReloadConfig(const config::BaseConfig&) override;

    std::map<metrics::BackendInfo, metrics::MetricsData> GetBackendsCurrentMetrics() override;
    std::map<metrics::ServiceInfo, metrics::MetricsData> GetServicesCurrentMetrics() override;

    std::map<xdp::Backend, xdp::PacketsData> GetBackendsMetrics() const;
    std::map<xdp::ServiceKey, xdp::PacketsData> GetServicesMetrics() const;

    void StopProgram();

    algorithm::ConsistentHashManager& getChManager() { return m_chManager; }
 
    void ChPeriodicMaintenance();
private:
    bool isValidBpfState() const noexcept;
    std::variant<bpf_map *, std::string> openBpfMap(std::string_view mapName);

    bool updateChBpfMaps(const xdp::ServiceKey& service_key,
                         const std::vector<xdp::Backend>& backends,
                         const std::vector<int32_t>& curr_lookup,
                         const std::vector<int32_t>& prev_lookup,
                         uint32_t hashring_size);
};

}