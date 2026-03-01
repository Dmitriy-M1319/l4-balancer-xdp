#pragma once

#include "baseconfig.h"
#include "idataplane.h"
#include "xdpstructs.h"
#include "metrics_data.h"
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

    bpf_map *m_rrIndexMap = nullptr;
    int m_rrIndexMapFd{};

    bpf_map *m_sessionStateMap = nullptr;
    int m_sessionStateMapFd{};

    bpf_map * m_wrrStateMap = nullptr;
    int m_wrrStateMapFd{};

    bpf_map *m_backendsStatsMap = nullptr;
    int m_backendsStatsMapFd{};

    bpf_map *m_servicesStatsMap = nullptr;
    int m_servicesStatsMapFd{};


    std::string m_progName;
    std::string m_progInterface;
    int m_interfaceIdx{};

    bool m_isFirstRun = true;
    int m_cpusNumber = libbpf_num_possible_cpus();
    std::vector<xdp::Backend> m_xdpBackends;
    std::vector<xdp::ServiceKey> m_xdpKeys;
    std::vector<xdp::ServiceInfo> m_xdpServices;

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
private:
    bool isValidBpfState() const noexcept;
    std::variant<bpf_map *, std::string> openBpfMap(std::string_view mapName);
};

}