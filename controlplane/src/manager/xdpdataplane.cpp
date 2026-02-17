#include "xdpdataplane.h"
#include "arp.h"
#include "xdpstructs.h"
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
        std::vector<xdp::Backend> xdpBackends;
        int currentBackendIdx = 0;
        std::vector<xdp::ServiceKey> xdpKeys(config.services.size());
        std::vector<xdp::ServiceInfo> xdpServices(config.services.size());

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

            xdpKeys.push_back(std::move(key));

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

                auto mac = netutils::Arp::Lookup(real.ip, m_progInterface);
                if(mac.has_value()) {
                    std::copy(mac->begin(), mac->end(), std::begin(back.mac));
                } else {
                     return std::format("failed to get MAC address for real IP {} ", real.ip);
                }
                back.active = static_cast<unsigned char>(real.enabled);
                xdpBackends.push_back(std::move(back));
                ++count;
            }

            // 3. Service Info Preparing
            xdp::ServiceInfo info;
            info.backend_start_idx = currentBackendIdx;
            info.backend_count = count;
            info.algorithm = static_cast<int>(service.type);
            xdpServices.push_back(std::move(info));
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
        std::vector<__u32> backendKeys(xdpBackends.size());
        for (size_t i = 0; i < backendKeys.size(); i++) {
            backendKeys[i] = static_cast<__u32>(i);
        }

        __u32 backendCount = static_cast<__u32>(xdpBackends.size());
        bpf_map_batch_opts opts;
        opts.flags = BPF_ANY; 
        int ret = bpf_map_update_batch(currBackendMapFd, 
                                       backendKeys.data(), 
                                       xdpBackends.data(),
                                       &backendCount, 
                                       &opts);
        if(ret != 0) {
            return std::format("failed to update batch of backends: {}", strerror(errno));
        }

        __u32 serviceCount = static_cast<__u32>(xdpKeys.size());
        
        ret = bpf_map_update_batch(currServicesMapFd,
                                       xdpKeys.data(),
                                       xdpServices.data(),
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
        std::vector<uint32_t> zeros(xdpKeys.size(), 0);
        if(bpf_map_update_batch(m_rrIndexMapFd, xdpKeys.data(), zeros.data(), &serviceCount,&opts) != 0) {
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

// // Ключ: комбинация VIP + protocol + port
// struct service_key {
//     __u32 vip;        // Virtual IP
//     __u16 port;       // Virtual Port
//     __u8 protocol;    // IPPROTO_TCP или IPPROTO_UDP
//     __u8 _pad;        // Выравнивание
// };

// // Значение: конфигурация сервиса
// struct service_info {
//     __u32 backend_count;     // Количество активных backends
//     __u32 backend_start_idx; // Индекс первого backend в массиве backends
//     __u8 algorithm;          // 0=round-robin, 1=consistent-hash, etc
//     __u8 _pad[3];
// };

// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 256);  // До 256 сервисов
//     __type(key, struct service_key);
//     __type(value, struct service_info);
// } services_first SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 256);  // До 256 сервисов
//     __type(key, struct service_key);
//     __type(value, struct service_info);
// } services_second SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_ARRAY);
//     __uint(max_entries, 1);
//     __type(key, __u32);
//     __type(value, __u64); // Указатель на map_fd
// } atomic_index SEC(".maps");

// Структура backend сервера
// struct backend {
//     __u32 ip;                // Real server IP
//     __u16 port;              // Real server port (если отличается от VIP port)
//     unsigned char mac[6];    // MAC адрес backend
//     __u8 active;             // 1=активен, 0=отключен
//     __u8 weight;             // Вес для weighted round-robin (опционально)
// };

// struct {
//     __uint(type, BPF_MAP_TYPE_ARRAY);
//     __uint(max_entries, 1024);  // До 1024 backend серверов всего
//     __type(key, __u32);         // Глобальный индекс backend
//     __type(value, struct backend);
// } backends SEC(".maps");