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
    
    m_backendsMapFirst = bpf_object__find_map_by_name(m_xdpObject, "backends_first");
    if(!m_backendsMapFirst) {
        if (m_xdpLink) {
            bpf_link__destroy(m_xdpLink);
        }
        if (m_xdpObject) {
            bpf_object__close(m_xdpObject);
        }
        return std::string{"failed to find map \"backends_first\""};
    }
    m_backendsMapFirstFd = bpf_map__fd(m_backendsMapFirst);

    m_backendsMapSecond = bpf_object__find_map_by_name(m_xdpObject, "backends_second");
    if(!m_backendsMapSecond) {
        if (m_xdpLink) {
            bpf_link__destroy(m_xdpLink);
        }
        if (m_xdpObject) {
            bpf_object__close(m_xdpObject);
        }
        return std::string{"failed to find map \"backends_second\""};
    }
    m_backendsMapSecondFd = bpf_map__fd(m_backendsMapSecond);

    m_servicesMapFirst = bpf_object__find_map_by_name(m_xdpObject, "services_first");
    if(!m_servicesMapFirst) {
        if (m_xdpLink) {
            bpf_link__destroy(m_xdpLink);
        }
        if (m_xdpObject) {
            bpf_object__close(m_xdpObject);
        }
        return std::string{"failed to find map \"services_first\""};
    }
    m_servicesMapFirstFd = bpf_map__fd(m_servicesMapFirst);

    m_servicesMapSecond = bpf_object__find_map_by_name(m_xdpObject, "services_second");
    if(!m_servicesMapSecond) {
        if (m_xdpLink) {
            bpf_link__destroy(m_xdpLink);
        }
        if (m_xdpObject) {
            bpf_object__close(m_xdpObject);
        }
        return std::string{"failed to find map \"services_second\""};
    }
    m_servicesMapSecondFd = bpf_map__fd(m_servicesMapSecond);

    m_atomicIndexMap = bpf_object__find_map_by_name(m_xdpObject, "atomic_index");
    if(!m_atomicIndexMap) {
        if (m_xdpLink) {
            bpf_link__destroy(m_xdpLink);
        }
        if (m_xdpObject) {
            bpf_object__close(m_xdpObject);
        }
        return std::string{"failed to find map \"atomic_index\""};
    }
    m_atomicIndexMapFd = bpf_map__fd(m_atomicIndexMap);

    return std::nullopt;
}

bool manager::XdpDataplane::isValidBpfState() const noexcept {
    return m_backendsMapFirst && m_backendsMapSecond && m_atomicIndexMap && m_servicesMapFirst && m_servicesMapSecond;
}

// TODO: Error handling
void manager::XdpDataplane::ReloadConfig(const config::BaseConfig& config) {
    if(isValidBpfState()) {

        // TODO: отдельная функция (свободная, потестить)
        std::vector<xdp::Backend> xdpBackends;
        int currentBackendIdx = 0;
        std::vector<xdp::ServiceKey> xdpKeys(config.services.size());
        std::vector<xdp::ServiceInfo> xdpServices(config.services.size());

        for(const auto& service: config.services) {
            // 1. Key preparing
            struct in_addr addr;
            int result;
            result = inet_aton(service.vip.c_str(), &addr);
            if(result == 0) {
                return; // error
            }
            xdpKeys.emplace_back(addr.s_addr, service.port, (service.protocol == "tcp" ? IPPROTO_TCP : IPPROTO_UDP), 0);

            // 2. Balancers Preparing
            int count = 0;
            for(const auto& real: service.reals) {
                xdp::Backend back;

                struct in_addr addr;
                int result;
                result = inet_aton(real.ip.c_str(), &addr);
                if(result == 0) {
                    return; // error
                }
                back.ip = addr.s_addr;
                back.port = service.port;

                auto mac = netutils::Arp::Lookup(real.ip, m_progInterface);
                if(mac.has_value()) {
                    std::copy(mac->begin(), mac->end(), std::begin(back.mac));
                } else {
                    return; // error
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
                return; // error
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
            return; // error
        }

        __u32 serviceCount = static_cast<__u32>(xdpKeys.size());
        
        ret = bpf_map_update_batch(currServicesMapFd,
                                       xdpKeys.data(),
                                       xdpServices.data(),
                                       &serviceCount,
                                       &opts);
        if(ret != 0) {
            return; // error
        }
        
        // atomic index change
        int newIndex = 1 - currentIndex;
        if(bpf_map_update_elem(m_atomicIndexMapFd, &key, &newIndex, BPF_ANY) != 0) {
            return; // error
        }

        return;
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