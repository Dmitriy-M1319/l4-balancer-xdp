#pragma once

#include "baseconfig.h"
#include <memory>
#include <optional>

namespace blncr {

namespace command {

struct SetRealStateRequest {
    std::string serviceName;
    std::string realIp;
    bool enabled;
};

}

namespace manager {

class ConfigManager {
private:
    std::unique_ptr<config::BaseConfig> m_currConfig = nullptr;
public:
    ConfigManager() = default;
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;

    void LoadConfig(config::BaseConfig&&);
    bool Equal(const config::BaseConfig&) const;
    void AddService(const config::BalancerService&);
    std::optional<std::string> SetRealState(const command::SetRealStateRequest&); // TODO: RealState request
};

}
}