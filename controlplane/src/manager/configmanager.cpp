#include "configmanager.h"
#include "baseconfig.h"
#include <algorithm>
#include <format>
#include <optional>

using namespace blncr;

manager::ConfigManager::ConfigManager(std::shared_ptr<IDataplane> dataplane): m_dataplane(dataplane) {}

void manager::ConfigManager::LoadConfig(config::BaseConfig&& config) {
    m_currConfig.reset(new config::BaseConfig(std::move(config)));
    if (m_dataplane) {
        m_dataplane->ReloadConfig(*m_currConfig);
    }
}

bool manager::ConfigManager::Equal(const config::BaseConfig& conf) const {
    if(m_currConfig == nullptr) {
        return false;
    }
    return *m_currConfig == conf;
}

void manager::ConfigManager::AddService(const config::BalancerService& service) {
    if(m_currConfig) {
        auto srv = std::find_if(m_currConfig->services.cbegin(), m_currConfig->services.cend(), 
        [&rhs = service](const auto& s){
            return s.name == rhs.name;
        });

        if(srv == m_currConfig->services.end()) {
            m_currConfig->services.push_back(service);
            if (m_dataplane) {
                m_dataplane->ReloadConfig(*m_currConfig);
            }    
        }
    }
}

std::optional<std::string> manager::ConfigManager::SetRealState(const command::SetRealStateRequest& request) {
    if(!m_currConfig) {
        return "empty config";
    }
    auto srv = std::find_if(m_currConfig->services.begin(), m_currConfig->services.end(), 
    [&req = request](const auto& service){
        return service.name == req.serviceName;
    });

    if(srv == m_currConfig->services.end()) {
        return std::format("service with name {} not found", std::move(request.serviceName));
    }

    auto real = std::find_if(srv->reals.begin(), srv->reals.end(), 
    [&req = request](const auto& r){
        return r.ip == req.realIp;
    });

    if(real == srv->reals.end()) {
        return std::format("real {} not found", std::move(request.realIp));
    }

    real->enabled = request.enabled;
    if (m_dataplane) {
        m_dataplane->ReloadConfig(*m_currConfig);
    }
    return std::nullopt;
}
