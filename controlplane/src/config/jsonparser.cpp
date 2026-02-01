#include "jsonparser.h"
#include "baseconfig.h"
#include <cstdint>
#include <nlohmann/json.hpp>

using namespace blncr::config;
using json = nlohmann::json;

std::optional<BaseConfig> JsonBaseConfigParser::Parse(const std::string& data) {
    BaseConfig config;

    json jdata = json::parse(data);
    if(!jdata.empty()) {
        auto services = jdata["services"];
        if(services.is_array()) {
            for(const auto& service: services) {
                if(!service.contains("vip")) {
                    return std::nullopt;
                }
                if(!service.contains("protocol")) {
                    return std::nullopt;
                }
                if(!service.contains("port")) {
                    return std::nullopt;
                }
                auto vip = service["vip"].get<std::string>();
                auto protocol = service["vip"].get<std::string>();
                auto port = service["port"].get<uint32_t>();

                std::vector<BalancerReal> reals;

                if(service.contains("reals")) {
                    if(service["reals"].is_array()) {
                        for(const auto& real: service["reals"]) {
                            auto ip = real["ip"].get<std::string>();
                            reals.push_back(std::move(BalancerReal{ip, false}));
                        }
                    }
                }

                BalancerService srv{std::move(reals), vip, protocol, port};
                config.services.push_back(std::move(srv));
            }
        } else {
            return std::nullopt; // TODO: Move from std::optional to std::variant
        }
    }

    return config;
}

std::optional<BaseConfig> JsonBaseConfigParser::Parse(std::string_view data) {
    BaseConfig config;

    json jdata = json::parse(data);
    if(!jdata.empty()) {
        auto services = jdata["services"];
        if(services.is_array()) {
            for(const auto& service: services) {
                if(!service.contains("vip")) {
                    return std::nullopt;
                }
                if(!service.contains("protocol")) {
                    return std::nullopt;
                }
                if(!service.contains("port")) {
                    return std::nullopt;
                }
                auto vip = service["vip"].get<std::string>();
                auto protocol = service["vip"].get<std::string>();
                auto port = service["port"].get<uint32_t>();

                std::vector<BalancerReal> reals;

                if(service.contains("reals")) {
                    if(service["reals"].is_array()) {
                        for(const auto& real: service["reals"]) {
                            auto ip = real["ip"].get<std::string>();
                            reals.push_back(std::move(BalancerReal{ip, false}));
                        }
                    }
                }

                BalancerService srv{std::move(reals), vip, protocol, port};
                config.services.push_back(std::move(srv));
            }
        } else {
            return std::nullopt; // TODO: Move from std::optional to std::variant
        }
    }

    return config;
}