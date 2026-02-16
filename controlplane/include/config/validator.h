#pragma once

#include "baseconfig.h"
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <regex>
#include <format>
#include <unordered_set>

namespace blncr {

namespace validators {

class IPValidator {
public:
    static const std::regex IPv4_REGEX;
    static const std::regex IPv6_REGEX;
    
    static std::optional<uint8_t> checkIP(const std::string& ip) {
        if (std::regex_match(ip, IPv4_REGEX)) {
            return 4;
        } else if (std::regex_match(ip, IPv6_REGEX)) {
            return 6;
        } else {
            return std::nullopt;
        }
    }
};

class ConfigValidator {
public:
    static std::optional<std::string> Validate(blncr::config::BaseConfig& conf) {

        std::unordered_set<std::string> names;
        names.reserve(conf.services.size());

        for (const auto& service : conf.services) {
            if (!names.emplace(service.name).second) {
                return std::format("dublicate service name: {}", service.name);
            }
        }

        for(auto& service: conf.services) {
            if(service.port <= 0 || service.port >= std::numeric_limits<uint16_t>::max()) {
                return std::format("invalid port value: {}", service.port);
            }

            auto ipVersion = IPValidator::checkIP(service.vip);
            if(ipVersion.has_value()) {
                service.ip_version = ipVersion.value();
            } else {
                return std::format("invalid VIP address for service: {}", service.vip);
            }

            if(service.protocol != "tcp" && service.protocol != "udp") {
                return std::format("invalid L4 layer protocol: {}", service.protocol);
            }

            for(auto& real: service.reals) {
                if(real.weight == 0) {
                    return std::format("invalid weight value for real: {}", real.weight);
                }
                auto ipVersion = IPValidator::checkIP(real.ip);
                if(ipVersion.has_value()) {
                    real.ip_version = ipVersion.value();
                } else {
                    return std::format("invalid IP address for real: {}", real.ip);
                }
            }

        }
        return std::nullopt;
    }
};


}
}