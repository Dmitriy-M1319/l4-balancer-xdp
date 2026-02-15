#include "jsonparser.h"
#include "baseconfig.h"
#include <cstdint>
#include <nlohmann/json.hpp>
#include <format>

using namespace blncr::config;
using json = nlohmann::json;

std::variant<BaseConfig, std::string> JsonBaseConfigParser::Parse(const std::string& data)
{
	try {
        BaseConfig config;
		json jdata = json::parse(data);
		if (!jdata.empty()) {
			auto services = jdata["services"];
			if (!services.is_null() && services.is_array()) {
				for (const auto& service : services) {
					if (!service.contains("name")) {
						return "name not found in service";
					}

					if (!service.contains("vip")) {
						return "vip not found in service";
					}

					if (!service.contains("protocol")) {
						return "protocol not found in service";
					}

					if (!service.contains("port")) {
						return "port not found in service";
					}

					if (!service.contains("balancer")) {
						return "balancer type not found in service";
					}

					auto name = service["name"].get<std::string>();
					auto vip = service["vip"].get<std::string>();
					auto protocol = service["protocol"].get<std::string>();
					auto port = service["port"].get<uint32_t>();

					auto type_str = service["balancer"].get<std::string>();
					auto balancer_type = fromString(type_str);
					if(!balancer_type.has_value()) {
						return "invalid balancer type";
					}

					std::vector<BalancerReal> reals;

					if (service.contains("reals")) {
						if (service["reals"].is_array()) {
							for (const auto& real : service["reals"]) {
								auto ip = real["ip"].get<std::string>();
								auto weight = real["weight"].get<uint8_t>();
								reals.push_back(std::move(BalancerReal{ip, false, weight}));
							}
						}
					}
					else {
						return "reals field not found in service or is not an array of elems";
					}

					BalancerService srv{std::move(reals), name, vip, protocol, port, balancer_type.value()};
					config.services.push_back(std::move(srv));
				}
			}
			else {
				return "services field not found or is not an array of elements";
			}
			return config;
		}
		else {
			return "empty config";
		}
	} catch(const json::parse_error& err) {
		auto err_str =  err.what();
        return std::format("invalid input: {}", err_str);
    }
}