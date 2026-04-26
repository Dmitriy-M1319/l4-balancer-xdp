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
								bool enabled = real.value("enabled", true);
							reals.push_back(std::move(BalancerReal{.ip=ip, .enabled=enabled, .weight=weight, .port=port}));
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

			// check on ddos configuration
			auto ddos = jdata["ddos_config"];
			if (!ddos.is_null()) {
				DDoSConfig conf;
				if (!ddos.contains("syn_threshold")) {
					return "syn_threshold not found in ddos_config";
				}

				if (!ddos.contains("syn_ack_ratio")) {
					return "syn_ack_ratio not found in ddos_config";
				}

				if (!ddos.contains("global_syn_threshold")) {
					return "global_syn_threshold not found in ddos_config";
				}

				if (!ddos.contains("ban_duration_ms")) {
					return "ban_duration_ms not found in ddos_config";
				}

				conf.syn_threshold = ddos["syn_threshold"].get<unsigned int>();
				conf.syn_ack_ratio = ddos["syn_ack_ratio"].get<unsigned int>();
				conf.global_syn_threshold = ddos["global_syn_threshold"].get<unsigned int>();
				conf.ban_duration_ms = ddos["ban_duration_ms"].get<unsigned int>();
				config.ddosConf = conf;
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