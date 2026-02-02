#pragma once

/*
 --- Balancer Config (for MVP)
 service [
    {
        vip: 192.168.0.1,
        protocol: tcp,
        port: 8501,
        reals: [
            192.168.0.2,
            192.168.0.3,
            192.168.0.4 // Same port config (MVP)
        ],
        balancer: rr (wrr, ch (only for TCP, another exception))
    },
    ...
 ]

*/

#include "baseconfigparser.h"
#include <string>

namespace blncr::config {

class JsonBaseConfigParser : public BaseConfigParser{
public:
    std::variant<BaseConfig, std::string> Parse(const std::string&) override;
};
}