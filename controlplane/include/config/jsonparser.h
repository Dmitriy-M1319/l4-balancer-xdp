#pragma once

/*
 --- Balancer Config (for MVP)
 service [
    {
        name: srv1,
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
 ],

 --- Optional DDoS Config
 ddos_config: {
    syn_threshold: 5,
    syn_ack_ratio: 500,       
    global_syn_threshold: 20,
    ban_duration_ms: 20000,
 }

*/

// TODO: Сделать валидатор конфига
// Проверка на корректные IP-адреса, что для каждого сервиса связка vip + dst port является уникальной

#include "baseconfigparser.h"
#include <string>

namespace blncr::config {

class JsonBaseConfigParser : public BaseConfigParser{
public:
    std::variant<BaseConfig, std::string> Parse(const std::string&) override;
};
}