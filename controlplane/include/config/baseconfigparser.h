#pragma once

#include "baseconfig.h"
#include <variant>

namespace blncr::config {

class BaseConfigParser {
public:
    virtual ~BaseConfigParser() = default;
    virtual std::variant<BaseConfig, std::string> Parse(const std::string&) = 0;
};

} // blncr