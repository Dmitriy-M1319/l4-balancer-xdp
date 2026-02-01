#pragma once

#include "baseconfig.h"
#include <optional>
#include <string_view>

namespace blncr::config {

class BaseConfigParser {
public:
    virtual ~BaseConfigParser() = default;
    virtual std::optional<BaseConfig> Parse(const std::string&) = 0;
    virtual std::optional<BaseConfig> Parse(std::string_view) = 0;
};

} // blncr