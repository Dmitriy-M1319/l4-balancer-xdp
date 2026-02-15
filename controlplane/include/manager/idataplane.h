#pragma once

#include "baseconfig.h"
#include <optional>

namespace blncr::manager {

class IDataplane {
public:
    virtual std::optional<std::string> ReloadConfig(const config::BaseConfig&) = 0;
};
}