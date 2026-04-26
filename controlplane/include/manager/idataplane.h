#pragma once

#include "baseconfig.h"
#include <optional>
#include <map>

namespace blncr::manager {

class IDataplane {
public:
    virtual std::optional<std::string> ReloadConfig(const config::BaseConfig&) = 0;
    virtual std::map<std::string, unsigned long> GetBlackList() const = 0;
};
}