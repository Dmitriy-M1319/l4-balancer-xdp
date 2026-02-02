#pragma once

#include "baseconfig.h"

namespace blncr::manager {

class IDataplane {
public:
    virtual void ReloadConfig(const config::BaseConfig&) = 0;
};
}