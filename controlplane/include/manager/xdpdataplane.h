#pragma once

#include "idataplane.h"

namespace blncr::manager {

class XdpDataplane : public IDataplane {
public:
    void ReloadConfig(const config::BaseConfig&) override;
};

}