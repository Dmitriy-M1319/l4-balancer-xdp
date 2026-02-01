#pragma once

#include <string>
namespace blncr::loader {

class ConfigLoader {
public:
    virtual std::string LoadConfig() = 0;
};

}