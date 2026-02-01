#pragma once

#include "configloader.h"
#include <fstream>
namespace blncr::loader {

class FileConfigLoader : public ConfigLoader {
private:
    std::string m_filename;
    std::string m_buf;
    std::ifstream m_input;
public:
    FileConfigLoader(const std::string& filename);
    bool openFile();
    std::string LoadConfig() override;
    ~FileConfigLoader();
};

}