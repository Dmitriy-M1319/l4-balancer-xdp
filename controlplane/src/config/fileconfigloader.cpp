#include "fileconfigloader.h"

using namespace blncr::loader;

FileConfigLoader::FileConfigLoader(const std::string& filename): m_filename{filename}, m_input{} {}

bool FileConfigLoader::openFile() {
    m_input.open(m_filename);
    return m_input.is_open();
}

std::string FileConfigLoader::LoadConfig() {
    if(m_input.is_open()) {
        if(!m_buf.empty())
            m_buf.clear();

        std::string line{};
        while(std::getline(m_input, line)) {
            m_buf += line;
        }
        return m_buf;
    }
    return std::string{};
}

FileConfigLoader::~FileConfigLoader() {
    if(m_input.is_open()) {
        m_input.close();
    }
}

