#include "baseconfig.h"
#include "baseconfigparser.h"
#include "configloader.h"
#include "configmanager.h"
#include "fileconfigloader.h"
#include "idataplane.h"
#include "jsonparser.h"
#include "xdpdataplane.h"
#include <iostream>
#include <boost/program_options.hpp>
#include <memory>
#include <variant>

namespace po = boost::program_options;

int main(int argc, char *argv[]) {
    po::options_description desc("usage: l4-controlplane <option>");
    desc.add_options()
        ("help", "produce help message")
        ("config-file", po::value<std::string>(), "set configuration file")
        ("format", po::value<std::string>(), "set configuration format (json, etc)")
    ;

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);    

    if (vm.count("help")) {
        std::cout << desc << "\n";
        return 1;
    }

    // Dependencies
    std::unique_ptr<blncr::loader::ConfigLoader> configLoader;
    std::unique_ptr<blncr::config::BaseConfigParser> configParser;
    std::unique_ptr<blncr::manager::ConfigManager> manager;
    std::shared_ptr<blncr::manager::IDataplane> dataplane;

    if (vm.count("config-file")) {
        std::cout << "Configuration file was set to " << vm["config-file"].as<std::string>() << ".\n";
        auto loader = std::make_unique<blncr::loader::FileConfigLoader>(vm["config-file"].as<std::string>());
        bool success = loader->openFile();
        if(!success) {
            std::cout << "Can not open file " << vm["config-file"].as<std::string>() << std::endl;
            return 1;
        }

        configLoader = std::move(loader);
    } else {
        std::cout << "Configuration file was not set.\n";
        return 1;
    }

    if (vm.count("format")) {
        std::cout << "Configuration format was set to " << vm["format"].as<std::string>() << ".\n";
        std::string format = vm["format"].as<std::string>();
        if(format == "json") {
            configParser = std::make_unique<blncr::config::JsonBaseConfigParser>();
        } else {
            std::cout << "Invalid configuration file format" << std::endl;
            return 1;
        }
    } else {
        std::cout << "Configuration format was not set.\n";
        return 1;
    }

    dataplane = std::make_shared<blncr::manager::XdpDataplane>("xdp-prog", "eth0"); // TODO: заглушки на названиях
    manager = std::make_unique<blncr::manager::ConfigManager>(dataplane);

    std::string data = configLoader->LoadConfig();
    if(data.empty()) {
        std::cout << "Can not load config for services" << std::endl;
        return -1;
    }

    auto config = configParser->Parse(data);
    if(const std::string *error = std::get_if<std::string>(&config)) {
        std::cout << "Error to parse config: " << *error << std::endl;
        return 1;
    }

    blncr::config::BaseConfig conf = std::get<blncr::config::BaseConfig>(config);
    manager->LoadConfig(std::move(conf));
    std::cout << "Manager loads config successfully" << std::endl;
    return 0;
}