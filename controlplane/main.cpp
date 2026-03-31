#include "baseconfig.h"
#include "baseconfigparser.h"
#include "configloader.h"
#include "configmanager.h"
#include "fileconfigloader.h"
#include "grpc_server.h"
#include "jsonparser.h"
#include "metrics_server.h"
#include "validator.h"
#include "xdpdataplane.h"
#include <iostream>
#include <boost/program_options.hpp>
#include <memory>
#include <variant>
#include <thread>
#include <atomic>
#include <chrono>

// cmake ..    \
// -DCMAKE_BUILD_TYPE=Release       \
// -DOPENTELEMETRY_ABI_VERSION_NO=2     \
// -DCMAKE_INSTALL_PREFIX=/usr/     \
// -DBUILD_TESTING=OFF     \
// -DWITH_EXAMPLES=OFF \
// -DWITH_PROMETHEUS=ON \
// -DWITH_ABI_VERSION_2=ON \
// -DWITH_ABI_VERSION_1=OFF \
// -DWITH_OTLP_HTTP=ON \
// -DWITH_JAEGER=ON \
// -DWITH_OTLP_GRPC=ON

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
    std::shared_ptr<blncr::manager::ConfigManager> manager;
    std::shared_ptr<blncr::manager::XdpDataplane> dataplane;

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

    dataplane = std::make_shared<blncr::manager::XdpDataplane>("balancer_handler", "eth0"); // TODO: заглушки на названиях
    manager = std::make_shared<blncr::manager::ConfigManager>(dataplane);

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
    auto err = blncr::validators::ConfigValidator::Validate(conf);
    if(err.has_value()) {
        std::cout << "Failed to validate config: " << *err << std::endl;
        return 1;
    }
    
    manager->LoadConfig(std::move(conf));
    std::cout << "Manager loads config successfully" << std::endl;

    blncr::metrics::MetricsServer metricsServer(dataplane);
    metricsServer.Serve();

    blncr::server::GrpcServer apiServer;
    apiServer.init(manager);
    std::cout << "gRPC API Server started on " << blncr::server::GRPC_SERVER_ADDRESS << std::endl;

    std::atomic<bool> ch_running{true};
    std::thread ch_maintenance_thread([&dataplane, &ch_running]() {
        while (ch_running.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            dataplane->ChPeriodicMaintenance();
        }
    });

    metricsServer.Join();

    ch_running.store(false, std::memory_order_release);
    if (ch_maintenance_thread.joinable()) {
        ch_maintenance_thread.join();
    }
    return 0;
}