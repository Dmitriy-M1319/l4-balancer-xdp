#include "configmanager.h"
#include <gtest/gtest.h>

TEST(ConfigManagerTest, LoadConfig) {
    blncr::manager::ConfigManager manager;
    auto reals = {blncr::config::BalancerReal{.ip="10.0.0.1"}, blncr::config::BalancerReal{.ip="10.0.0.2"}};
    blncr::config::BaseConfig config{.services={
        blncr::config::BalancerService{.reals=reals, .name="srv1", .vip="192.168.0.1", .protocol="tcp", .port=32001, .type=blncr::config::BalancerType::RR}
    }};

    auto copy = config;
    manager.LoadConfig(std::move(copy));
    ASSERT_TRUE(manager.Equal(config));
}

TEST(ConfigManagerTest, AddNewOtherService) {
    blncr::manager::ConfigManager manager;
    auto reals = {blncr::config::BalancerReal{.ip="10.0.0.1"}, blncr::config::BalancerReal{.ip="10.0.0.2"}};
    blncr::config::BaseConfig config{.services={
        blncr::config::BalancerService{.reals=reals, .name="srv1", .vip="192.168.0.1", .protocol="tcp", .port=32001, .type=blncr::config::BalancerType::RR}
    }};

    auto copy = config;
    manager.LoadConfig(std::move(copy));
    ASSERT_TRUE(manager.Equal(config));

    auto newService = blncr::config::BalancerService{.reals=reals, .name="srv2", .vip="192.168.0.1", .protocol="tcp", .port=32001, .type=blncr::config::BalancerType::RR};
    config.services.push_back(newService);
    manager.AddService(newService);
    ASSERT_TRUE(manager.Equal(config));
}

TEST(ConfigManagerTest, AddServiceWithExistingName) {
    blncr::manager::ConfigManager manager;
    auto reals = {blncr::config::BalancerReal{.ip="10.0.0.1"}, blncr::config::BalancerReal{.ip="10.0.0.2"}};
    blncr::config::BaseConfig config{.services={
        blncr::config::BalancerService{.reals=reals, .name="srv1", .vip="192.168.0.1", .protocol="tcp", .port=32001, .type=blncr::config::BalancerType::RR}
    }};

    auto copy = config;
    manager.LoadConfig(std::move(copy));
    ASSERT_TRUE(manager.Equal(config));

    auto newService = blncr::config::BalancerService{.reals=reals, .name="srv1", .vip="192.168.0.1", .protocol="tcp", .port=32001, .type=blncr::config::BalancerType::RR};
    manager.AddService(newService);
    ASSERT_TRUE(manager.Equal(config));
}

TEST(ConfigManagerTest, SetExistingRealState) {
    blncr::manager::ConfigManager manager;
    auto reals = {blncr::config::BalancerReal{.ip="10.0.0.1"}, blncr::config::BalancerReal{.ip="10.0.0.2"}};
    blncr::config::BaseConfig config{.services={
        blncr::config::BalancerService{.reals=reals, .name="srv1", .vip="192.168.0.1", .protocol="tcp", .port=32001, .type=blncr::config::BalancerType::RR}
    }};

    auto copy = config;
    manager.LoadConfig(std::move(copy));
    ASSERT_TRUE(manager.Equal(config));

    blncr::command::SetRealStateRequest req{.serviceName="srv1", .realIp="10.0.0.1", .enabled=true};
    auto result = manager.SetRealState(req);
    ASSERT_FALSE(result.has_value());
}

TEST(ConfigManagerTest, SetRealStateWithInvalidService) {
    blncr::manager::ConfigManager manager;
    auto reals = {blncr::config::BalancerReal{.ip="10.0.0.1"}, blncr::config::BalancerReal{.ip="10.0.0.2"}};
    blncr::config::BaseConfig config{.services={
        blncr::config::BalancerService{.reals=reals, .name="srv1", .vip="192.168.0.1", .protocol="tcp", .port=32001, .type=blncr::config::BalancerType::RR}
    }};

    auto copy = config;
    manager.LoadConfig(std::move(copy));
    ASSERT_TRUE(manager.Equal(config));

    blncr::command::SetRealStateRequest req{.serviceName="sr1", .realIp="10.0.0.1", .enabled=true};
    auto result = manager.SetRealState(req);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result.value().find("service") != std::string::npos);
}

TEST(ConfigManagerTest, SetRealStateWithInvalidName) {
    blncr::manager::ConfigManager manager;
    auto reals = {blncr::config::BalancerReal{.ip="10.0.0.1"}, blncr::config::BalancerReal{.ip="10.0.0.2"}};
    blncr::config::BaseConfig config{.services={
        blncr::config::BalancerService{.reals=reals, .name="srv1", .vip="192.168.0.1", .protocol="tcp", .port=32001, .type=blncr::config::BalancerType::RR}
    }};

    auto copy = config;
    manager.LoadConfig(std::move(copy));
    ASSERT_TRUE(manager.Equal(config));

    blncr::command::SetRealStateRequest req{.serviceName="srv1", .realIp="10.0.0.5", .enabled=true};
    auto result = manager.SetRealState(req);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result.value().find("real") != std::string::npos);
}

TEST(ConfigManagerTest, SetRealStateInEmptyConfig) {
    blncr::manager::ConfigManager manager;
    blncr::command::SetRealStateRequest req{.serviceName="srv1", .realIp="10.0.0.5", .enabled=true};
    auto result = manager.SetRealState(req);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result.value().find("empty config") != std::string::npos);
}