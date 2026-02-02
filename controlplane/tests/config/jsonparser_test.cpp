#include "baseconfig.h"
#include "jsonparser.h"
#include <gtest/gtest.h>


TEST(JsonBaseConfigParserTest, ParseEmptyConfig) {
    std::string conf{""};
    blncr::config::JsonBaseConfigParser parser{};
    auto result = parser.Parse(conf);
    ASSERT_TRUE(std::get<std::string>(result).find("invalid input") != std::string::npos);
}

TEST(JsonBaseConfigParserTest, ParseInvalidRootConfig) {
    std::string conf{R"({"knklnl": 1})"};
    blncr::config::JsonBaseConfigParser parser{};
    auto result = parser.Parse(conf);
    ASSERT_EQ(std::get<std::string>(result), "services field not found or is not an array of elements");
}

TEST(JsonBaseConfigParserTest, ParseInvalidServices) {
    std::string conf{R"({"services": 1})"};
    blncr::config::JsonBaseConfigParser parser{};
    auto result = parser.Parse(conf);
    ASSERT_EQ(std::get<std::string>(result), "services field not found or is not an array of elements");
}

TEST(JsonBaseConfigParserTest, ParseEmptyServices) {
    std::string conf{R"({"services": []})"};
    blncr::config::JsonBaseConfigParser parser{};
    auto result = parser.Parse(conf);
    blncr::config::BaseConfig expected{};
    ASSERT_EQ(std::get<blncr::config::BaseConfig>(result), expected);
}

TEST(JsonBaseConfigParserTest, ParseNotFullService) {
    std::string conf{R"(
        {
            "services": [
                {
                    "name": "srv1",
                    "proto": "tcp",
                    "port":  32001,
                    "balancer": "rr",
                    "reals": []
                }
            ]
        }
    )"};
    blncr::config::JsonBaseConfigParser parser{};
    auto result = parser.Parse(conf);
    ASSERT_EQ(std::get<std::string>(result), "vip not found in service");
}

TEST(JsonBaseConfigParserTest, ParseServiceWithEmptyReals) {
    std::string conf{R"(
        {
            "services": [
                {
                    "name": "srv1",
                    "vip": "192.168.0.1",
                    "protocol": "tcp",
                    "port":  32001,
                    "balancer": "rr",
                    "reals": []
                }
            ]
        }
    )"};
    blncr::config::JsonBaseConfigParser parser{};
    auto result = parser.Parse(conf);
    blncr::config::BaseConfig expected{.services={
        blncr::config::BalancerService{.name="srv1", .vip="192.168.0.1", .protocol="tcp", .port=32001, .type=blncr::config::BalancerType::RR}
    }};
    ASSERT_EQ(std::get<blncr::config::BaseConfig>(result), expected);
}

TEST(JsonBaseConfigParserTest, ParseNormalService) {
    std::string conf{R"(
        {
            "services": [
                {
                    "name": "srv1",
                    "vip": "192.168.0.1",
                    "protocol": "tcp",
                    "port":  32001,
                    "balancer": "rr",
                    "reals": [
                        {
                            "ip": "10.0.0.1"
                        },
                        {
                            "ip": "10.0.0.2"
                        }
                    ]
                }
            ]
        }
    )"};
    blncr::config::JsonBaseConfigParser parser{};
    auto result = parser.Parse(conf);

    auto reals = {blncr::config::BalancerReal{.ip="10.0.0.1"}, blncr::config::BalancerReal{.ip="10.0.0.2"}};
    blncr::config::BaseConfig expected{.services={
        blncr::config::BalancerService{.reals=reals, .name="srv1", .vip="192.168.0.1", .protocol="tcp", .port=32001, .type=blncr::config::BalancerType::RR}
    }};
    ASSERT_EQ(std::get<blncr::config::BaseConfig>(result), expected);
}

TEST(JsonBaseConfigParserTest, ParseNormalManyServices) {
    std::string conf{R"(
        {
            "services": [
                {
                    "name": "srv1",
                    "vip": "192.168.0.1",
                    "protocol": "tcp",
                    "port":  32001,
                    "balancer": "rr",
                    "reals": [
                        {
                            "ip": "10.0.0.1"
                        },
                        {
                            "ip": "10.0.0.2"
                        }
                    ]
                },
                {
                    "name": "srv1",
                    "vip": "192.168.0.1",
                    "protocol": "tcp",
                    "port":  32001,
                    "balancer": "rr",
                    "reals": [
                        {
                            "ip": "10.0.0.1"
                        },
                        {
                            "ip": "10.0.0.2"
                        }
                    ]
                }
            ]
        }
    )"};
    blncr::config::JsonBaseConfigParser parser{};
    auto result = parser.Parse(conf);

    auto reals = {blncr::config::BalancerReal{.ip="10.0.0.1"}, blncr::config::BalancerReal{.ip="10.0.0.2"}};
    auto service = blncr::config::BalancerService{
        .reals=reals,
        .name="srv1",
        .vip="192.168.0.1", 
        .protocol="tcp", 
        .port=32001, 
        .type=blncr::config::BalancerType::RR};
    blncr::config::BaseConfig expected{.services={
            service,
            service
        }
    };
    ASSERT_EQ(std::get<blncr::config::BaseConfig>(result), expected);
}

