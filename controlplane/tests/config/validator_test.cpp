#include <gtest/gtest.h>
#include "validator.h"


TEST(IPValidatorTest, ValidIPv4Addresses) {
    std::string validIp{"10.0.0.1"};
    auto result = blncr::validators::IPValidator::checkIP(validIp);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result.value(), 4);
}

TEST(IPValidatorTest, ValidIPv6Addresses) {
    std::string validIp{"2000:51b::1"};
    auto result = blncr::validators::IPValidator::checkIP(validIp);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result.value(), 6);
}

TEST(IPValidatorTest, InvalidIPAddresses) {
    std::string invalidIp1{"10.0.01"};
    auto result = blncr::validators::IPValidator::checkIP(invalidIp1);
    ASSERT_FALSE(result.has_value());
    std::string invalidIp2{"2000:51b:1"};
    result = blncr::validators::IPValidator::checkIP(invalidIp2);
    ASSERT_FALSE(result.has_value());
}



TEST(ConfigValidatorTest, UniqueServiceNames) {
    blncr::config::BaseConfig validConf{.services={
        blncr::config::BalancerService{
            .name="srv1", 
            .vip="192.168.0.1", 
            .protocol="tcp", 
            .port=32001, 
            .type=blncr::config::BalancerType::RR
        },
        blncr::config::BalancerService{
            .name="srv2", 
            .vip="192.168.0.2", 
            .protocol="tcp", 
            .port=32001, 
            .type=blncr::config::BalancerType::RR
        }
    }};
    auto result = blncr::validators::ConfigValidator::Validate(validConf);
    ASSERT_FALSE(result.has_value());
}

TEST(ConfigValidatorTest, DuplicateServiceNames) {
    blncr::config::BaseConfig invalidConf{.services={
        blncr::config::BalancerService{
            .name="srv1", 
            .vip="192.168.0.1", 
            .protocol="tcp", 
            .port=32001, 
            .type=blncr::config::BalancerType::RR
        },
        blncr::config::BalancerService{
            .name="srv1", 
            .vip="192.168.0.2", 
            .protocol="tcp", 
            .port=32001, 
            .type=blncr::config::BalancerType::RR
        }
    }};
    auto result = blncr::validators::ConfigValidator::Validate(invalidConf);
    ASSERT_TRUE(result.has_value());
}

TEST(ConfigValidatorTest, EmptyServiceList) {
    blncr::config::BaseConfig emptyConf;
    auto result = blncr::validators::ConfigValidator::Validate(emptyConf);
    ASSERT_FALSE(result.has_value());
}



TEST(ConfigValidatorTest, ValidPorts) {
    blncr::config::BaseConfig validConf{.services={
        blncr::config::BalancerService{
            .name="srv1", 
            .vip="192.168.0.1", 
            .protocol="tcp", 
            .port=12001, 
            .type=blncr::config::BalancerType::RR
        },
        blncr::config::BalancerService{
            .name="srv2", 
            .vip="192.168.0.2", 
            .protocol="tcp", 
            .port=32244, 
            .type=blncr::config::BalancerType::RR
        }
    }};
    auto result = blncr::validators::ConfigValidator::Validate(validConf);
    ASSERT_FALSE(result.has_value());
}

TEST(ConfigValidatorTest, PortBoundaryValues) {
    blncr::config::BaseConfig validConf{.services={
        blncr::config::BalancerService{
            .name="srv1", 
            .vip="192.168.0.1", 
            .protocol="tcp", 
            .port=120010, 
            .type=blncr::config::BalancerType::RR
        },
        blncr::config::BalancerService{
            .name="srv2", 
            .vip="192.168.0.2", 
            .protocol="tcp", 
            .port=322440, 
            .type=blncr::config::BalancerType::RR
        }
    }};
    auto result = blncr::validators::ConfigValidator::Validate(validConf);
    ASSERT_TRUE(result.has_value());
}



TEST(ConfigValidatorTest, ValidVIP) {
    blncr::config::BaseConfig validConf{.services={
        blncr::config::BalancerService{
            .name="srv1", 
            .vip="192.168.0.1", 
            .protocol="tcp", 
            .port=12001, 
            .type=blncr::config::BalancerType::RR
        },
        blncr::config::BalancerService{
            .name="srv2", 
            .vip="192.168.0.2", 
            .protocol="tcp", 
            .port=32244, 
            .type=blncr::config::BalancerType::RR
        }
    }};
    auto result = blncr::validators::ConfigValidator::Validate(validConf);
    ASSERT_FALSE(result.has_value());
}

TEST(ConfigValidatorTest, InvalidVIP) {
    blncr::config::BaseConfig validConf{.services={
        blncr::config::BalancerService{
            .name="srv1", 
            .vip="192.168.0.1", 
            .protocol="tcp", 
            .port=12001, 
            .type=blncr::config::BalancerType::RR
        },
        blncr::config::BalancerService{
            .name="srv2", 
            .vip="2000:1::1p", 
            .protocol="tcp", 
            .port=32244, 
            .type=blncr::config::BalancerType::RR
        }
    }};
    auto result = blncr::validators::ConfigValidator::Validate(validConf);
    ASSERT_TRUE(result.has_value());
}



TEST(ConfigValidatorTest, ValidProtocols) {
      blncr::config::BaseConfig validConf{.services={
        blncr::config::BalancerService{
            .name="srv1", 
            .vip="192.168.0.1", 
            .protocol="TCP", 
            .port=12001, 
            .type=blncr::config::BalancerType::RR
        },
        blncr::config::BalancerService{
            .name="srv2", 
            .vip="192.168.0.2", 
            .protocol="uDp", 
            .port=32244, 
            .type=blncr::config::BalancerType::RR
        }
    }};
    auto result = blncr::validators::ConfigValidator::Validate(validConf);
    ASSERT_FALSE(result.has_value());
}

TEST(ConfigValidatorTest, InvalidProtocols) {
      blncr::config::BaseConfig validConf{.services={
        blncr::config::BalancerService{
            .name="srv1", 
            .vip="192.168.0.1", 
            .protocol="TcP", 
            .port=12001, 
            .type=blncr::config::BalancerType::RR
        },
        blncr::config::BalancerService{
            .name="srv2", 
            .vip="192.168.0.2", 
            .protocol="http", 
            .port=32244, 
            .type=blncr::config::BalancerType::RR
        }
    }};
    auto result = blncr::validators::ConfigValidator::Validate(validConf);
    ASSERT_TRUE(result.has_value());
}
