cmake_minimum_required(VERSION 3.10)
project(l4-controlplane)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED true)

option(L4_BUILD_TESTS "Build unit tests" ON)
if(L4_BUILD_TESTS)
    add_subdirectory(tests)
endif()

find_package(nlohmann_json REQUIRED)
set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

find_package(Boost REQUIRED COMPONENTS program_options)
find_package(opentelemetry-cpp CONFIG REQUIRED)
find_package(Prometheus-cpp REQUIRED)
find_package(gRPC CONFIG REQUIRED)


include_directories(SYSTEM ${Boost_INCLUDE_DIRS})

set(CONFIG_SOURCES src/config/jsonparser.cpp
    src/config/fileconfigloader.cpp
    src/config/validator.cpp)

set(MANAGER_SOURCES 
    src/manager/configmanager.cpp
    src/manager/xdpdataplane.cpp)

set(NETUTILS_SOURCES
    src/netutils/arp.cpp
    src/netutils/ndp.cpp)

set(METRICS_SOURCES
    src/metrics/metrics_server.cpp)

set(GRPC_SERVER_SOURCES
    api/controlplane-api.grpc.pb.cc
    api/controlplane-api.pb.cc
    src/server/grpc_server.cpp)

set(ALGORITHM_SOURCES
    src/algorithm/consistent_hash.cpp
    src/algorithm/xxhash.cpp)

set(SOURCES ${CONFIG_SOURCES} ${MANAGER_SOURCES} ${NETUTILS_SOURCES} ${METRICS_SOURCES} ${GRPC_SERVER_SOURCES} ${ALGORITHM_SOURCES})

set(CONFIG_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include/config)
set(MANAGER_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include/manager)
set(NETUTILS_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include/netutils)
set(METRICS_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include/metrics)
set(GRPC_SERVER_API_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR})
set(GRPC_SERVER_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include/server)
set(ALGORITHM_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include/algorithm)

add_executable(${PROJECT_NAME} main.cpp ${SOURCES})
target_include_directories(${PROJECT_NAME} PRIVATE 
    ${CONFIG_INCLUDES} 
    ${MANAGER_INCLUDES}
    ${NETUTILS_INCLUDES}
    ${LIBBPF_LIBRARIES}
    ${METRICS_INCLUDES}
    ${GRPC_SERVER_INCLUDES}
    ${GRPC_SERVER_API_INCLUDES}
    ${ALGORITHM_INCLUDES})

target_link_libraries(${PROJECT_NAME} PRIVATE
    nlohmann_json::nlohmann_json 
    Boost::program_options
    ${LIBBPF_LIBRARIES}
    opentelemetry-cpp::api
    opentelemetry-cpp::sdk
    prometheus-cpp::core
    prometheus-cpp::pull
    opentelemetry-cpp::prometheus_exporter
    elf
    gRPC::grpc++ gRPC::grpc gRPC::gpr)

target_compile_options(${PROJECT_NAME} PUBLIC -fsanitize=address)
target_link_options(${PROJECT_NAME} PUBLIC -fsanitize=address)

