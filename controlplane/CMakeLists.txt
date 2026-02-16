cmake_minimum_required(VERSION 3.18)
project(l4-controlplane)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED true)

# TODO: Make over condition
add_subdirectory(tests)

find_package(nlohmann_json REQUIRED)
set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

find_package(Boost REQUIRED COMPONENTS program_options)

set(CONFIG_SOURCES src/config/jsonparser.cpp
    src/config/fileconfigloader.cpp
    src/config/validator.cpp)

set(MANAGER_SOURCES 
    src/manager/configmanager.cpp
    src/manager/xdpdataplane.cpp)

set(NETUTILS_SOURCES
    src/netutils/arp.cpp)

set(SOURCES ${CONFIG_SOURCES} ${MANAGER_SOURCES} ${NETUTILS_SOURCES})

set(CONFIG_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include/config)
set(MANAGER_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include/manager)
set(NETUTILS_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include/netutils)

add_executable(${PROJECT_NAME} main.cpp ${SOURCES})
target_include_directories(${PROJECT_NAME} PRIVATE 
    ${CONFIG_INCLUDES} 
    ${MANAGER_INCLUDES}
    ${NETUTILS_INCLUDES}
    ${LIBBPF_LIBRARIES})

target_link_libraries(${PROJECT_NAME} PRIVATE
    nlohmann_json::nlohmann_json 
    Boost::program_options
    ${LIBBPF_LIBRARIES} 
    elf)