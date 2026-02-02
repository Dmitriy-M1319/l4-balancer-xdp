cmake_minimum_required(VERSION 3.18)
project(l4-controlplane)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED true)

# TODO: Make over condition
add_subdirectory(tests)

find_package(nlohmann_json REQUIRED)

set(CONFIG_SOURCES src/config/jsonparser.cpp
    src/config/fileconfigloader.cpp)

set(MANAGER_SOURCES src/manager/configmanager.cpp)

set(SOURCES ${CONFIG_SOURCES} ${MANAGER_SOURCES})

set(CONFIG_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include/config)
set(MANAGER_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include/manager)

add_executable(${PROJECT_NAME} main.cpp ${SOURCES})
target_include_directories(${PROJECT_NAME} PRIVATE ${CONFIG_INCLUDES} ${MANAGER_INCLUDES})
target_link_libraries(${PROJECT_NAME} PRIVATE nlohmann_json::nlohmann_json)