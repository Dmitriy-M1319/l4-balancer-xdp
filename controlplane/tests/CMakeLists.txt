cmake_minimum_required(VERSION 3.18)
project(l4-tests)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
FetchContent_MakeAvailable(googletest)

enable_testing()
set(EXTERNAL_SOURCES 
  ${CMAKE_CURRENT_SOURCE_DIR}/../src/config/fileconfigloader.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../src/config/jsonparser.cpp)
set(EXTERNAL_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/../include/config)
set(CONFIG_TESTS 
  config/fileconfigloader_test.cpp
  config/jsonparser_test.cpp)

add_executable(
    ${PROJECT_NAME}
    ${CONFIG_TESTS}
    ${EXTERNAL_SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE ${EXTERNAL_HEADERS})
target_link_libraries(${PROJECT_NAME} GTest::gtest GTest::gtest_main)
include(GoogleTest)
gtest_discover_tests(${PROJECT_NAME})