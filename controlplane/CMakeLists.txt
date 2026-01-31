cmake_minimum_required(VERSION 3.18)
project(l4-controlplane)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED true)

add_executable(${PROJECT_NAME} main.cpp)