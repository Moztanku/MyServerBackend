cmake_minimum_required(VERSION 3.28)

project(MyServerBackend)

# C++

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS 
    "${CMAKE_CXX_FLAGS} -Wall -Wextra -pedantic -Wno-unused-parameter -Wno-unused-variable")

# OpenSSL

find_package(OpenSSL REQUIRED)

# Sources

file(GLOB_RECURSE SOURCES "src/*.cpp")
set(HEADERS ${CMAKE_SOURCE_DIR}/inc)

# Project

add_executable(${PROJECT_NAME})

target_sources(${PROJECT_NAME} PRIVATE ${SOURCES})
target_include_directories(${PROJECT_NAME} PRIVATE ${HEADERS})
target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::SSL OpenSSL::Crypto)