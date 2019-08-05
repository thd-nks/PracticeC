cmake_minimum_required(VERSION 3.14)
project(Server C)

set(CMAKE_C_STANDARD 99)

add_executable(Server main.c)

find_library(SOD_LIB libsodium.a)
if(NOT SOD_LIB)
    message(FATAL_ERROR "libsodium library not found")
endif()

target_link_libraries(Server libsodium.a)
