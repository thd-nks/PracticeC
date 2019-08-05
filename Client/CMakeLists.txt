cmake_minimum_required(VERSION 3.14)
project(Client C)

set(CMAKE_C_STANDARD 99)

find_library(SOD_LIB libsodium.a)
if(NOT SOD_LIB)
    message(FATAL_ERROR "libsodium library not found")
endif()

add_executable(Client main.c)

target_link_libraries(Client libsodium.a)
