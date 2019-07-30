cmake_minimum_required(VERSION 3.14)
project(Server C)

set(CMAKE_C_STANDARD 99)

add_executable(Server main.c)

target_link_libraries(Server libsodium.a)