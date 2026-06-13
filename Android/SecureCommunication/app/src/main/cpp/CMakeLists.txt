cmake_minimum_required(VERSION 3.22.1)

project(securecommunication)

# Don't build Mbed TLS examples or tests
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)

add_subdirectory(mbedtls)

add_library(securecommunication SHARED
        encrypted-communication.cpp
)

target_link_libraries(securecommunication
        PRIVATE
        mbedcrypto
        android
        log
)