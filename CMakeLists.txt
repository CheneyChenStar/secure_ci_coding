cmake_minimum_required(VERSION 3.16)
project(SecureFileVault C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -D_XOPEN_SOURCE=700")

include_directories(${CMAKE_SOURCE_DIR}/include)

set(VULN_SOURCES
    src/main.c
    src/network.c
    src/auth.c
    src/session.c
    src/file_handler.c
    src/protocol.c
    src/config.c
    src/logger.c
)

# Vulnerable target
add_executable(securefile_server ${VULN_SOURCES})
target_compile_definitions(securefile_server PRIVATE VULNERABLE=1)
target_link_libraries(securefile_server pthread)

# Fixed target
add_executable(securefile_server_fixed ${VULN_SOURCES})
target_compile_definitions(securefile_server_fixed PRIVATE FIXED=1)
target_link_libraries(securefile_server_fixed pthread ssl crypto)
