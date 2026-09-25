cmake_minimum_required(VERSION 3.20)
project(cpptcpduplex VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 99)

option(CPPTCPDUPLEX_BUILD_SHARED "Build shared library" OFF)
option(CPPTCPDUPLEX_BUILD_TESTS "Build unit and interop tests" ON)
option(CPPTCPDUPLEX_BUILD_EXAMPLES "Build examples" ON)

set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)

set(MBEDTLS_LOCAL "${CMAKE_CURRENT_SOURCE_DIR}/third_party/mbedtls-2.28.9")
if(NOT EXISTS "${MBEDTLS_LOCAL}/CMakeLists.txt")
  message(FATAL_ERROR "mbedtls not found at ${MBEDTLS_LOCAL}. Unpack mbedtls 2.28.x into third_party/.")
endif()
add_subdirectory(${MBEDTLS_LOCAL} ${CMAKE_BINARY_DIR}/mbedtls-build EXCLUDE_FROM_ALL)

set(CPPTCPDUPLEX_SOURCES
  src/errors.cpp
  src/config.cpp
  src/fingerprint.cpp
  src/conn.cpp
  src/dial.cpp
  src/server.cpp
  src/detail/socket.cpp
  src/protocol/protocol.cpp
  src/crypto/session.cpp
  src/crypto/handshake.cpp
  src/crypto/x25519.cpp
  src/transfer/transfer.cpp
  third_party/monocypher/monocypher.c
)

if(CPPTCPDUPLEX_BUILD_SHARED)
  add_library(cpptcpduplex SHARED ${CPPTCPDUPLEX_SOURCES})
  target_compile_definitions(cpptcpduplex PUBLIC CPPTCPDUPLEX_SHARED)
else()
  add_library(cpptcpduplex STATIC ${CPPTCPDUPLEX_SOURCES})
endif()

add_library(cpptcpduplex::cpptcpduplex ALIAS cpptcpduplex)

target_include_directories(cpptcpduplex
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/monocypher
)

target_link_libraries(cpptcpduplex PRIVATE mbedtls mbedx509 mbedcrypto)

if(WIN32)
  target_link_libraries(cpptcpduplex PUBLIC ws2_32)
  target_compile_definitions(cpptcpduplex PRIVATE _CRT_RAND_S WIN32_LEAN_AND_MEAN)
endif()

# Consumers need mbedtls include path only transitively for our headers — we keep
# crypto internals private. Export a simple config without vendored mbedtls targets.
set(CPPTCPDUPLEX_INSTALL OFF CACHE BOOL "Install library and headers")
if(CPPTCPDUPLEX_INSTALL)
  include(GNUInstallDirs)
  install(TARGETS cpptcpduplex
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  )
  install(DIRECTORY include/cpptcpduplex DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
endif()

if(CPPTCPDUPLEX_BUILD_TESTS)
  enable_testing()
  add_executable(cpptcpduplex_tests
    tests/test_main.cpp
    tests/test_protocol.cpp
    tests/test_conn.cpp
    tests/test_transfer.cpp
  )
  target_link_libraries(cpptcpduplex_tests PRIVATE cpptcpduplex)
  add_test(NAME cpptcpduplex_tests COMMAND cpptcpduplex_tests)

  add_executable(cpp_echo_server tests/interop/cpp_echo_server.cpp)
  target_link_libraries(cpp_echo_server PRIVATE cpptcpduplex)

  add_executable(cpp_echo_client tests/interop/cpp_echo_client.cpp)
  target_link_libraries(cpp_echo_client PRIVATE cpptcpduplex)
endif()

if(CPPTCPDUPLEX_BUILD_EXAMPLES)
  add_executable(example_simple examples/simple/main.cpp)
  target_link_libraries(example_simple PRIVATE cpptcpduplex)

  add_executable(example_transfer examples/transfer/main.cpp)
  target_link_libraries(example_transfer PRIVATE cpptcpduplex)

  add_executable(example_server examples/server/main.cpp)
  target_link_libraries(example_server PRIVATE cpptcpduplex)

  add_executable(example_client examples/client/main.cpp)
  target_link_libraries(example_client PRIVATE cpptcpduplex)
endif()
