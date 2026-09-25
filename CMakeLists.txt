cmake_minimum_required(VERSION 3.20)
project(cpptcpduplex VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 99)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(CPPTCPDUPLEX_BUILD_SHARED "Build shared library" OFF)
option(CPPTCPDUPLEX_BUILD_TESTS "Build unit and interop tests" ON)
option(CPPTCPDUPLEX_BUILD_EXAMPLES "Build examples" ON)
option(CPPTCPDUPLEX_BUILD_FUZZERS "Build libFuzzer targets (Clang)" OFF)
option(CPPTCPDUPLEX_ENABLE_INSTALL "Generate install / find_package rules" ON)
option(CPPTCPDUPLEX_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(CPPTCPDUPLEX_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# --- Sanitizers ----------------------------------------------------------------
function(cpptcpduplex_apply_sanitizers target)
  if(CPPTCPDUPLEX_ENABLE_ASAN)
    target_compile_options(${target} PRIVATE -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(${target} PRIVATE -fsanitize=address)
  endif()
  if(CPPTCPDUPLEX_ENABLE_UBSAN)
    target_compile_options(${target} PRIVATE -fsanitize=undefined -fno-omit-frame-pointer)
    target_link_options(${target} PRIVATE -fsanitize=undefined)
  endif()
endfunction()

# --- Vendored crypto -----------------------------------------------------------
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)

set(MBEDTLS_LOCAL "${CMAKE_CURRENT_SOURCE_DIR}/third_party/mbedtls-2.28.9")
if(NOT EXISTS "${MBEDTLS_LOCAL}/CMakeLists.txt")
  message(FATAL_ERROR "mbedtls not found at ${MBEDTLS_LOCAL}. Unpack mbedtls 2.28.x into third_party/.")
endif()
add_subdirectory(${MBEDTLS_LOCAL} ${CMAKE_BINARY_DIR}/mbedtls-build EXCLUDE_FROM_ALL)

# --- Library -------------------------------------------------------------------
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
  set_target_properties(cpptcpduplex PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
  )
else()
  add_library(cpptcpduplex STATIC ${CPPTCPDUPLEX_SOURCES})
endif()

add_library(cpptcpduplex::cpptcpduplex ALIAS cpptcpduplex)

target_include_directories(cpptcpduplex
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/monocypher
)

# BUILD_INTERFACE only so install(EXPORT) does not require exporting mbedtls.
target_link_libraries(cpptcpduplex PRIVATE $<BUILD_INTERFACE:mbedcrypto>)

if(WIN32)
  target_link_libraries(cpptcpduplex PUBLIC ws2_32)
  target_compile_definitions(cpptcpduplex PRIVATE _CRT_RAND_S WIN32_LEAN_AND_MEAN)
endif()

cpptcpduplex_apply_sanitizers(cpptcpduplex)

# --- Install / find_package ----------------------------------------------------
if(CPPTCPDUPLEX_ENABLE_INSTALL)
  install(TARGETS cpptcpduplex
    EXPORT cpptcpduplexTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  )

  # Ship the static crypto archive without exporting the mbedtls CMake target
  # (avoids INTERFACE_INCLUDE_DIRECTORIES source-tree errors).
  install(FILES $<TARGET_FILE:mbedcrypto>
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
  )

  install(DIRECTORY include/cpptcpduplex
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  )
  install(DIRECTORY ${MBEDTLS_LOCAL}/include/mbedtls
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  )
  if(EXISTS "${MBEDTLS_LOCAL}/include/psa")
    install(DIRECTORY ${MBEDTLS_LOCAL}/include/psa
      DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )
  endif()

  install(EXPORT cpptcpduplexTargets
    FILE cpptcpduplexTargets.cmake
    NAMESPACE cpptcpduplex::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cpptcpduplex
  )

  configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/cpptcpduplexConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/cpptcpduplexConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cpptcpduplex
  )

  write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/cpptcpduplexConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
  )

  install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/cpptcpduplexConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/cpptcpduplexConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cpptcpduplex
  )
endif()

# --- Tests ---------------------------------------------------------------------
if(CPPTCPDUPLEX_BUILD_TESTS)
  enable_testing()
  add_executable(cpptcpduplex_tests
    tests/test_main.cpp
    tests/test_protocol.cpp
    tests/test_conn.cpp
    tests/test_transfer.cpp
  )
  target_link_libraries(cpptcpduplex_tests PRIVATE cpptcpduplex)
  cpptcpduplex_apply_sanitizers(cpptcpduplex_tests)
  add_test(NAME cpptcpduplex_tests COMMAND cpptcpduplex_tests)

  add_executable(cpp_echo_server tests/interop/cpp_echo_server.cpp)
  target_link_libraries(cpp_echo_server PRIVATE cpptcpduplex)
  cpptcpduplex_apply_sanitizers(cpp_echo_server)

  add_executable(cpp_echo_client tests/interop/cpp_echo_client.cpp)
  target_link_libraries(cpp_echo_client PRIVATE cpptcpduplex)
  cpptcpduplex_apply_sanitizers(cpp_echo_client)
endif()

# --- Fuzzers (Clang + libFuzzer) -----------------------------------------------
if(CPPTCPDUPLEX_BUILD_FUZZERS)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "CPPTCPDUPLEX_BUILD_FUZZERS requires Clang")
  endif()
  add_executable(fuzz_protocol tests/fuzz/fuzz_protocol.cpp)
  target_link_libraries(fuzz_protocol PRIVATE cpptcpduplex)
  target_compile_options(fuzz_protocol PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
  target_link_options(fuzz_protocol PRIVATE -fsanitize=fuzzer,address,undefined)

  add_executable(fuzz_transfer_frame tests/fuzz/fuzz_transfer_frame.cpp)
  target_link_libraries(fuzz_transfer_frame PRIVATE cpptcpduplex)
  target_compile_options(fuzz_transfer_frame PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
  target_link_options(fuzz_transfer_frame PRIVATE -fsanitize=fuzzer,address,undefined)
endif()

# --- Examples ------------------------------------------------------------------
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
