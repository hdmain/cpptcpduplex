# cpptcpduplex

[![CI](https://github.com/hdmain/cpptcpduplex/actions/workflows/ci.yml/badge.svg)](https://github.com/hdmain/cpptcpduplex/actions/workflows/ci.yml)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.cppreference.com/w/cpp/20)
[![License](https://img.shields.io/badge/license-see%20LICENSE.md-lightgrey.svg)](LICENSE.md)
[![Release](https://img.shields.io/github/v/release/hdmain/cpptcpduplex?include_prereleases)](https://github.com/hdmain/cpptcpduplex/releases)

**Repository:** [https://github.com/hdmain/cpptcpduplex](https://github.com/hdmain/cpptcpduplex)

Native **C++20** port of [tcpduplex](https://github.com/hdmain/tcpduplex): encrypted full-duplex messaging over TCP using **X25519 ECDH**, **AES-256-GCM**, length-prefixed records, and concurrent read/write loops.

Wire-compatible with the Go library:

- Go `tcpduplex` ↔ C++ `cpptcpduplex`
- C++ `cpptcpduplex` ↔ Go `tcpduplex`

This is **not** TLS and does **not** replace certificate-based authentication for the public internet.

## Versioning

This project uses [Semantic Versioning](https://semver.org/). Releases are tagged as `vMAJOR.MINOR.PATCH` (see [Releases](https://github.com/hdmain/cpptcpduplex/releases) and [CHANGELOG.md](CHANGELOG.md)).

Current version: **1.0.0** (`project(cpptcpduplex VERSION 1.0.0)` in CMake).

## Requirements

- C++20 compiler (GCC 12+, Clang 15+, MSVC 2022+)
- CMake **3.20+**
- Vendored **mbedTLS 2.28** (AES-GCM, SHA-256, RNG) and **Monocypher** (X25519)

## Build

```bash
cmake -S . -B build -DCPPTCPDUPLEX_BUILD_SHARED=OFF
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Shared library:

```bash
cmake -S . -B build -DCPPTCPDUPLEX_BUILD_SHARED=ON
cmake --build build -j
```

### Windows (MinGW)

```powershell
cmake -S . -B build -G "MinGW Makefiles" -DCPPTCPDUPLEX_BUILD_SHARED=OFF
cmake --build build -j
.\build\cpptcpduplex_tests.exe
```

## Install & `find_package`

```bash
cmake -S . -B build -DCPPTCPDUPLEX_ENABLE_INSTALL=ON
cmake --build build -j
cmake --install build --prefix /usr/local   # or any prefix
```

Then from another project:

```cmake
cmake_minimum_required(VERSION 3.20)
project(app LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)

find_package(cpptcpduplex 1.0 REQUIRED CONFIG)
add_executable(app main.cpp)
target_link_libraries(app PRIVATE cpptcpduplex::cpptcpduplex)
```

```bash
cmake -S . -B build -DCMAKE_PREFIX_PATH=/usr/local
```

### Package managers

| Manager | Status |
|---------|--------|
| **CMake `find_package`** | Supported via exported `cpptcpduplexConfig.cmake` (see above). |
| **vcpkg** | Manifest stub: [`vcpkg.json`](vcpkg.json). Point an [overlay port](https://learn.microsoft.com/en-us/vcpkg/concepts/overlay-ports) at this repo (`vcpkg install` with `--overlay-ports`) or use `vcpkg install` after packaging the CMake install tree. Vendored mbedTLS means no extra crypto dependency. |
| **Conan** | Use a CMakeDeps consumer against an installed prefix, or package with Conan’s `CMakeToolchain` + `cmake --install`. A full Conan Center recipe is welcome via PR. |

## Features

- Duplex `Conn` with `send` / `receive`, bounded queues, max message size
- Optional `Config::on_message` callback path (`receive` disabled when set)
- Timeouts via `send_for` / `receive_for` / `shutdown(wait)`
- `Config`: dial/handshake timeouts, protocol version, queue depths, PSK + peer fingerprint hooks
- `Server`: `listen` + `serve` with per-connection handlers
- Encrypted resumable file transfer (`cpptcpduplex::transfer`)

## Quick start

```cpp
#include "cpptcpduplex/cpptcpduplex.hpp"
#include "cpptcpduplex/detail/socket.hpp"

using namespace cpptcpduplex;

std::error_code ec;
auto ln = detail::TcpListener::listen("127.0.0.1:9090", ec);
auto raw = ln->accept(ec);
auto srv = serve_conn(std::move(raw));

auto cli = dial("127.0.0.1:9090");
cli->send(std::span<const std::uint8_t>{/* ... */});
auto msg = cli->receive();
```

PSK example:

```cpp
Config cfg = default_config();
cfg.handshake.pre_shared_key.assign({'s','e','c','r','e','t'});
auto cli = dial(addr, &cfg);
```

## Wire format (compatible with Go tcpduplex)

1. **Handshake (plaintext):** magic `TDX1`, `uint16` BE protocol version, 32-byte X25519 public key. Client sends first; server replies with the same version and its public key.
2. **Records:** `uint32` BE length (includes 1-byte type + sealed blob), type byte (`MsgText`/`MsgPing`/`MsgPong`/`MsgClose`), then **nonce ‖ ciphertext ‖ tag** (AES-256-GCM, 12-byte nonce, 16-byte tag).
3. Session key: `SHA256(shared)` or `SHA256(shared ‖ 0x00 ‖ uint32_be(len(psk)) ‖ psk)`.

Transfer frames use magic `TFX1` inside `MsgText` (offer/accept/chunk/ack/done/abort), matching Go `transfer`.

## Project layout

```
include/cpptcpduplex/   Public headers
src/                    Library sources
tests/                  Unit tests, fuzzers, Go↔C++ interop
examples/               simple, transfer, client, server
cmake/                  find_package config package
third_party/            mbedTLS 2.28, Monocypher
.github/workflows/      CI, sanitizers, fuzz, interop
```

## Examples

```bash
./build/example_simple
./build/example_transfer
./build/example_server 127.0.0.1:9090
./build/example_client 127.0.0.1:9090
```

## Testing

```bash
./build/cpptcpduplex_tests
# or
ctest --test-dir build --output-on-failure
```

### Sanitizers

```bash
cmake -S . -B build-san \
  -DCPPTCPDUPLEX_ENABLE_ASAN=ON \
  -DCPPTCPDUPLEX_ENABLE_UBSAN=ON \
  -DCPPTCPDUPLEX_BUILD_EXAMPLES=OFF
cmake --build build-san -j
ctest --test-dir build-san --output-on-failure
```

### Fuzzing (Clang + libFuzzer)

Targets exercise the network-facing parsers (`uint32` BE record lengths, TFX1 frames):

```bash
cmake -S . -B build-fuzz \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DCPPTCPDUPLEX_BUILD_FUZZERS=ON \
  -DCPPTCPDUPLEX_BUILD_TESTS=OFF -DCPPTCPDUPLEX_BUILD_EXAMPLES=OFF
cmake --build build-fuzz -j
./build-fuzz/fuzz_protocol -max_total_time=60
./build-fuzz/fuzz_transfer_frame -max_total_time=60
```

### Go ↔ C++ interop

Requires Go 1.22+ and network access to `github.com/hdmain/tcpduplex`.

```bash
cmake --build build --target cpp_echo_server cpp_echo_client
cd tests/interop/go_harness
go mod tidy
go run . ../../../build
```

## Differences from the Go implementation

| Area | Notes |
|------|--------|
| Cancellation | C++ uses timeouts (`send_for` / `receive_for` / `shutdown(duration)`) instead of `context.Context`. |
| Errors | `std::error_code` + optional throwing helpers, instead of Go `error` values. |
| Crypto libs | mbedTLS + Monocypher instead of Go `crypto/*` (same algorithms and wire encoding). |
| Sockets | Native BSD/Winsock RAII wrappers (no Boost.Asio). |
| `OnMessage` | `std::function` on `Config` (same semantics: disables `receive`). |
| License | Upstream Go repo currently has **no LICENSE file**; this port does not invent one. Third-party code retains its own licenses (mbedTLS Apache-2.0, Monocypher CC0/BSD). |

## Security notes

- Symmetric keys derive from ECDH; with PSK, material is mixed on both sides—peers must agree.
- Fingerprint pinning checks the peer’s ephemeral X25519 public key from the handshake.
- Prefer TLS/QUIC for hostile networks; treat cpptcpduplex as a building block for controlled deployments.
- Frame parsers are covered by unit tests, ASan/UBSan CI, and libFuzzer smoke runs on protocol + transfer framing.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Upstream

Port of [https://github.com/hdmain/tcpduplex](https://github.com/hdmain/tcpduplex).
