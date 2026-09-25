# cpptcpduplex

**Repository:** [https://github.com/hdmain/cpptcpduplex](https://github.com/hdmain/cpptcpduplex)

Native **C++20** port of [tcpduplex](https://github.com/hdmain/tcpduplex): encrypted full-duplex messaging over TCP using **X25519 ECDH**, **AES-256-GCM**, length-prefixed records, and concurrent read/write loops.

Wire-compatible with the Go library:

- Go `tcpduplex` ↔ C++ `cpptcpduplex`
- C++ `cpptcpduplex` ↔ Go `tcpduplex`

This is **not** TLS and does **not** replace certificate-based authentication for the public internet.

## Requirements

- C++20 compiler (GCC 12+, Clang 15+, MSVC 2022+)
- CMake **3.20+**
- CMake builds vendored **mbedTLS 2.28** (AES-GCM, SHA-256, RNG) and **Monocypher** (X25519)

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
tests/                  Unit tests + Go↔C++ interop harness
examples/               simple, transfer, client, server
third_party/            mbedTLS 2.28, Monocypher
```

## Examples

```bash
./build/example_simple
./build/example_transfer
./build/example_server 127.0.0.1:9090
./build/example_client 127.0.0.1:9090
```

## Go ↔ C++ interop tests

Requires Go 1.22+ and network access to `github.com/hdmain/tcpduplex` (or a local `replace`).

```bash
cmake --build build --target cpp_echo_server cpp_echo_client
cd tests/interop/go_harness
go mod tidy
go run . ../../../build
```

## Testing

```bash
./build/cpptcpduplex_tests
# or
ctest --test-dir build --output-on-failure
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

## Upstream

Port of [https://github.com/hdmain/tcpduplex](https://github.com/hdmain/tcpduplex).
