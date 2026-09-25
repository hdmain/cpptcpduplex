# Contributing

Thanks for your interest in improving **cpptcpduplex**.

## Development setup

Requirements: C++20 toolchain, CMake 3.20+, and (for interop tests) Go 1.22+.

```bash
cmake -S . -B build -DCPPTCPDUPLEX_BUILD_TESTS=ON -DCPPTCPDUPLEX_BUILD_EXAMPLES=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Sanitizers (Clang/GCC on Linux/macOS):

```bash
cmake -S . -B build-san \
  -DCPPTCPDUPLEX_ENABLE_ASAN=ON \
  -DCPPTCPDUPLEX_ENABLE_UBSAN=ON \
  -DCPPTCPDUPLEX_BUILD_EXAMPLES=OFF
cmake --build build-san -j
ctest --test-dir build-san --output-on-failure
```

Fuzzers (Clang + libFuzzer):

```bash
cmake -S . -B build-fuzz \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DCPPTCPDUPLEX_BUILD_FUZZERS=ON \
  -DCPPTCPDUPLEX_BUILD_TESTS=OFF -DCPPTCPDUPLEX_BUILD_EXAMPLES=OFF
cmake --build build-fuzz -j
./build-fuzz/fuzz_protocol -max_total_time=30
./build-fuzz/fuzz_transfer_frame -max_total_time=30
```

## Protocol compatibility

This library must stay **wire-compatible** with [github.com/hdmain/tcpduplex](https://github.com/hdmain/tcpduplex).

- Do not change handshake magic (`TDX1`), record framing, AEAD layout, or key derivation without a negotiated protocol version bump.
- Prefer adding tests (unit and/or Go ↔ C++ interop) for any framing or crypto change.
- Run `tests/interop/go_harness` after transport changes.

## Pull requests

1. Keep changes focused; match existing style (C++20, RAII, `std::error_code`).
2. Update `CHANGELOG.md` under an `[Unreleased]` section when behavior or API changes.
3. Ensure CI is green (build matrix, sanitizers, fuzz smoke, interop).

## Reporting issues

Please include OS, compiler version, CMake options, and a minimal reproducer when possible. For security-sensitive parser/crypto bugs, describe impact and prefer a private report if exploitation is realistic.
