# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-09-26

### Added

- Initial public release: native C++20 port of [tcpduplex](https://github.com/hdmain/tcpduplex).
- Wire-compatible duplex sessions (X25519 + AES-256-GCM), `Server`, and resumable `transfer`.
- CMake static/shared builds with `cmake --install` / `find_package(cpptcpduplex)`.
- Unit tests, Go ↔ C++ interop harness, examples.
- GitHub Actions CI (Linux/macOS/Windows), ASan/UBSan, and libFuzzer targets for protocol and transfer frames.

[1.0.0]: https://github.com/hdmain/cpptcpduplex/releases/tag/v1.0.0
