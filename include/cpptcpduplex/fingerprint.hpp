#pragma once

#include <array>
#include <cstdint>
#include <span>

namespace cpptcpduplex {

// Returns SHA256(raw X25519 public key bytes) for HandshakeAuth pinning.
std::array<std::uint8_t, 32> peer_public_key_fingerprint(std::span<const std::uint8_t> pub_key);

}  // namespace cpptcpduplex
