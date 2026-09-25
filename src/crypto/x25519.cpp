#include "x25519.hpp"

extern "C" {
#include "monocypher.h"
}

namespace cpptcpduplex::crypto {

void x25519_public_from_private(std::span<std::uint8_t, 32> pub,
                                std::span<const std::uint8_t, 32> priv) {
  crypto_x25519_public_key(pub.data(), priv.data());
}

void x25519_shared_secret(std::span<std::uint8_t, 32> shared,
                          std::span<const std::uint8_t, 32> priv,
                          std::span<const std::uint8_t, 32> peer_pub) {
  crypto_x25519(shared.data(), priv.data(), peer_pub.data());
}

}  // namespace cpptcpduplex::crypto
