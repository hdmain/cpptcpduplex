#pragma once

#include <cstdint>
#include <span>

namespace cpptcpduplex::crypto {

// RFC 7748 X25519. out/pub/priv are 32 bytes.
void x25519_public_from_private(std::span<std::uint8_t, 32> pub,
                                std::span<const std::uint8_t, 32> priv);
// shared = X25519(priv, peer_pub)
void x25519_shared_secret(std::span<std::uint8_t, 32> shared,
                          std::span<const std::uint8_t, 32> priv,
                          std::span<const std::uint8_t, 32> peer_pub);

}  // namespace cpptcpduplex::crypto
