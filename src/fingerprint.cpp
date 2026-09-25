#include "cpptcpduplex/fingerprint.hpp"
#include "cpptcpduplex/crypto/handshake.hpp"

namespace cpptcpduplex {

std::array<std::uint8_t, 32> peer_public_key_fingerprint(std::span<const std::uint8_t> pub_key) {
  return crypto::fingerprint_sha256(pub_key);
}

}  // namespace cpptcpduplex
