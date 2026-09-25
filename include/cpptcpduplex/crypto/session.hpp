#pragma once

#include <cstdint>
#include <span>
#include <system_error>
#include <vector>

namespace cpptcpduplex::crypto {

// AES-256-GCM session derived from ECDH (optionally mixed with PSK).
class Session {
 public:
  Session() = default;
  explicit Session(std::vector<std::uint8_t> key);

  static std::error_code create(std::span<const std::uint8_t> shared_secret,
                                std::span<const std::uint8_t> psk,
                                Session& out);

  // Seal encrypts plaintext and returns nonce || ciphertext || tag (12+ct+16).
  std::error_code seal(std::span<const std::uint8_t> plaintext,
                       std::vector<std::uint8_t>& out) const;

  // Open decrypts a blob produced by Seal.
  std::error_code open(std::span<const std::uint8_t> sealed,
                       std::vector<std::uint8_t>& out) const;

  bool valid() const noexcept { return !key_.empty(); }

 private:
  std::vector<std::uint8_t> key_;
};

std::vector<std::uint8_t> derive_session_key(std::span<const std::uint8_t> shared_secret,
                                             std::span<const std::uint8_t> psk);

}  // namespace cpptcpduplex::crypto
