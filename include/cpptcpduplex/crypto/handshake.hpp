#pragma once

#include "cpptcpduplex/crypto/session.hpp"
#include "cpptcpduplex/protocol/protocol.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <system_error>
#include <vector>

namespace cpptcpduplex::crypto {

struct HandshakeOpts {
  std::vector<std::uint8_t> pre_shared_key;
  // When set, must equal SHA256(peer raw X25519 public key bytes).
  std::optional<std::array<std::uint8_t, 32>> expected_peer_pubkey_sha256;
};

std::error_code client_handshake(protocol::ByteStream& rw,
                                 std::uint16_t negotiated_version,
                                 const HandshakeOpts* opts, Session& out);

std::error_code server_handshake(protocol::ByteStream& rw, const HandshakeOpts* opts,
                                 Session& out, std::uint16_t& negotiated_version);

std::array<std::uint8_t, 32> fingerprint_sha256(std::span<const std::uint8_t> pub_key);

}  // namespace cpptcpduplex::crypto
