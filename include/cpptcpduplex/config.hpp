#pragma once

#include "cpptcpduplex/crypto/handshake.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

namespace cpptcpduplex {

struct HandshakeAuth {
  std::vector<std::uint8_t> pre_shared_key;
  std::optional<std::array<std::uint8_t, 32>> expected_peer_pubkey_sha256;
};

struct Config {
  std::chrono::milliseconds dial_timeout{30000};
  std::chrono::milliseconds handshake_timeout{15000};
  std::uint16_t protocol_version{1};
  int max_message_bytes{512 << 10};
  int send_queue_depth{256};
  int receive_queue_depth{256};
  std::function<void(std::vector<std::uint8_t>)> on_message;
  int on_message_buffer_depth{128};
  bool disconnect_on_slow_callback_consumer{false};
  HandshakeAuth handshake;
};

Config default_config();

struct FrozenConfig {
  std::chrono::milliseconds dial_timeout{};
  std::chrono::milliseconds handshake_timeout{};
  std::uint16_t protocol_version{1};
  int max_message_bytes{512 << 10};
  int send_queue_depth{256};
  int receive_queue_depth{256};
  std::function<void(std::vector<std::uint8_t>)> on_message;
  int on_message_buffer_depth{128};
  bool disconnect_on_slow_callback_consumer{false};
  HandshakeAuth handshake;
};

FrozenConfig freeze_config(const Config* cfg);
crypto::HandshakeOpts handshake_opts(const FrozenConfig& f);

}  // namespace cpptcpduplex
