#include "cpptcpduplex/config.hpp"
#include "cpptcpduplex/protocol/protocol.hpp"

namespace cpptcpduplex {

Config default_config() {
  Config c;
  c.dial_timeout = std::chrono::milliseconds{30000};
  c.handshake_timeout = std::chrono::milliseconds{15000};
  c.protocol_version = protocol::kCurrentProtocolVersion;
  c.max_message_bytes = 512 << 10;
  c.send_queue_depth = 256;
  c.receive_queue_depth = 256;
  c.on_message_buffer_depth = 128;
  c.disconnect_on_slow_callback_consumer = false;
  return c;
}

FrozenConfig freeze_config(const Config* cfg) {
  Config d = default_config();
  const Config& src = cfg ? *cfg : d;
  FrozenConfig f;
  f.dial_timeout = src.dial_timeout.count() <= 0 ? d.dial_timeout : src.dial_timeout;
  f.handshake_timeout =
      src.handshake_timeout.count() <= 0 ? d.handshake_timeout : src.handshake_timeout;
  f.protocol_version = src.protocol_version == 0 ? d.protocol_version : src.protocol_version;
  f.max_message_bytes = src.max_message_bytes <= 0 ? d.max_message_bytes : src.max_message_bytes;
  f.send_queue_depth = src.send_queue_depth <= 0 ? d.send_queue_depth : src.send_queue_depth;
  f.receive_queue_depth =
      src.receive_queue_depth <= 0 ? d.receive_queue_depth : src.receive_queue_depth;
  f.on_message = src.on_message;
  f.on_message_buffer_depth = src.on_message_buffer_depth;
  if (f.on_message && f.on_message_buffer_depth <= 0) {
    f.on_message_buffer_depth = d.on_message_buffer_depth;
  }
  f.disconnect_on_slow_callback_consumer = src.disconnect_on_slow_callback_consumer;
  f.handshake = src.handshake;
  return f;
}

crypto::HandshakeOpts handshake_opts(const FrozenConfig& f) {
  crypto::HandshakeOpts o;
  o.pre_shared_key = f.handshake.pre_shared_key;
  o.expected_peer_pubkey_sha256 = f.handshake.expected_peer_pubkey_sha256;
  return o;
}

}  // namespace cpptcpduplex
