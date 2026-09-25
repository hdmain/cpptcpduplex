#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <system_error>
#include <vector>

namespace cpptcpduplex::protocol {

inline constexpr std::uint8_t kMsgText = 1;
inline constexpr std::uint8_t kMsgPing = 2;
inline constexpr std::uint8_t kMsgPong = 3;
inline constexpr std::uint8_t kMsgClose = 4;

inline constexpr std::uint16_t kCurrentProtocolVersion = 1;
inline constexpr std::size_t kX25519PubKeyLen = 32;
inline constexpr std::uint32_t kMaxRecordPayload = 1u << 20;

bool supports_version(std::uint16_t v) noexcept;

std::error_code write_handshake(void* sock, std::uint16_t negotiated_version,
                                std::span<const std::uint8_t> pub_key);
std::error_code read_handshake(void* sock, std::uint16_t& protocol_version,
                               std::vector<std::uint8_t>& pub_key);

std::error_code read_record(void* sock, std::uint8_t& msg_type,
                            std::vector<std::uint8_t>& sealed);
std::error_code write_record(void* sock, std::uint8_t msg_type,
                             std::span<const std::uint8_t> sealed);

// Stream-oriented helpers used by tests and crypto over abstract readers/writers.
class ByteStream {
 public:
  virtual ~ByteStream() = default;
  virtual std::error_code read_exact(std::span<std::uint8_t> buf) = 0;
  virtual std::error_code write_all(std::span<const std::uint8_t> buf) = 0;
};

std::error_code write_handshake(ByteStream& rw, std::uint16_t negotiated_version,
                                std::span<const std::uint8_t> pub_key);
std::error_code read_handshake(ByteStream& rw, std::uint16_t& protocol_version,
                               std::vector<std::uint8_t>& pub_key);
std::error_code read_record(ByteStream& rw, std::uint8_t& msg_type,
                            std::vector<std::uint8_t>& sealed);
std::error_code write_record(ByteStream& rw, std::uint8_t msg_type,
                             std::span<const std::uint8_t> sealed);

}  // namespace cpptcpduplex::protocol
