#include "cpptcpduplex/protocol/protocol.hpp"
#include "cpptcpduplex/detail/socket.hpp"
#include "cpptcpduplex/errors.hpp"

#include <cstring>

namespace cpptcpduplex::protocol {
namespace {

constexpr std::uint8_t kMagic[4] = {'T', 'D', 'X', '1'};

void put_be16(std::uint8_t* p, std::uint16_t v) {
  p[0] = static_cast<std::uint8_t>((v >> 8) & 0xff);
  p[1] = static_cast<std::uint8_t>(v & 0xff);
}

void put_be32(std::uint8_t* p, std::uint32_t v) {
  p[0] = static_cast<std::uint8_t>((v >> 24) & 0xff);
  p[1] = static_cast<std::uint8_t>((v >> 16) & 0xff);
  p[2] = static_cast<std::uint8_t>((v >> 8) & 0xff);
  p[3] = static_cast<std::uint8_t>(v & 0xff);
}

std::uint16_t get_be16(const std::uint8_t* p) {
  return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

std::uint32_t get_be32(const std::uint8_t* p) {
  return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
         (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

class SocketStream final : public ByteStream {
 public:
  explicit SocketStream(detail::TcpSocket& sock) : sock_(sock) {}
  std::error_code read_exact(std::span<std::uint8_t> buf) override { return sock_.read_exact(buf); }
  std::error_code write_all(std::span<const std::uint8_t> buf) override {
    return sock_.write_all(buf);
  }

 private:
  detail::TcpSocket& sock_;
};

}  // namespace

bool supports_version(std::uint16_t v) noexcept { return v == 1; }

std::error_code write_handshake(ByteStream& rw, std::uint16_t negotiated_version,
                                std::span<const std::uint8_t> pub_key) {
  if (!supports_version(negotiated_version)) {
    return make_error_code(errc::unsupported_protocol);
  }
  if (pub_key.size() != kX25519PubKeyLen) {
    return make_error_code(errc::bad_handshake);
  }
  std::uint8_t hdr[6];
  std::memcpy(hdr, kMagic, 4);
  put_be16(hdr + 4, negotiated_version);
  if (auto ec = rw.write_all(hdr)) {
    return ec;
  }
  return rw.write_all(pub_key);
}

std::error_code read_handshake(ByteStream& rw, std::uint16_t& protocol_version,
                               std::vector<std::uint8_t>& pub_key) {
  std::uint8_t magic[4];
  if (auto ec = rw.read_exact(magic)) {
    return ec;
  }
  if (std::memcmp(magic, kMagic, 4) != 0) {
    return make_error_code(errc::bad_handshake);
  }
  std::uint8_t ver[2];
  if (auto ec = rw.read_exact(ver)) {
    return ec;
  }
  protocol_version = get_be16(ver);
  if (!supports_version(protocol_version)) {
    return make_error_code(errc::unsupported_protocol);
  }
  pub_key.assign(kX25519PubKeyLen, 0);
  return rw.read_exact(pub_key);
}

std::error_code read_record(ByteStream& rw, std::uint8_t& msg_type,
                            std::vector<std::uint8_t>& sealed) {
  std::uint8_t len_buf[4];
  if (auto ec = rw.read_exact(len_buf)) {
    return ec;
  }
  const std::uint32_t n = get_be32(len_buf);
  if (n == 0 || n > kMaxRecordPayload) {
    return make_error_code(errc::bad_frame);
  }
  std::vector<std::uint8_t> payload(n);
  if (auto ec = rw.read_exact(payload)) {
    return ec;
  }
  msg_type = payload[0];
  sealed.assign(payload.begin() + 1, payload.end());
  return {};
}

std::error_code write_record(ByteStream& rw, std::uint8_t msg_type,
                             std::span<const std::uint8_t> sealed) {
  if (sealed.size() > kMaxRecordPayload - 1) {
    return make_error_code(errc::bad_frame);
  }
  const std::uint32_t n = static_cast<std::uint32_t>(1 + sealed.size());
  std::uint8_t len_buf[4];
  put_be32(len_buf, n);
  if (auto ec = rw.write_all(len_buf)) {
    return ec;
  }
  std::uint8_t hdr[1] = {msg_type};
  if (auto ec = rw.write_all(hdr)) {
    return ec;
  }
  return rw.write_all(sealed);
}

std::error_code write_handshake(void* sock, std::uint16_t negotiated_version,
                                std::span<const std::uint8_t> pub_key) {
  SocketStream stream(*static_cast<detail::TcpSocket*>(sock));
  return write_handshake(stream, negotiated_version, pub_key);
}

std::error_code read_handshake(void* sock, std::uint16_t& protocol_version,
                               std::vector<std::uint8_t>& pub_key) {
  SocketStream stream(*static_cast<detail::TcpSocket*>(sock));
  return read_handshake(stream, protocol_version, pub_key);
}

std::error_code read_record(void* sock, std::uint8_t& msg_type, std::vector<std::uint8_t>& sealed) {
  SocketStream stream(*static_cast<detail::TcpSocket*>(sock));
  return read_record(stream, msg_type, sealed);
}

std::error_code write_record(void* sock, std::uint8_t msg_type,
                             std::span<const std::uint8_t> sealed) {
  SocketStream stream(*static_cast<detail::TcpSocket*>(sock));
  return write_record(stream, msg_type, sealed);
}

}  // namespace cpptcpduplex::protocol
