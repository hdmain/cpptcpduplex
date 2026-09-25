#include "cpptcpduplex/dial.hpp"
#include "cpptcpduplex/crypto/handshake.hpp"
#include "cpptcpduplex/detail/socket.hpp"
#include "cpptcpduplex/protocol/protocol.hpp"

namespace cpptcpduplex {
namespace {

class SocketStream final : public protocol::ByteStream {
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

std::unique_ptr<Conn> dial(const std::string& address) { return dial(address, nullptr); }

std::unique_ptr<Conn> dial(const std::string& address, const Config* cfg) {
  std::error_code ec;
  auto c = dial(address, cfg, ec);
  if (ec) {
    throw Error("dial", ec);
  }
  return c;
}

std::unique_ptr<Conn> dial(const std::string& address, const Config* cfg, std::error_code& ec) {
  return dial_for(address, cfg, std::chrono::milliseconds::max(), ec);
}

std::unique_ptr<Conn> dial_for(const std::string& address, const Config* cfg,
                               std::chrono::milliseconds /*overall_timeout*/, std::error_code& ec) {
  ec.clear();
  auto fc = freeze_config(cfg);
  if (!protocol::supports_version(fc.protocol_version)) {
    ec = make_error_code(errc::unsupported_protocol);
    return nullptr;
  }

  auto sock = detail::TcpSocket::connect(address, fc.dial_timeout, ec);
  if (!sock) {
    return nullptr;
  }

  if (fc.handshake_timeout.count() > 0) {
    sock->set_deadline(fc.handshake_timeout);
  }
  SocketStream stream(*sock);
  crypto::Session sess;
  auto hops = handshake_opts(fc);
  const crypto::HandshakeOpts* opts_ptr =
      (hops.pre_shared_key.empty() && !hops.expected_peer_pubkey_sha256) ? nullptr : &hops;
  auto hec = crypto::client_handshake(stream, fc.protocol_version, opts_ptr, sess);
  sock->clear_deadline();
  if (hec) {
    ec = hec;
    sock->close();
    return nullptr;
  }
  return std::make_unique<Conn>(std::move(sock), std::move(sess), std::move(fc));
}

std::unique_ptr<Conn> serve_conn(std::unique_ptr<detail::TcpSocket> sock) {
  return serve_conn(std::move(sock), nullptr);
}

std::unique_ptr<Conn> serve_conn(std::unique_ptr<detail::TcpSocket> sock, const Config* cfg) {
  std::error_code ec;
  auto c = serve_conn(std::move(sock), cfg, ec);
  if (ec) {
    throw Error("handshake", ec);
  }
  return c;
}

std::unique_ptr<Conn> serve_conn(std::unique_ptr<detail::TcpSocket> sock, const Config* cfg,
                                 std::error_code& ec) {
  return serve_conn_for(std::move(sock), cfg, std::chrono::milliseconds::max(), ec);
}

std::unique_ptr<Conn> serve_conn_for(std::unique_ptr<detail::TcpSocket> sock, const Config* cfg,
                                     std::chrono::milliseconds /*overall_timeout*/,
                                     std::error_code& ec) {
  ec.clear();
  if (!sock) {
    ec = make_error_code(errc::other);
    return nullptr;
  }
  auto fc = freeze_config(cfg);
  if (fc.handshake_timeout.count() > 0) {
    sock->set_deadline(fc.handshake_timeout);
  }
  SocketStream stream(*sock);
  crypto::Session sess;
  std::uint16_t ver = 0;
  auto hops = handshake_opts(fc);
  const crypto::HandshakeOpts* opts_ptr =
      (hops.pre_shared_key.empty() && !hops.expected_peer_pubkey_sha256) ? nullptr : &hops;
  auto hec = crypto::server_handshake(stream, opts_ptr, sess, ver);
  sock->clear_deadline();
  if (hec) {
    ec = hec;
    sock->close();
    return nullptr;
  }
  return std::make_unique<Conn>(std::move(sock), std::move(sess), std::move(fc));
}

}  // namespace cpptcpduplex
