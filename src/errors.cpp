#include "cpptcpduplex/errors.hpp"

namespace cpptcpduplex {

std::string error_category::message(int ev) const {
  switch (static_cast<errc>(ev)) {
    case errc::ok:
      return "success";
    case errc::closed:
      return "connection closed";
    case errc::receive_disabled:
      return "Receive unavailable while OnMessage is configured";
    case errc::message_too_large:
      return "message exceeds MaxMessageBytes";
    case errc::inbound_dropped:
      return "inbound OnMessage buffer full";
    case errc::slow_consumer:
      return "disconnected due to slow OnMessage consumer";
    case errc::unsupported_protocol:
      return "unsupported protocol version";
    case errc::handshake_authentication:
      return "handshake authentication failed";
    case errc::peer_fingerprint_mismatch:
      return "peer public key fingerprint mismatch";
    case errc::bad_handshake:
      return "invalid handshake";
    case errc::bad_frame:
      return "invalid frame";
    case errc::canceled:
      return "operation canceled";
    case errc::timed_out:
      return "operation timed out";
    case errc::io_error:
      return "I/O error";
    case errc::other:
    default:
      return "error";
  }
}

const std::error_category& category() {
  static error_category cat;
  return cat;
}

Error::Error(std::string op, std::error_code ec)
    : std::runtime_error("cpptcpduplex " + op + ": " + ec.message()),
      op_(std::move(op)),
      code_(ec) {}

Error::Error(std::string op, std::string message, errc code)
    : std::runtime_error("cpptcpduplex " + op + ": " + message),
      op_(std::move(op)),
      code_(make_error_code(code)) {}

bool is_closed(const std::error_code& ec) {
  return ec == errc::closed || ec == std::errc::connection_reset ||
         ec == std::errc::broken_pipe;
}

bool is_eof(const std::error_code& ec) { return is_closed(ec); }

}  // namespace cpptcpduplex
