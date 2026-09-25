#pragma once

#include <stdexcept>
#include <string>
#include <system_error>

namespace cpptcpduplex {

enum class errc {
  ok = 0,
  closed,
  receive_disabled,
  message_too_large,
  inbound_dropped,
  slow_consumer,
  unsupported_protocol,
  handshake_authentication,
  peer_fingerprint_mismatch,
  bad_handshake,
  bad_frame,
  canceled,
  timed_out,
  io_error,
  other,
};

class error_category : public std::error_category {
 public:
  const char* name() const noexcept override { return "cpptcpduplex"; }
  std::string message(int ev) const override;
};

const std::error_category& category();

inline std::error_code make_error_code(errc e) {
  return {static_cast<int>(e), category()};
}

class Error : public std::runtime_error {
 public:
  Error(std::string op, std::error_code ec);
  Error(std::string op, std::string message, errc code = errc::other);

  const std::string& op() const noexcept { return op_; }
  const std::error_code& code() const noexcept { return code_; }

 private:
  std::string op_;
  std::error_code code_;
};

bool is_closed(const std::error_code& ec);
bool is_eof(const std::error_code& ec);

}  // namespace cpptcpduplex

namespace std {
template <>
struct is_error_code_enum<cpptcpduplex::errc> : true_type {};
}
