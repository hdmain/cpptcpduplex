#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <vector>

namespace cpptcpduplex::detail {

#if defined(_WIN32)
using socket_handle = std::uintptr_t;
inline constexpr socket_handle kInvalidSocket = static_cast<socket_handle>(~std::uintptr_t{0});
#else
using socket_handle = int;
inline constexpr socket_handle kInvalidSocket = -1;
#endif

class TcpSocket {
 public:
  TcpSocket() = default;
  explicit TcpSocket(socket_handle fd);
  ~TcpSocket();

  TcpSocket(const TcpSocket&) = delete;
  TcpSocket& operator=(const TcpSocket&) = delete;
  TcpSocket(TcpSocket&& other) noexcept;
  TcpSocket& operator=(TcpSocket&& other) noexcept;

  static std::unique_ptr<TcpSocket> connect(const std::string& address,
                                            std::chrono::milliseconds timeout,
                                            std::error_code& ec);

  std::error_code read_exact(std::span<std::uint8_t> buf);
  std::error_code write_all(std::span<const std::uint8_t> buf);

  void set_deadline(std::chrono::milliseconds from_now);
  void clear_deadline();

  void close();
  socket_handle native() const noexcept { return fd_; }
  bool valid() const noexcept { return fd_ != kInvalidSocket; }

  std::string remote_addr() const;
  std::string local_addr() const;

 private:
  socket_handle fd_{kInvalidSocket};
};

class TcpListener {
 public:
  TcpListener() = default;
  ~TcpListener();

  TcpListener(const TcpListener&) = delete;
  TcpListener& operator=(const TcpListener&) = delete;

  static std::unique_ptr<TcpListener> listen(const std::string& address, std::error_code& ec);

  std::unique_ptr<TcpSocket> accept(std::error_code& ec);
  void close();
  std::string addr() const;
  socket_handle native() const noexcept { return fd_; }

 private:
  socket_handle fd_{kInvalidSocket};
  std::string addr_;
};

void ensure_sockets_initialized();
std::error_code map_socket_error();

}  // namespace cpptcpduplex::detail
