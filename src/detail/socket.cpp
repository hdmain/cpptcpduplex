#include "cpptcpduplex/detail/socket.hpp"
#include "cpptcpduplex/errors.hpp"

#include <mutex>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#  include <errno.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <signal.h>
#  include <sys/socket.h>
#  include <sys/types.h>
#  include <unistd.h>
#endif

namespace cpptcpduplex::detail {
namespace {

#if defined(_WIN32)
std::once_flag g_wsa_once;
void init_wsa() {
  WSADATA wsa{};
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
    throw Error("sockets", "WSAStartup failed", errc::io_error);
  }
}
#else
std::once_flag g_unix_once;
void init_unix_sockets() {
  // Avoid process death when writing to a peer that already closed (EPIPE).
  ::signal(SIGPIPE, SIG_IGN);
}
#endif

#ifndef MSG_NOSIGNAL
#  define MSG_NOSIGNAL 0
#endif

void configure_new_socket(socket_handle fd) {
#if defined(__APPLE__)
  int one = 1;
  setsockopt(static_cast<int>(fd), SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#else
  (void)fd;
#endif
}

std::error_code last_socket_error() {
#if defined(_WIN32)
  const int e = WSAGetLastError();
  if (e == WSAETIMEDOUT || e == WSAEWOULDBLOCK) {
    return make_error_code(errc::timed_out);
  }
  if (e == WSAECONNRESET || e == WSAECONNABORTED) {
    return make_error_code(errc::closed);
  }
  return std::error_code(e, std::system_category());
#else
  const int e = errno;
  if (e == ETIMEDOUT || e == EAGAIN || e == EWOULDBLOCK) {
    return make_error_code(errc::timed_out);
  }
  if (e == ECONNRESET || e == EPIPE) {
    return make_error_code(errc::closed);
  }
  return std::error_code(e, std::generic_category());
#endif
}

bool parse_host_port(const std::string& address, std::string& host, std::string& port) {
  if (address.empty()) {
    return false;
  }
  if (address[0] == '[') {
    const auto end = address.find(']');
    if (end == std::string::npos || end + 1 >= address.size() || address[end + 1] != ':') {
      return false;
    }
    host = address.substr(1, end - 1);
    port = address.substr(end + 2);
    return !host.empty() && !port.empty();
  }
  const auto pos = address.rfind(':');
  if (pos == std::string::npos) {
    return false;
  }
  host = address.substr(0, pos);
  port = address.substr(pos + 1);
  if (host.empty()) {
    host = "0.0.0.0";
  }
  return !port.empty();
}

std::string sockaddr_to_string(const sockaddr* sa, socklen_t len) {
  char host[NI_MAXHOST]{};
  char serv[NI_MAXSERV]{};
  if (getnameinfo(sa, len, host, sizeof(host), serv, sizeof(serv),
                  NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
    return {};
  }
  if (sa->sa_family == AF_INET6) {
    return std::string("[") + host + "]:" + serv;
  }
  return std::string(host) + ":" + serv;
}

}  // namespace

void ensure_sockets_initialized() {
#if defined(_WIN32)
  std::call_once(g_wsa_once, init_wsa);
#else
  std::call_once(g_unix_once, init_unix_sockets);
#endif
}

std::error_code map_socket_error() { return last_socket_error(); }

TcpSocket::TcpSocket(socket_handle fd) : fd_(fd) {}

TcpSocket::~TcpSocket() { close(); }

TcpSocket::TcpSocket(TcpSocket&& other) noexcept : fd_(other.fd_) {
  other.fd_ = kInvalidSocket;
}

TcpSocket& TcpSocket::operator=(TcpSocket&& other) noexcept {
  if (this != &other) {
    close();
    fd_ = other.fd_;
    other.fd_ = kInvalidSocket;
  }
  return *this;
}

void TcpSocket::close() {
  if (fd_ == kInvalidSocket) {
    return;
  }
#if defined(_WIN32)
  closesocket(static_cast<SOCKET>(fd_));
#else
  ::close(static_cast<int>(fd_));
#endif
  fd_ = kInvalidSocket;
}

std::unique_ptr<TcpSocket> TcpSocket::connect(const std::string& address,
                                              std::chrono::milliseconds timeout,
                                              std::error_code& ec) {
  ensure_sockets_initialized();
  ec.clear();
  std::string host;
  std::string port;
  if (!parse_host_port(address, host, port)) {
    ec = make_error_code(errc::other);
    return nullptr;
  }

  addrinfo hints{};
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  hints.ai_protocol = IPPROTO_TCP;

  addrinfo* res = nullptr;
  if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0) {
    ec = make_error_code(errc::io_error);
    return nullptr;
  }

  socket_handle fd = kInvalidSocket;
  for (addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
#if defined(_WIN32)
    SOCKET s = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (s == INVALID_SOCKET) {
      continue;
    }
    if (timeout.count() > 0) {
      DWORD ms = static_cast<DWORD>(timeout.count());
      setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
      setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
    }
    if (::connect(s, ai->ai_addr, static_cast<int>(ai->ai_addrlen)) == 0) {
      fd = static_cast<socket_handle>(s);
      break;
    }
    closesocket(s);
#else
    int s = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (s < 0) {
      continue;
    }
    if (timeout.count() > 0) {
      timeval tv{};
      tv.tv_sec = static_cast<long>(timeout.count() / 1000);
      tv.tv_usec = static_cast<long>((timeout.count() % 1000) * 1000);
      setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
      setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
    if (::connect(s, ai->ai_addr, ai->ai_addrlen) == 0) {
      fd = s;
      break;
    }
    ::close(s);
#endif
  }
  freeaddrinfo(res);

  if (fd == kInvalidSocket) {
    ec = make_error_code(errc::io_error);
    return nullptr;
  }

  configure_new_socket(fd);
  auto sock = std::make_unique<TcpSocket>(fd);
  sock->clear_deadline();
  return sock;
}

std::error_code TcpSocket::read_exact(std::span<std::uint8_t> buf) {
  std::size_t got = 0;
  while (got < buf.size()) {
#if defined(_WIN32)
    const int n = ::recv(static_cast<SOCKET>(fd_), reinterpret_cast<char*>(buf.data() + got),
                         static_cast<int>(buf.size() - got), 0);
#else
    const ssize_t n = ::recv(static_cast<int>(fd_), buf.data() + got, buf.size() - got, 0);
#endif
    if (n == 0) {
      return make_error_code(errc::closed);
    }
    if (n < 0) {
      return last_socket_error();
    }
    got += static_cast<std::size_t>(n);
  }
  return {};
}

std::error_code TcpSocket::write_all(std::span<const std::uint8_t> buf) {
  std::size_t sent = 0;
  while (sent < buf.size()) {
#if defined(_WIN32)
    const int n = ::send(static_cast<SOCKET>(fd_), reinterpret_cast<const char*>(buf.data() + sent),
                         static_cast<int>(buf.size() - sent), 0);
#else
    const ssize_t n =
        ::send(static_cast<int>(fd_), buf.data() + sent, buf.size() - sent, MSG_NOSIGNAL);
#endif
    if (n <= 0) {
      return last_socket_error();
    }
    sent += static_cast<std::size_t>(n);
  }
  return {};
}

void TcpSocket::set_deadline(std::chrono::milliseconds from_now) {
  if (!valid()) {
    return;
  }
#if defined(_WIN32)
  DWORD ms = from_now.count() <= 0 ? 0 : static_cast<DWORD>(from_now.count());
  setsockopt(static_cast<SOCKET>(fd_), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ms),
             sizeof(ms));
  setsockopt(static_cast<SOCKET>(fd_), SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&ms),
             sizeof(ms));
#else
  timeval tv{};
  if (from_now.count() > 0) {
    tv.tv_sec = static_cast<long>(from_now.count() / 1000);
    tv.tv_usec = static_cast<long>((from_now.count() % 1000) * 1000);
  }
  setsockopt(static_cast<int>(fd_), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(static_cast<int>(fd_), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

void TcpSocket::clear_deadline() { set_deadline(std::chrono::milliseconds{0}); }

std::string TcpSocket::remote_addr() const {
  if (!valid()) {
    return {};
  }
  sockaddr_storage ss{};
  socklen_t len = sizeof(ss);
#if defined(_WIN32)
  if (getpeername(static_cast<SOCKET>(fd_), reinterpret_cast<sockaddr*>(&ss), &len) != 0) {
    return {};
  }
#else
  if (getpeername(static_cast<int>(fd_), reinterpret_cast<sockaddr*>(&ss), &len) != 0) {
    return {};
  }
#endif
  return sockaddr_to_string(reinterpret_cast<sockaddr*>(&ss), len);
}

std::string TcpSocket::local_addr() const {
  if (!valid()) {
    return {};
  }
  sockaddr_storage ss{};
  socklen_t len = sizeof(ss);
#if defined(_WIN32)
  if (getsockname(static_cast<SOCKET>(fd_), reinterpret_cast<sockaddr*>(&ss), &len) != 0) {
    return {};
  }
#else
  if (getsockname(static_cast<int>(fd_), reinterpret_cast<sockaddr*>(&ss), &len) != 0) {
    return {};
  }
#endif
  return sockaddr_to_string(reinterpret_cast<sockaddr*>(&ss), len);
}

TcpListener::~TcpListener() { close(); }

void TcpListener::close() {
  if (fd_ == kInvalidSocket) {
    return;
  }
#if defined(_WIN32)
  closesocket(static_cast<SOCKET>(fd_));
#else
  ::close(static_cast<int>(fd_));
#endif
  fd_ = kInvalidSocket;
}

std::unique_ptr<TcpListener> TcpListener::listen(const std::string& address, std::error_code& ec) {
  ensure_sockets_initialized();
  ec.clear();
  std::string host;
  std::string port;
  if (!parse_host_port(address, host, port)) {
    ec = make_error_code(errc::other);
    return nullptr;
  }

  addrinfo hints{};
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_PASSIVE;
  hints.ai_protocol = IPPROTO_TCP;

  addrinfo* res = nullptr;
  const char* host_c = (host == "0.0.0.0" || host.empty()) ? nullptr : host.c_str();
  if (getaddrinfo(host_c, port.c_str(), &hints, &res) != 0) {
    ec = make_error_code(errc::io_error);
    return nullptr;
  }

  socket_handle fd = kInvalidSocket;
  for (addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
#if defined(_WIN32)
    SOCKET s = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (s == INVALID_SOCKET) {
      continue;
    }
    BOOL yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));
    if (::bind(s, ai->ai_addr, static_cast<int>(ai->ai_addrlen)) == 0 &&
        ::listen(s, SOMAXCONN) == 0) {
      fd = static_cast<socket_handle>(s);
      break;
    }
    closesocket(s);
#else
    int s = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (s < 0) {
      continue;
    }
    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    if (::bind(s, ai->ai_addr, ai->ai_addrlen) == 0 && ::listen(s, SOMAXCONN) == 0) {
      fd = s;
      break;
    }
    ::close(s);
#endif
  }
  freeaddrinfo(res);

  if (fd == kInvalidSocket) {
    ec = make_error_code(errc::io_error);
    return nullptr;
  }

  auto ln = std::unique_ptr<TcpListener>(new TcpListener());
  ln->fd_ = fd;
  sockaddr_storage ss{};
  socklen_t len = sizeof(ss);
#if defined(_WIN32)
  if (getsockname(static_cast<SOCKET>(fd), reinterpret_cast<sockaddr*>(&ss), &len) == 0) {
    ln->addr_ = sockaddr_to_string(reinterpret_cast<sockaddr*>(&ss), len);
  }
#else
  if (getsockname(static_cast<int>(fd), reinterpret_cast<sockaddr*>(&ss), &len) == 0) {
    ln->addr_ = sockaddr_to_string(reinterpret_cast<sockaddr*>(&ss), len);
  }
#endif
  return ln;
}

std::unique_ptr<TcpSocket> TcpListener::accept(std::error_code& ec) {
  ec.clear();
  if (fd_ == kInvalidSocket) {
    ec = make_error_code(errc::closed);
    return nullptr;
  }
#if defined(_WIN32)
  SOCKET s = ::accept(static_cast<SOCKET>(fd_), nullptr, nullptr);
  if (s == INVALID_SOCKET) {
    ec = last_socket_error();
    return nullptr;
  }
  return std::make_unique<TcpSocket>(static_cast<socket_handle>(s));
#else
  int s = ::accept(static_cast<int>(fd_), nullptr, nullptr);
  if (s < 0) {
    ec = last_socket_error();
    return nullptr;
  }
  configure_new_socket(static_cast<socket_handle>(s));
  return std::make_unique<TcpSocket>(s);
#endif
}

std::string TcpListener::addr() const { return addr_; }

}  // namespace cpptcpduplex::detail
