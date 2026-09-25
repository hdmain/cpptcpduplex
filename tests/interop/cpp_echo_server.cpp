#include "cpptcpduplex/cpptcpduplex.hpp"
#include "cpptcpduplex/detail/socket.hpp"

#include <iostream>
#include <string>

// Usage: cpp_echo_server <listen-addr>
// Accepts one connection, echoes MsgText payloads until peer closes.
int main(int argc, char** argv) {
  using namespace cpptcpduplex;
  std::string addr = "127.0.0.1:19090";
  if (argc > 1) {
    addr = argv[1];
  }
  std::error_code ec;
  auto ln = detail::TcpListener::listen(addr, ec);
  if (!ln) {
    std::cerr << "listen failed: " << ec.message() << "\n";
    return 1;
  }
  std::cout << "READY " << ln->addr() << std::endl;
  auto raw = ln->accept(ec);
  if (!raw) {
    std::cerr << "accept failed: " << ec.message() << "\n";
    return 1;
  }
  auto conn = serve_conn(std::move(raw), nullptr, ec);
  if (!conn) {
    std::cerr << "handshake failed: " << ec.message() << "\n";
    return 1;
  }
  for (;;) {
    auto msg = conn->receive(ec);
    if (ec) {
      break;
    }
    conn->send(msg, ec);
    if (ec) {
      break;
    }
  }
  conn->shutdown(std::chrono::milliseconds{2000}, ec);
  return 0;
}
