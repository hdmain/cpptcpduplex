#include "cpptcpduplex/cpptcpduplex.hpp"
#include "cpptcpduplex/detail/socket.hpp"

#include <iostream>
#include <string>
#include <thread>

int main() {
  using namespace cpptcpduplex;
  std::error_code ec;
  auto ln = detail::TcpListener::listen("127.0.0.1:0", ec);
  if (!ln) {
    std::cerr << "listen: " << ec.message() << "\n";
    return 1;
  }

  std::thread server([&] {
    auto raw = ln->accept(ec);
    if (!raw) {
      return;
    }
    auto srv = serve_conn(std::move(raw));
    auto msg = srv->receive();
    std::cout << "server received: " << std::string(msg.begin(), msg.end()) << "\n";
    const std::string reply = "world";
    srv->send(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(reply.data()),
                                            reply.size()));
    srv->close();
  });

  auto cli = dial(ln->addr());
  const std::string hello = "hello";
  cli->send(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(hello.data()),
                                          hello.size()));
  auto out = cli->receive();
  std::cout << "client received: " << std::string(out.begin(), out.end()) << "\n";
  cli->close();
  server.join();
  return 0;
}
