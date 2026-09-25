#include "cpptcpduplex/cpptcpduplex.hpp"

#include <algorithm>
#include <chrono>
#include <iostream>
#include <mutex>
#include <string>
#include <vector>

int main(int argc, char** argv) {
  using namespace cpptcpduplex;
  std::string listen = "127.0.0.1:9090";
  if (argc > 1) {
    listen = argv[1];
  }

  auto srv = Server::listen("tcp", listen);
  std::cout << "cpptcpduplex listening on " << srv->addr() << "\n";

  std::mutex mu;
  std::vector<Conn*> conns;

  srv->serve([&](Conn& conn) {
    {
      std::lock_guard lock(mu);
      conns.push_back(&conn);
    }
    std::cout << "peer joined " << (conn.underlying() ? conn.underlying()->remote_addr() : "?")
              << "\n";
    for (;;) {
      std::error_code ec;
      auto msg = conn.receive(ec);
      if (ec) {
        break;
      }
      const std::string line(msg.begin(), msg.end());
      std::cerr << "[" << (conn.underlying() ? conn.underlying()->remote_addr() : "?") << "] "
                << line << "\n";
      std::lock_guard lock(mu);
      for (auto* c : conns) {
        std::error_code se;
        c->send(msg, se);
      }
    }
    std::lock_guard lock(mu);
    conns.erase(std::remove(conns.begin(), conns.end(), &conn), conns.end());
    std::error_code ignored;
    conn.shutdown(std::chrono::milliseconds{1000}, ignored);
  });
  return 0;
}
