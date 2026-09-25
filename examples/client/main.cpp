#include "cpptcpduplex/cpptcpduplex.hpp"

#include <iostream>
#include <string>
#include <thread>

int main(int argc, char** argv) {
  using namespace cpptcpduplex;
  std::string addr = "127.0.0.1:9090";
  if (argc > 1) {
    addr = argv[1];
  }

  auto conn = dial(addr);
  std::thread reader([&] {
    for (;;) {
      std::error_code ec;
      auto msg = conn->receive(ec);
      if (ec) {
        return;
      }
      std::cout << std::string(msg.begin(), msg.end()) << "\n";
    }
  });

  std::string line;
  while (std::getline(std::cin, line)) {
    if (line == "/quit") {
      break;
    }
    std::error_code ec;
    conn->send(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(line.data()),
                                             line.size()),
               ec);
    if (ec) {
      std::cerr << "send: " << ec.message() << "\n";
    }
  }
  conn->close();
  reader.join();
  return 0;
}
