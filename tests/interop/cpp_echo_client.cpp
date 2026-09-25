#include "cpptcpduplex/cpptcpduplex.hpp"

#include <iostream>
#include <string>

// Usage: cpp_echo_client <addr> <message>
int main(int argc, char** argv) {
  using namespace cpptcpduplex;
  if (argc < 3) {
    std::cerr << "usage: cpp_echo_client <addr> <message>\n";
    return 2;
  }
  std::error_code ec;
  auto conn = dial(argv[1], nullptr, ec);
  if (!conn) {
    std::cerr << "dial failed: " << ec.message() << "\n";
    return 1;
  }
  const std::string msg = argv[2];
  conn->send(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(msg.data()),
                                           msg.size()),
             ec);
  if (ec) {
    std::cerr << "send failed: " << ec.message() << "\n";
    return 1;
  }
  auto got = conn->receive(ec);
  if (ec) {
    std::cerr << "receive failed: " << ec.message() << "\n";
    return 1;
  }
  std::cout << std::string(got.begin(), got.end()) << "\n";
  conn->shutdown(std::chrono::milliseconds{2000}, ec);
  return 0;
}
