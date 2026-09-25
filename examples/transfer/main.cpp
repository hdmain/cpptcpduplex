#include "cpptcpduplex/cpptcpduplex.hpp"
#include "cpptcpduplex/detail/socket.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>

int main() {
  using namespace cpptcpduplex;
  namespace fs = std::filesystem;

  const auto dir = fs::temp_directory_path() / "cpptcpduplex-transfer-ex";
  fs::create_directories(dir);
  const auto src = dir / "hello.txt";
  const auto dst = dir / "hello-copy.txt";
  {
    std::ofstream out(src, std::ios::binary);
    out << "encrypted resumable transfer over cpptcpduplex\n";
  }

  std::error_code ec;
  auto ln = detail::TcpListener::listen("127.0.0.1:0", ec);
  std::thread server([&] {
    auto raw = ln->accept(ec);
    auto srv = serve_conn(std::move(raw));
    transfer::Meta meta;
    if (auto e = transfer::receive_file(*srv, dst.string(), meta, nullptr)) {
      std::cerr << "receive: " << e.message() << "\n";
      return;
    }
    std::cout << "received " << meta.name << " (" << meta.size
              << " bytes, id=" << transfer::id_to_string(meta.id) << ")\n";
    srv->close();
  });

  auto cli = dial(ln->addr());
  transfer::Options opts;
  opts.on_progress = [](std::int64_t n, std::int64_t total) {
    std::cout << "progress " << n << "/" << total << "\n";
  };
  if (auto e = transfer::send_file(*cli, src.string(), &opts)) {
    std::cerr << "send: " << e.message() << "\n";
    return 1;
  }
  cli->close();
  server.join();

  std::ifstream in(dst);
  std::string got((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  in.close();
  std::cout << "verified: " << got;
  std::error_code fec;
  fs::remove_all(dir, fec);
  return 0;
}
