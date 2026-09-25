#include "cpptcpduplex/cpptcpduplex.hpp"
#include "cpptcpduplex/detail/socket.hpp"

#include <iostream>
#include <string>
#include <thread>

int test_conn() {
  int fail = 0;
  using namespace cpptcpduplex;

  std::error_code ec;
  auto ln = detail::TcpListener::listen("127.0.0.1:0", ec);
  if (!ln) {
    std::cerr << "listener: " << ec.message() << "\n";
    return 1;
  }
  const auto listen_addr = ln->addr();

  std::unique_ptr<Conn> server_conn;
  std::error_code server_ec;
  std::thread th([&] {
    auto raw = ln->accept(server_ec);
    if (!raw) {
      return;
    }
    server_conn = serve_conn(std::move(raw), nullptr, server_ec);
  });

  auto cli = dial(listen_addr, nullptr, ec);
  if (!cli) {
    std::cerr << "dial: " << ec.message() << "\n";
    ln->close();
    th.join();
    return 1;
  }
  th.join();
  if (!server_conn) {
    std::cerr << "server handshake failed: " << server_ec.message() << "\n";
    return 1;
  }

  const std::string msg = "hello duplex";
  cli->send(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(msg.data()),
                                          msg.size()),
            ec);
  if (ec) {
    std::cerr << "send: " << ec.message() << "\n";
    ++fail;
  }
  auto got = server_conn->receive(ec);
  if (ec || std::string(got.begin(), got.end()) != msg) {
    std::cerr << "server receive mismatch\n";
    ++fail;
  }

  const std::string reply = "ack";
  server_conn->send(
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(reply.data()), reply.size()),
      ec);
  auto got2 = cli->receive(ec);
  if (ec || std::string(got2.begin(), got2.end()) != reply) {
    std::cerr << "client receive mismatch\n";
    ++fail;
  }

  for (int i = 0; i < 50; ++i) {
    std::uint8_t payload = static_cast<std::uint8_t>(i);
    cli->send(std::span<const std::uint8_t>(&payload, 1), ec);
    if (ec) {
      std::cerr << "concurrent send " << i << ": " << ec.message() << "\n";
      ++fail;
      break;
    }
    auto echo = server_conn->receive(ec);
    if (ec) {
      std::cerr << "concurrent srv recv " << i << "\n";
      ++fail;
      break;
    }
    server_conn->send(echo, ec);
    auto back = cli->receive(ec);
    if (ec || back.size() != 1 || back[0] != payload) {
      std::cerr << "concurrent round-trip " << i << "\n";
      ++fail;
      break;
    }
  }

  {
    Config cfg = default_config();
    cfg.handshake.pre_shared_key = {'u', 'n', 'i', 't', '-', 't', 'e', 's', 't', '-', 'p', 's', 'k'};
    auto ln2 = detail::TcpListener::listen("127.0.0.1:0", ec);
    std::unique_ptr<Conn> sc;
    std::error_code sec;
    std::thread th2([&] {
      auto raw = ln2->accept(sec);
      if (raw) {
        sc = serve_conn(std::move(raw), &cfg, sec);
      }
    });
    auto cc = dial(ln2->addr(), &cfg, ec);
    th2.join();
    if (!cc || !sc) {
      std::cerr << "psk handshake failed\n";
      ++fail;
    } else {
      const std::string ping = "ping";
      cc->send(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(ping.data()),
                                             ping.size()),
               ec);
      auto m = sc->receive(ec);
      if (ec || std::string(m.begin(), m.end()) != "ping") {
        std::cerr << "psk recv failed\n";
        ++fail;
      } else {
        const std::string pong = "pong";
        sc->send(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(pong.data()),
                                               pong.size()),
                 ec);
        auto m2 = cc->receive(ec);
        if (ec || std::string(m2.begin(), m2.end()) != "pong") {
          std::cerr << "psk pong failed\n";
          ++fail;
        }
      }
      std::error_code ignored;
      cc->shutdown(std::chrono::milliseconds{2000}, ignored);
      sc->shutdown(std::chrono::milliseconds{2000}, ignored);
    }
    ln2->close();
  }

  {
    Config bad = default_config();
    bad.protocol_version = 42;
    auto c = dial("127.0.0.1:1", &bad, ec);
    if (!ec || ec != errc::unsupported_protocol) {
      std::cerr << "expected unsupported protocol, got " << ec.message() << "\n";
      ++fail;
    }
  }

  {
    std::error_code ignored;
    server_conn->shutdown(std::chrono::milliseconds{2000}, ignored);
    cli->shutdown(std::chrono::milliseconds{2000}, ignored);
  }
  ln->close();

  if (fail) {
    std::cerr << "test_conn FAILED\n";
  } else {
    std::cout << "test_conn OK\n";
  }
  return fail ? 1 : 0;
}
