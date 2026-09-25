#pragma once

#include "cpptcpduplex/config.hpp"
#include "cpptcpduplex/crypto/session.hpp"
#include "cpptcpduplex/errors.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <thread>
#include <vector>

namespace cpptcpduplex {

namespace detail {
class TcpSocket;
}

// Encrypted full-duplex tcpduplex session after handshake.
class Conn {
 public:
  Conn(std::unique_ptr<detail::TcpSocket> sock, crypto::Session sess, FrozenConfig cfg);
  ~Conn();

  Conn(const Conn&) = delete;
  Conn& operator=(const Conn&) = delete;

  // Queues an application message (encrypted as MsgText).
  void send(std::span<const std::uint8_t> payload);
  void send(std::span<const std::uint8_t> payload, std::error_code& ec);
  void send_for(std::span<const std::uint8_t> payload, std::chrono::milliseconds timeout,
                std::error_code& ec);

  // Blocks until the next application message (requires on_message == nullptr).
  std::vector<std::uint8_t> receive();
  std::vector<std::uint8_t> receive(std::error_code& ec);
  std::vector<std::uint8_t> receive_for(std::chrono::milliseconds timeout, std::error_code& ec);

  std::uint64_t callback_dropped() const noexcept;

  void close();
  void shutdown(std::chrono::milliseconds wait = std::chrono::milliseconds::max());
  void shutdown(std::chrono::milliseconds wait, std::error_code& ec);

  int max_message_bytes() const noexcept { return cfg_.max_message_bytes; }
  detail::TcpSocket* underlying() noexcept { return sock_.get(); }
  const detail::TcpSocket* underlying() const noexcept { return sock_.get(); }

 private:
  struct Outbound {
    std::uint8_t typ{};
    std::vector<std::uint8_t> pt;
  };

  void read_loop();
  void write_loop();
  void deliver_loop();
  void abort_recv(std::error_code err);
  bool write_out(const Outbound& out);

  std::unique_ptr<detail::TcpSocket> sock_;
  crypto::Session sess_;
  FrozenConfig cfg_;

  std::mutex send_mu_;
  std::condition_variable send_cv_;
  std::deque<Outbound> send_q_;
  bool stop_send_{false};

  std::mutex recv_mu_;
  std::condition_variable recv_cv_;
  std::deque<std::vector<std::uint8_t>> recv_q_;
  std::error_code recv_err_;
  bool recv_closed_{false};

  std::mutex jobs_mu_;
  std::condition_variable jobs_cv_;
  std::deque<std::vector<std::uint8_t>> msg_jobs_;
  bool deliver_stop_{false};

  std::atomic<std::uint64_t> callback_dropped_{0};
  std::atomic<bool> shutdown_started_{false};
  std::atomic<bool> closed_{false};

  std::thread reader_;
  std::thread writer_;
  std::thread deliver_;
  std::atomic<bool> write_done_{false};
  std::atomic<bool> read_done_{false};
  std::condition_variable done_cv_;
  std::mutex done_mu_;
};

}  // namespace cpptcpduplex
