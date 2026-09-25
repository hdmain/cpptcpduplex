#include "cpptcpduplex/conn.hpp"
#include "cpptcpduplex/detail/socket.hpp"
#include "cpptcpduplex/protocol/protocol.hpp"

#include <utility>

namespace cpptcpduplex {
namespace {

class SocketStream final : public protocol::ByteStream {
 public:
  explicit SocketStream(detail::TcpSocket& sock) : sock_(sock) {}
  std::error_code read_exact(std::span<std::uint8_t> buf) override { return sock_.read_exact(buf); }
  std::error_code write_all(std::span<const std::uint8_t> buf) override {
    return sock_.write_all(buf);
  }

 private:
  detail::TcpSocket& sock_;
};

}  // namespace

Conn::Conn(std::unique_ptr<detail::TcpSocket> sock, crypto::Session sess, FrozenConfig cfg)
    : sock_(std::move(sock)), sess_(std::move(sess)), cfg_(std::move(cfg)) {
  if (cfg_.on_message) {
    deliver_ = std::thread([this] { deliver_loop(); });
  }
  reader_ = std::thread([this] { read_loop(); });
  writer_ = std::thread([this] { write_loop(); });
}

Conn::~Conn() {
  std::error_code ec;
  shutdown(std::chrono::milliseconds{5000}, ec);
  if (reader_.joinable()) {
    reader_.join();
  }
  if (writer_.joinable()) {
    writer_.join();
  }
  if (deliver_.joinable()) {
    deliver_.join();
  }
}

void Conn::send(std::span<const std::uint8_t> payload) {
  std::error_code ec;
  send(payload, ec);
  if (ec) {
    throw Error("send", ec);
  }
}

void Conn::send(std::span<const std::uint8_t> payload, std::error_code& ec) {
  send_for(payload, std::chrono::milliseconds::max(), ec);
}

void Conn::send_for(std::span<const std::uint8_t> payload, std::chrono::milliseconds timeout,
                    std::error_code& ec) {
  ec.clear();
  if (closed_.load()) {
    ec = make_error_code(errc::closed);
    return;
  }
  if (static_cast<int>(payload.size()) > cfg_.max_message_bytes) {
    ec = make_error_code(errc::message_too_large);
    return;
  }

  Outbound out;
  out.typ = protocol::kMsgText;
  out.pt.assign(payload.begin(), payload.end());

  std::unique_lock lock(send_mu_);
  auto pred = [&] {
    return stop_send_ || static_cast<int>(send_q_.size()) < cfg_.send_queue_depth;
  };
  if (timeout == std::chrono::milliseconds::max()) {
    send_cv_.wait(lock, pred);
  } else if (!send_cv_.wait_for(lock, timeout, pred)) {
    ec = make_error_code(errc::timed_out);
    return;
  }
  if (stop_send_) {
    ec = make_error_code(errc::closed);
    return;
  }
  send_q_.push_back(std::move(out));
  send_cv_.notify_all();
}

std::vector<std::uint8_t> Conn::receive() {
  std::error_code ec;
  auto msg = receive(ec);
  if (ec) {
    throw Error("receive", ec);
  }
  return msg;
}

std::vector<std::uint8_t> Conn::receive(std::error_code& ec) {
  return receive_for(std::chrono::milliseconds::max(), ec);
}

std::vector<std::uint8_t> Conn::receive_for(std::chrono::milliseconds timeout, std::error_code& ec) {
  ec.clear();
  if (cfg_.on_message) {
    ec = make_error_code(errc::receive_disabled);
    return {};
  }
  std::unique_lock lock(recv_mu_);
  auto pred = [&] { return recv_closed_ || !recv_q_.empty(); };
  if (timeout == std::chrono::milliseconds::max()) {
    recv_cv_.wait(lock, pred);
  } else if (!recv_cv_.wait_for(lock, timeout, pred)) {
    ec = make_error_code(errc::timed_out);
    return {};
  }
  if (!recv_q_.empty()) {
    auto msg = std::move(recv_q_.front());
    recv_q_.pop_front();
    return msg;
  }
  ec = recv_err_ ? recv_err_ : make_error_code(errc::closed);
  return {};
}

std::uint64_t Conn::callback_dropped() const noexcept { return callback_dropped_.load(); }

void Conn::close() {
  std::error_code ec;
  shutdown(std::chrono::milliseconds::max(), ec);
  if (ec && ec != errc::closed) {
    throw Error("close", ec);
  }
}

void Conn::shutdown(std::chrono::milliseconds wait) {
  std::error_code ec;
  shutdown(wait, ec);
  if (ec && ec != errc::closed) {
    throw Error("shutdown", ec);
  }
}

void Conn::shutdown(std::chrono::milliseconds wait, std::error_code& ec) {
  ec.clear();
  bool expected = false;
  if (!shutdown_started_.compare_exchange_strong(expected, true)) {
    ec = make_error_code(errc::closed);
    return;
  }
  closed_.store(true);

  {
    std::lock_guard lock(send_mu_);
    stop_send_ = true;
  }
  send_cv_.notify_all();

  auto wait_flag = [&](std::atomic<bool>& flag) -> std::error_code {
    std::unique_lock lock(done_mu_);
    if (wait == std::chrono::milliseconds::max()) {
      done_cv_.wait(lock, [&] { return flag.load(); });
      return {};
    }
    if (!done_cv_.wait_for(lock, wait, [&] { return flag.load(); })) {
      return make_error_code(errc::timed_out);
    }
    return {};
  };

  ec = wait_flag(write_done_);

  {
    std::lock_guard lock(jobs_mu_);
    deliver_stop_ = true;
  }
  jobs_cv_.notify_all();

  if (sock_) {
    sock_->close();
  }

  auto ec2 = wait_flag(read_done_);
  if (!ec) {
    ec = ec2;
  }
}

void Conn::abort_recv(std::error_code err) {
  std::lock_guard lock(recv_mu_);
  if (recv_closed_) {
    return;
  }
  recv_closed_ = true;
  if (!err) {
    err = make_error_code(errc::closed);
  }
  recv_err_ = err;
  recv_cv_.notify_all();
}

bool Conn::write_out(const Outbound& out) {
  std::vector<std::uint8_t> sealed;
  if (sess_.seal(out.pt, sealed)) {
    return false;
  }
  SocketStream stream(*sock_);
  return !protocol::write_record(stream, out.typ, sealed);
}

void Conn::write_loop() {
  for (;;) {
    Outbound out;
    bool flushing = false;
    {
      std::unique_lock lock(send_mu_);
      send_cv_.wait(lock, [&] { return stop_send_ || !send_q_.empty(); });
      if (!send_q_.empty()) {
        out = std::move(send_q_.front());
        send_q_.pop_front();
        send_cv_.notify_all();
      } else if (stop_send_) {
        flushing = true;
      }
    }
    if (flushing) {
      // Drain remaining then send close.
      for (;;) {
        Outbound more;
        bool have = false;
        {
          std::lock_guard lock(send_mu_);
          if (!send_q_.empty()) {
            more = std::move(send_q_.front());
            send_q_.pop_front();
            have = true;
          }
        }
        if (!have) {
          break;
        }
        if (!write_out(more)) {
          write_done_.store(true);
          done_cv_.notify_all();
          return;
        }
      }
      Outbound close_msg;
      close_msg.typ = protocol::kMsgClose;
      write_out(close_msg);
      write_done_.store(true);
      done_cv_.notify_all();
      return;
    }
    if (!write_out(out)) {
      write_done_.store(true);
      done_cv_.notify_all();
      return;
    }
  }
}

void Conn::read_loop() {
  SocketStream stream(*sock_);
  for (;;) {
    std::uint8_t msg_type = 0;
    std::vector<std::uint8_t> sealed;
    auto ec = protocol::read_record(stream, msg_type, sealed);
    if (ec) {
      abort_recv(ec);
      read_done_.store(true);
      done_cv_.notify_all();
      return;
    }
    std::vector<std::uint8_t> pt;
    ec = sess_.open(sealed, pt);
    if (ec) {
      abort_recv(ec);
      read_done_.store(true);
      done_cv_.notify_all();
      return;
    }
    switch (msg_type) {
      case protocol::kMsgText: {
        if (static_cast<int>(pt.size()) > cfg_.max_message_bytes) {
          abort_recv(make_error_code(errc::message_too_large));
          read_done_.store(true);
          done_cv_.notify_all();
          return;
        }
        if (cfg_.on_message) {
          std::lock_guard lock(jobs_mu_);
          if (static_cast<int>(msg_jobs_.size()) >= cfg_.on_message_buffer_depth) {
            if (cfg_.disconnect_on_slow_callback_consumer) {
              abort_recv(make_error_code(errc::slow_consumer));
              read_done_.store(true);
              done_cv_.notify_all();
              return;
            }
            callback_dropped_.fetch_add(1);
          } else {
            msg_jobs_.push_back(std::move(pt));
            jobs_cv_.notify_one();
          }
        } else {
          std::unique_lock lock(recv_mu_);
          if (stop_send_) {
            // mirrored: if shutting down while blocked on full receive queue
          }
          // Block if queue full until space or stop — match Go select on stopSend
          recv_cv_.wait(lock, [&] {
            return recv_closed_ || stop_send_ ||
                   static_cast<int>(recv_q_.size()) < cfg_.receive_queue_depth;
          });
          {
            std::lock_guard slock(send_mu_);
            if (stop_send_ && static_cast<int>(recv_q_.size()) >= cfg_.receive_queue_depth) {
              abort_recv(make_error_code(errc::closed));
              read_done_.store(true);
              done_cv_.notify_all();
              return;
            }
          }
          if (!recv_closed_) {
            recv_q_.push_back(std::move(pt));
            recv_cv_.notify_all();
          }
        }
        break;
      }
      case protocol::kMsgPing: {
        Outbound reply;
        reply.typ = protocol::kMsgPong;
        reply.pt = std::move(pt);
        std::unique_lock lock(send_mu_);
        if (stop_send_) {
          abort_recv(make_error_code(errc::closed));
          read_done_.store(true);
          done_cv_.notify_all();
          return;
        }
        send_cv_.wait(lock, [&] {
          return stop_send_ || static_cast<int>(send_q_.size()) < cfg_.send_queue_depth;
        });
        if (stop_send_) {
          abort_recv(make_error_code(errc::closed));
          read_done_.store(true);
          done_cv_.notify_all();
          return;
        }
        send_q_.push_back(std::move(reply));
        send_cv_.notify_all();
        break;
      }
      case protocol::kMsgPong:
        break;
      case protocol::kMsgClose:
        abort_recv(make_error_code(errc::closed));
        read_done_.store(true);
        done_cv_.notify_all();
        return;
      default:
        abort_recv(make_error_code(errc::bad_frame));
        read_done_.store(true);
        done_cv_.notify_all();
        return;
    }
  }
}

void Conn::deliver_loop() {
  auto fn = cfg_.on_message;
  for (;;) {
    std::vector<std::uint8_t> payload;
    {
      std::unique_lock lock(jobs_mu_);
      jobs_cv_.wait(lock, [&] { return deliver_stop_ || !msg_jobs_.empty(); });
      if (!msg_jobs_.empty()) {
        payload = std::move(msg_jobs_.front());
        msg_jobs_.pop_front();
      } else if (deliver_stop_) {
        // Drain remaining
        while (!msg_jobs_.empty()) {
          auto p = std::move(msg_jobs_.front());
          msg_jobs_.pop_front();
          lock.unlock();
          if (fn) {
            fn(std::move(p));
          }
          lock.lock();
        }
        return;
      }
    }
    if (!payload.empty() && fn) {
      fn(std::move(payload));
    }
  }
}

}  // namespace cpptcpduplex
