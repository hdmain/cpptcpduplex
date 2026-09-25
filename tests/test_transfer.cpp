#include "cpptcpduplex/cpptcpduplex.hpp"
#include "cpptcpduplex/detail/socket.hpp"

#include <cstring>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

class MemFile : public cpptcpduplex::transfer::ReaderWriterAt {
 public:
  std::error_code write_at(std::int64_t offset,
                           std::span<const std::uint8_t> buf) override {
    std::lock_guard lock(mu_);
    const auto end = static_cast<std::size_t>(offset) + buf.size();
    if (end > data_.size()) {
      data_.resize(end);
    }
    std::memcpy(data_.data() + offset, buf.data(), buf.size());
    return {};
  }
  std::error_code read_at(std::int64_t offset, std::span<std::uint8_t> buf) override {
    std::lock_guard lock(mu_);
    if (offset >= static_cast<std::int64_t>(data_.size())) {
      return cpptcpduplex::transfer::make_error_code(cpptcpduplex::transfer::errc::other);
    }
    const auto n = std::min(buf.size(), data_.size() - static_cast<std::size_t>(offset));
    std::memcpy(buf.data(), data_.data() + offset, n);
    if (n < buf.size()) {
      return cpptcpduplex::transfer::make_error_code(cpptcpduplex::transfer::errc::other);
    }
    return {};
  }
  std::size_t size() const {
    std::lock_guard lock(mu_);
    return data_.size();
  }
  std::vector<std::uint8_t> bytes() const {
    std::lock_guard lock(mu_);
    return data_;
  }

 private:
  mutable std::mutex mu_;
  std::vector<std::uint8_t> data_;
};

class VecReader : public cpptcpduplex::transfer::ReaderAt {
 public:
  explicit VecReader(std::vector<std::uint8_t> d) : data_(std::move(d)) {}
  std::error_code read_at(std::int64_t offset, std::span<std::uint8_t> buf) override {
    if (offset < 0 || static_cast<std::size_t>(offset) + buf.size() > data_.size()) {
      return cpptcpduplex::transfer::make_error_code(cpptcpduplex::transfer::errc::other);
    }
    std::memcpy(buf.data(), data_.data() + offset, buf.size());
    return {};
  }

 private:
  std::vector<std::uint8_t> data_;
};

}  // namespace

int test_transfer() {
  int fail = 0;
  using namespace cpptcpduplex;

  std::error_code ec;
  auto ln = detail::TcpListener::listen("127.0.0.1:0", ec);
  std::unique_ptr<Conn> srv;
  std::thread th([&] {
    auto raw = ln->accept(ec);
    if (raw) {
      srv = serve_conn(std::move(raw), nullptr, ec);
    }
  });
  auto cli = dial(ln->addr(), nullptr, ec);
  th.join();
  if (!cli || !srv) {
    std::cerr << "transfer pair failed\n";
    return 1;
  }

  std::vector<std::uint8_t> payload(64 << 10);
  for (std::size_t i = 0; i < payload.size(); ++i) {
    payload[i] = static_cast<std::uint8_t>("abcdefgh"[i % 8]);
  }

  MemFile dst;
  transfer::Options opts;
  opts.chunk_size = 16 << 10;
  opts.window = 4;
  opts.ack_every = 2;

  std::error_code recv_ec;
  std::thread recv_th([&] {
    transfer::Meta meta;
    recv_ec = transfer::receive(*srv, dst, 0, meta, &opts);
  });

  transfer::Meta meta;
  meta.name = "blob";
  meta.size = static_cast<std::int64_t>(payload.size());
  VecReader reader(payload);
  auto send_ec = transfer::send(*cli, reader, meta, &opts);
  recv_th.join();

  if (send_ec) {
    std::cerr << "send: " << send_ec.message() << "\n";
    ++fail;
  }
  if (recv_ec) {
    std::cerr << "recv: " << recv_ec.message() << "\n";
    ++fail;
  }
  if (dst.bytes() != payload) {
    std::cerr << "content mismatch len " << dst.size() << " vs " << payload.size() << "\n";
    ++fail;
  }

  // Empty transfer
  {
    auto ln2 = detail::TcpListener::listen("127.0.0.1:0", ec);
    std::unique_ptr<Conn> s2;
    std::thread t2([&] {
      auto raw = ln2->accept(ec);
      if (raw) {
        s2 = serve_conn(std::move(raw), nullptr, ec);
      }
    });
    auto c2 = dial(ln2->addr(), nullptr, ec);
    t2.join();
    MemFile empty_dst;
    std::error_code re;
    std::thread rt([&] {
      transfer::Meta m;
      re = transfer::receive(*s2, empty_dst, 0, m, nullptr);
    });
    transfer::Meta em;
    em.name = "empty";
    em.size = 0;
    VecReader er({});
    auto se = transfer::send(*c2, er, em, nullptr);
    rt.join();
    if (se || re || empty_dst.size() != 0) {
      std::cerr << "empty transfer failed\n";
      ++fail;
    }
    std::error_code ignored;
    c2->shutdown(std::chrono::milliseconds{1000}, ignored);
    s2->shutdown(std::chrono::milliseconds{1000}, ignored);
    ln2->close();
  }

  {
    std::error_code ignored;
    cli->shutdown(std::chrono::milliseconds{2000}, ignored);
    srv->shutdown(std::chrono::milliseconds{2000}, ignored);
  }
  ln->close();

  if (fail) {
    std::cerr << "test_transfer FAILED\n";
  } else {
    std::cout << "test_transfer OK\n";
  }
  return fail ? 1 : 0;
}
