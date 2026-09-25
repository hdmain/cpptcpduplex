#include "cpptcpduplex/protocol/protocol.hpp"
#include "cpptcpduplex/errors.hpp"

#include <cstring>
#include <iostream>
#include <vector>

namespace {

class MemStream final : public cpptcpduplex::protocol::ByteStream {
 public:
  std::vector<std::uint8_t> buf;
  std::size_t read_pos{0};

  std::error_code read_exact(std::span<std::uint8_t> out) override {
    if (read_pos + out.size() > buf.size()) {
      return cpptcpduplex::make_error_code(cpptcpduplex::errc::closed);
    }
    std::memcpy(out.data(), buf.data() + read_pos, out.size());
    read_pos += out.size();
    return {};
  }
  std::error_code write_all(std::span<const std::uint8_t> in) override {
    buf.insert(buf.end(), in.begin(), in.end());
    return {};
  }
};

}  // namespace

int test_protocol() {
  int fail = 0;
  MemStream rw;
  std::uint8_t pub[32];
  for (int i = 0; i < 32; ++i) {
    pub[i] = static_cast<std::uint8_t>(i);
  }
  if (auto ec = cpptcpduplex::protocol::write_handshake(rw, 1, pub)) {
    std::cerr << "write_handshake: " << ec.message() << "\n";
    ++fail;
  }
  std::uint16_t ver = 0;
  std::vector<std::uint8_t> got;
  rw.read_pos = 0;
  if (auto ec = cpptcpduplex::protocol::read_handshake(rw, ver, got)) {
    std::cerr << "read_handshake: " << ec.message() << "\n";
    ++fail;
  }
  if (ver != 1 || got.size() != 32) {
    std::cerr << "handshake mismatch\n";
    ++fail;
  }

  MemStream rec;
  std::uint8_t sealed[] = {1, 2, 3, 4, 5};
  if (auto ec = cpptcpduplex::protocol::write_record(rec, cpptcpduplex::protocol::kMsgText, sealed)) {
    std::cerr << "write_record: " << ec.message() << "\n";
    ++fail;
  }
  std::uint8_t typ = 0;
  std::vector<std::uint8_t> out;
  rec.read_pos = 0;
  if (auto ec = cpptcpduplex::protocol::read_record(rec, typ, out)) {
    std::cerr << "read_record: " << ec.message() << "\n";
    ++fail;
  }
  if (typ != cpptcpduplex::protocol::kMsgText || out.size() != 5) {
    std::cerr << "record mismatch\n";
    ++fail;
  }

  if (!cpptcpduplex::protocol::supports_version(1) ||
      cpptcpduplex::protocol::supports_version(42)) {
    std::cerr << "supports_version failed\n";
    ++fail;
  }

  if (fail) {
    std::cerr << "test_protocol FAILED\n";
  } else {
    std::cout << "test_protocol OK\n";
  }
  return fail ? 1 : 0;
}
