#include "cpptcpduplex/protocol/protocol.hpp"

#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

namespace {

class MemStream final : public cpptcpduplex::protocol::ByteStream {
 public:
  explicit MemStream(const uint8_t* data, size_t size) : data_(data), size_(size) {}

  std::error_code read_exact(std::span<std::uint8_t> out) override {
    if (pos_ + out.size() > size_) {
      return std::make_error_code(std::errc::broken_pipe);
    }
    std::memcpy(out.data(), data_ + pos_, out.size());
    pos_ += out.size();
    return {};
  }

  std::error_code write_all(std::span<const std::uint8_t>) override {
    return {};
  }

 private:
  const uint8_t* data_;
  size_t size_;
  size_t pos_{0};
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0) {
    return 0;
  }

  // Alternate between handshake and record parsers based on first byte.
  if ((data[0] & 1) == 0) {
    MemStream stream(data, size);
    std::uint16_t ver = 0;
    std::vector<std::uint8_t> pub;
    (void)cpptcpduplex::protocol::read_handshake(stream, ver, pub);
  } else {
    MemStream stream(data, size);
    std::uint8_t typ = 0;
    std::vector<std::uint8_t> sealed;
    (void)cpptcpduplex::protocol::read_record(stream, typ, sealed);
  }
  return 0;
}
