#include "cpptcpduplex/transfer/transfer.hpp"

#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  (void)cpptcpduplex::transfer::validate_frame(std::span<const std::uint8_t>(data, size));
  return 0;
}
