#pragma once

#include "cpptcpduplex/conn.hpp"

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace cpptcpduplex::transfer {

using ID = std::array<std::uint8_t, 16>;

ID new_id();
std::string id_to_string(const ID& id);
std::optional<ID> parse_id(std::string_view s);

struct Meta {
  ID id{};
  std::string name;
  std::int64_t size{0};
  std::array<std::uint8_t, 32> hash{};
};

struct Options {
  int chunk_size{256 << 10};
  int window{32};
  int ack_every{8};
  int max_attempts{8};
  std::function<std::unique_ptr<Conn>(std::error_code&)> redial;
  std::function<void(std::int64_t transferred, std::int64_t total)> on_progress;
  std::function<std::error_code(const Meta&)> accept;
};

Options default_options();

enum class errc {
  ok = 0,
  bad_frame,
  rejected,
  aborted,
  size_mismatch,
  hash_mismatch,
  resume_past_end,
  closed,
  too_many_retries,
  other,
};

class error_category : public std::error_category {
 public:
  const char* name() const noexcept override { return "cpptcpduplex.transfer"; }
  std::string message(int ev) const override;
};

const std::error_category& category();
inline std::error_code make_error_code(errc e) {
  return {static_cast<int>(e), category()};
}

// Abstract random-access source/sink for Send/Receive.
class ReaderAt {
 public:
  virtual ~ReaderAt() = default;
  virtual std::error_code read_at(std::int64_t offset, std::span<std::uint8_t> buf) = 0;
};

class WriterAt {
 public:
  virtual ~WriterAt() = default;
  virtual std::error_code write_at(std::int64_t offset, std::span<const std::uint8_t> buf) = 0;
};

class ReaderWriterAt : public ReaderAt, public WriterAt {};

std::error_code send(Conn& conn, ReaderAt& r, Meta meta, const Options* opts);
std::error_code send_file(Conn& conn, const std::string& path, const Options* opts);

std::error_code receive(Conn& conn, WriterAt& w, std::int64_t resume_offset, Meta& out_meta,
                        const Options* opts);
std::error_code receive_file(Conn& conn, const std::string& dest_path, Meta& out_meta,
                             const Options* opts);

}  // namespace cpptcpduplex::transfer

namespace std {
template <>
struct is_error_code_enum<cpptcpduplex::transfer::errc> : true_type {};
}
