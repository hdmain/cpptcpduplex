#include "cpptcpduplex/transfer/transfer.hpp"

#include <mbedtls/sha256.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>

#if defined(_WIN32)
#  include <io.h>
#else
#  include <unistd.h>
#endif

namespace cpptcpduplex::transfer {
namespace {

constexpr std::uint8_t kTypeOffer = 1;
constexpr std::uint8_t kTypeAccept = 2;
constexpr std::uint8_t kTypeReject = 3;
constexpr std::uint8_t kTypeChunk = 4;
constexpr std::uint8_t kTypeAck = 5;
constexpr std::uint8_t kTypeDone = 6;
constexpr std::uint8_t kTypeAbort = 7;

constexpr std::uint8_t kMagic[4] = {'T', 'F', 'X', '1'};
constexpr int kHeaderLen = 5;
constexpr int kIdLen = 16;
constexpr int kOfferFixedLen = kHeaderLen + kIdLen + 8 + 32 + 2;
constexpr int kAcceptLen = kHeaderLen + kIdLen + 8;
constexpr int kChunkFixedLen = kHeaderLen + kIdLen + 8;
constexpr int kAckLen = kHeaderLen + kIdLen + 8;
constexpr int kDoneLen = kHeaderLen + kIdLen + 1 + 32;
constexpr int kRejectFixedLen = kHeaderLen + kIdLen + 2;
constexpr int kAbortFixedLen = kHeaderLen + kIdLen + 2;
constexpr int kChunkOverhead = kChunkFixedLen;

void put_be16(std::uint8_t* p, std::uint16_t v) {
  p[0] = static_cast<std::uint8_t>((v >> 8) & 0xff);
  p[1] = static_cast<std::uint8_t>(v & 0xff);
}
void put_be64(std::uint8_t* p, std::uint64_t v) {
  for (int i = 7; i >= 0; --i) {
    p[i] = static_cast<std::uint8_t>(v & 0xff);
    v >>= 8;
  }
}
std::uint16_t get_be16(const std::uint8_t* p) {
  return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}
std::uint64_t get_be64(const std::uint8_t* p) {
  std::uint64_t v = 0;
  for (int i = 0; i < 8; ++i) {
    v = (v << 8) | p[i];
  }
  return v;
}

bool is_zero_hash(const std::array<std::uint8_t, 32>& h) {
  return std::all_of(h.begin(), h.end(), [](std::uint8_t b) { return b == 0; });
}

struct Decoded {
  std::uint8_t typ{};
  ID id{};
  Meta meta{};
  std::int64_t offset{0};
  std::vector<std::uint8_t> data;
  bool ok{false};
  std::array<std::uint8_t, 32> hash{};
  std::string reason;
};

std::error_code decode_frame(std::span<const std::uint8_t> b, Decoded& d) {
  d = {};
  if (b.size() < static_cast<std::size_t>(kHeaderLen)) {
    return make_error_code(errc::bad_frame);
  }
  if (b[0] != kMagic[0] || b[1] != kMagic[1] || b[2] != kMagic[2] || b[3] != kMagic[3]) {
    return make_error_code(errc::bad_frame);
  }
  d.typ = b[4];
  switch (d.typ) {
    case kTypeOffer: {
      if (b.size() < static_cast<std::size_t>(kOfferFixedLen)) {
        return make_error_code(errc::bad_frame);
      }
      std::copy(b.begin() + 5, b.begin() + 21, d.id.begin());
      d.meta.id = d.id;
      d.meta.size = static_cast<std::int64_t>(get_be64(b.data() + 21));
      std::copy(b.begin() + 29, b.begin() + 61, d.meta.hash.begin());
      const int nlen = get_be16(b.data() + 61);
      if (b.size() != static_cast<std::size_t>(kOfferFixedLen + nlen)) {
        return make_error_code(errc::bad_frame);
      }
      d.meta.name.assign(reinterpret_cast<const char*>(b.data() + 63), nlen);
      break;
    }
    case kTypeAccept: {
      if (b.size() != static_cast<std::size_t>(kAcceptLen)) {
        return make_error_code(errc::bad_frame);
      }
      std::copy(b.begin() + 5, b.begin() + 21, d.id.begin());
      d.offset = static_cast<std::int64_t>(get_be64(b.data() + 21));
      break;
    }
    case kTypeReject:
    case kTypeAbort: {
      const int fixed = (d.typ == kTypeReject) ? kRejectFixedLen : kAbortFixedLen;
      if (b.size() < static_cast<std::size_t>(fixed)) {
        return make_error_code(errc::bad_frame);
      }
      std::copy(b.begin() + 5, b.begin() + 21, d.id.begin());
      const int nlen = get_be16(b.data() + 21);
      if (b.size() != static_cast<std::size_t>(fixed + nlen)) {
        return make_error_code(errc::bad_frame);
      }
      d.reason.assign(reinterpret_cast<const char*>(b.data() + 23), nlen);
      break;
    }
    case kTypeChunk: {
      if (b.size() < static_cast<std::size_t>(kChunkFixedLen)) {
        return make_error_code(errc::bad_frame);
      }
      std::copy(b.begin() + 5, b.begin() + 21, d.id.begin());
      d.offset = static_cast<std::int64_t>(get_be64(b.data() + 21));
      d.data.assign(b.begin() + 29, b.end());
      break;
    }
    case kTypeAck: {
      if (b.size() != static_cast<std::size_t>(kAckLen)) {
        return make_error_code(errc::bad_frame);
      }
      std::copy(b.begin() + 5, b.begin() + 21, d.id.begin());
      d.offset = static_cast<std::int64_t>(get_be64(b.data() + 21));
      break;
    }
    case kTypeDone: {
      if (b.size() != static_cast<std::size_t>(kDoneLen)) {
        return make_error_code(errc::bad_frame);
      }
      std::copy(b.begin() + 5, b.begin() + 21, d.id.begin());
      d.ok = b[21] != 0;
      std::copy(b.begin() + 22, b.begin() + 54, d.hash.begin());
      break;
    }
    default:
      return make_error_code(errc::bad_frame);
  }
  return {};
}

std::vector<std::uint8_t> encode_offer(const Meta& m, std::error_code& ec) {
  ec.clear();
  if (m.size < 0) {
    ec = make_error_code(errc::size_mismatch);
    return {};
  }
  if (m.name.size() > 0xffff) {
    ec = make_error_code(errc::bad_frame);
    return {};
  }
  std::vector<std::uint8_t> buf(static_cast<std::size_t>(kOfferFixedLen) + m.name.size());
  std::memcpy(buf.data(), kMagic, 4);
  buf[4] = kTypeOffer;
  std::copy(m.id.begin(), m.id.end(), buf.begin() + 5);
  put_be64(buf.data() + 21, static_cast<std::uint64_t>(m.size));
  std::copy(m.hash.begin(), m.hash.end(), buf.begin() + 29);
  put_be16(buf.data() + 61, static_cast<std::uint16_t>(m.name.size()));
  std::memcpy(buf.data() + 63, m.name.data(), m.name.size());
  return buf;
}

std::vector<std::uint8_t> encode_accept(const ID& id, std::int64_t resume) {
  std::vector<std::uint8_t> buf(kAcceptLen);
  std::memcpy(buf.data(), kMagic, 4);
  buf[4] = kTypeAccept;
  std::copy(id.begin(), id.end(), buf.begin() + 5);
  put_be64(buf.data() + 21, static_cast<std::uint64_t>(resume));
  return buf;
}

std::vector<std::uint8_t> encode_reject(const ID& id, const std::string& reason) {
  auto r = reason;
  if (r.size() > 0xffff) {
    r.resize(0xffff);
  }
  std::vector<std::uint8_t> buf(static_cast<std::size_t>(kRejectFixedLen) + r.size());
  std::memcpy(buf.data(), kMagic, 4);
  buf[4] = kTypeReject;
  std::copy(id.begin(), id.end(), buf.begin() + 5);
  put_be16(buf.data() + 21, static_cast<std::uint16_t>(r.size()));
  std::memcpy(buf.data() + 23, r.data(), r.size());
  return buf;
}

std::vector<std::uint8_t> encode_chunk(const ID& id, std::int64_t offset,
                                       std::span<const std::uint8_t> data) {
  std::vector<std::uint8_t> buf(static_cast<std::size_t>(kChunkFixedLen) + data.size());
  std::memcpy(buf.data(), kMagic, 4);
  buf[4] = kTypeChunk;
  std::copy(id.begin(), id.end(), buf.begin() + 5);
  put_be64(buf.data() + 21, static_cast<std::uint64_t>(offset));
  std::memcpy(buf.data() + 29, data.data(), data.size());
  return buf;
}

std::vector<std::uint8_t> encode_ack(const ID& id, std::int64_t cum) {
  std::vector<std::uint8_t> buf(kAckLen);
  std::memcpy(buf.data(), kMagic, 4);
  buf[4] = kTypeAck;
  std::copy(id.begin(), id.end(), buf.begin() + 5);
  put_be64(buf.data() + 21, static_cast<std::uint64_t>(cum));
  return buf;
}

std::vector<std::uint8_t> encode_done(const ID& id, bool ok, const std::array<std::uint8_t, 32>& hash) {
  std::vector<std::uint8_t> buf(kDoneLen);
  std::memcpy(buf.data(), kMagic, 4);
  buf[4] = kTypeDone;
  std::copy(id.begin(), id.end(), buf.begin() + 5);
  buf[21] = ok ? 1 : 0;
  std::copy(hash.begin(), hash.end(), buf.begin() + 22);
  return buf;
}

std::vector<std::uint8_t> encode_abort(const ID& id, const std::string& reason) {
  auto r = reason;
  if (r.size() > 0xffff) {
    r.resize(0xffff);
  }
  std::vector<std::uint8_t> buf(static_cast<std::size_t>(kAbortFixedLen) + r.size());
  std::memcpy(buf.data(), kMagic, 4);
  buf[4] = kTypeAbort;
  std::copy(id.begin(), id.end(), buf.begin() + 5);
  put_be16(buf.data() + 21, static_cast<std::uint16_t>(r.size()));
  std::memcpy(buf.data() + 23, r.data(), r.size());
  return buf;
}

Options normalize(const Options* opts) {
  Options d = default_options();
  if (!opts) {
    return d;
  }
  Options out = *opts;
  if (out.chunk_size <= 0) {
    out.chunk_size = d.chunk_size;
  }
  if (out.window <= 0) {
    out.window = d.window;
  }
  if (out.ack_every <= 0) {
    out.ack_every = d.ack_every;
  }
  if (out.max_attempts <= 0) {
    out.max_attempts = d.max_attempts;
  }
  return out;
}

int effective_chunk_size(Conn& conn, int want) {
  int max = conn.max_message_bytes() - kChunkOverhead;
  if (max < 1) {
    max = 1;
  }
  if (want <= 0 || want > max) {
    return max;
  }
  return want;
}

std::error_code map_conn_err(const std::error_code& err) {
  if (!err) {
    return {};
  }
  if (err == cpptcpduplex::errc::closed) {
    return make_error_code(errc::closed);
  }
  return err;
}

bool is_retriable(const std::error_code& err) {
  if (!err) {
    return false;
  }
  if (err == errc::rejected || err == errc::hash_mismatch || err == errc::size_mismatch ||
      err == errc::resume_past_end || err == errc::bad_frame ||
      err == cpptcpduplex::errc::canceled || err == cpptcpduplex::errc::timed_out) {
    return false;
  }
  return true;
}

std::error_code hash_reader(ReaderAt& r, std::int64_t size, std::array<std::uint8_t, 32>& out) {
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  std::vector<std::uint8_t> buf(256 << 10);
  std::int64_t off = 0;
  while (off < size) {
    std::size_t n = buf.size();
    if (static_cast<std::int64_t>(n) > size - off) {
      n = static_cast<std::size_t>(size - off);
    }
    if (auto ec = r.read_at(off, std::span(buf.data(), n))) {
      mbedtls_sha256_free(&ctx);
      return ec;
    }
    mbedtls_sha256_update(&ctx, buf.data(), n);
    off += static_cast<std::int64_t>(n);
  }
  mbedtls_sha256_finish(&ctx, out.data());
  mbedtls_sha256_free(&ctx);
  return {};
}

int count_in_flight(std::int64_t acked, std::int64_t next_off, int chunk_size) {
  if (next_off <= acked) {
    return 0;
  }
  const auto remain = next_off - acked;
  const auto cs = static_cast<std::int64_t>(chunk_size);
  return static_cast<int>((remain + cs - 1) / cs);
}

std::string path_base(const std::string& path) {
  const auto pos = path.find_last_of("/\\");
  if (pos == std::string::npos) {
    return path;
  }
  return path.substr(pos + 1);
}

class FileReaderAt : public ReaderAt {
 public:
  explicit FileReaderAt(std::fstream& f) : f_(f) {}
  std::error_code read_at(std::int64_t offset, std::span<std::uint8_t> buf) override {
    f_.seekg(offset);
    f_.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
    if (static_cast<std::size_t>(f_.gcount()) != buf.size()) {
      return make_error_code(errc::other);
    }
    return {};
  }

 private:
  std::fstream& f_;
};

class FileWriterAt : public ReaderWriterAt {
 public:
  explicit FileWriterAt(std::fstream& f) : f_(f) {}
  std::error_code write_at(std::int64_t offset, std::span<const std::uint8_t> buf) override {
    f_.seekp(offset);
    f_.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
    if (!f_) {
      return make_error_code(errc::other);
    }
    return {};
  }
  std::error_code read_at(std::int64_t offset, std::span<std::uint8_t> buf) override {
    f_.seekg(offset);
    f_.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
    if (static_cast<std::size_t>(f_.gcount()) != buf.size()) {
      return make_error_code(errc::other);
    }
    return {};
  }

 private:
  std::fstream& f_;
};

class HashingWriter {
 public:
  HashingWriter(WriterAt& w, std::int64_t resume, std::error_code& ec) : w_(w), offset_(resume) {
    mbedtls_sha256_init(&ctx_);
    mbedtls_sha256_starts(&ctx_, 0);
    if (resume > 0) {
      auto* ra = dynamic_cast<ReaderAt*>(&w);
      if (!ra) {
        ec = make_error_code(errc::other);
        return;
      }
      std::array<std::uint8_t, 32> dummy{};
      // hash existing prefix
      std::vector<std::uint8_t> buf(256 << 10);
      std::int64_t off = 0;
      while (off < resume) {
        std::size_t n = buf.size();
        if (static_cast<std::int64_t>(n) > resume - off) {
          n = static_cast<std::size_t>(resume - off);
        }
        if (auto e = ra->read_at(off, std::span(buf.data(), n))) {
          ec = e;
          return;
        }
        mbedtls_sha256_update(&ctx_, buf.data(), n);
        off += static_cast<std::int64_t>(n);
      }
    }
  }
  ~HashingWriter() { mbedtls_sha256_free(&ctx_); }

  std::error_code write_at(std::span<const std::uint8_t> p, std::int64_t off) {
    if (off != offset_) {
      return make_error_code(errc::bad_frame);
    }
    if (auto ec = w_.write_at(off, p)) {
      return ec;
    }
    mbedtls_sha256_update(&ctx_, p.data(), p.size());
    offset_ += static_cast<std::int64_t>(p.size());
    return {};
  }

  std::array<std::uint8_t, 32> sum() {
    std::array<std::uint8_t, 32> out{};
    mbedtls_sha256_finish(&ctx_, out.data());
    // finish consumes; re-init not needed for one-shot use after done
    return out;
  }

 private:
  WriterAt& w_;
  std::int64_t offset_;
  mbedtls_sha256_context ctx_{};
};

std::error_code finish_send(Conn& conn, const Meta& meta) {
  std::error_code ec;
  conn.send(encode_done(meta.id, true, meta.hash), ec);
  if (ec) {
    return map_conn_err(ec);
  }
  auto msg = conn.receive(ec);
  if (ec) {
    return map_conn_err(ec);
  }
  Decoded dec;
  if (auto e = decode_frame(msg, dec)) {
    return e;
  }
  if (dec.typ != kTypeDone || dec.id != meta.id) {
    return make_error_code(errc::bad_frame);
  }
  if (!dec.ok) {
    return make_error_code(errc::hash_mismatch);
  }
  return {};
}

std::error_code send_once(Conn& conn, ReaderAt& r, Meta meta, const Options& opts) {
  const int chunk_size = effective_chunk_size(conn, opts.chunk_size);
  std::error_code ec;
  auto offer = encode_offer(meta, ec);
  if (ec) {
    return ec;
  }
  conn.send(offer, ec);
  if (ec) {
    return map_conn_err(ec);
  }
  auto msg = conn.receive(ec);
  if (ec) {
    return map_conn_err(ec);
  }
  Decoded dec;
  if (auto e = decode_frame(msg, dec)) {
    return e;
  }
  if (dec.typ == kTypeReject) {
    if (dec.id != meta.id) {
      return make_error_code(errc::bad_frame);
    }
    return make_error_code(errc::rejected);
  }
  if (dec.typ != kTypeAccept || dec.id != meta.id) {
    return make_error_code(errc::bad_frame);
  }
  std::int64_t offset = dec.offset;
  if (offset < 0 || offset > meta.size) {
    return make_error_code(errc::resume_past_end);
  }
  if (opts.on_progress) {
    opts.on_progress(offset, meta.size);
  }
  if (offset == meta.size) {
    return finish_send(conn, meta);
  }

  std::int64_t acked = offset;
  std::int64_t next_off = offset;
  std::vector<std::uint8_t> buf(static_cast<std::size_t>(chunk_size));

  while (acked < meta.size) {
    while (count_in_flight(acked, next_off, chunk_size) < opts.window && next_off < meta.size) {
      std::int64_t n = chunk_size;
      if (next_off + n > meta.size) {
        n = meta.size - next_off;
      }
      if (auto e = r.read_at(next_off, std::span(buf.data(), static_cast<std::size_t>(n)))) {
        return e;
      }
      auto frame = encode_chunk(meta.id, next_off, std::span(buf.data(), static_cast<std::size_t>(n)));
      conn.send(frame, ec);
      if (ec) {
        return map_conn_err(ec);
      }
      next_off += n;
    }
    msg = conn.receive(ec);
    if (ec) {
      return map_conn_err(ec);
    }
    if (auto e = decode_frame(msg, dec)) {
      return e;
    }
    if (dec.typ == kTypeAck) {
      if (dec.id != meta.id || dec.offset < acked || dec.offset > next_off) {
        return make_error_code(errc::bad_frame);
      }
      acked = dec.offset;
      if (opts.on_progress) {
        opts.on_progress(acked, meta.size);
      }
    } else if (dec.typ == kTypeAbort) {
      return make_error_code(errc::aborted);
    } else {
      return make_error_code(errc::bad_frame);
    }
  }
  return finish_send(conn, meta);
}

std::error_code verify_and_ack_done(Conn& conn, const Meta& meta, std::int64_t /*written*/,
                                    const Decoded& dec, const std::array<std::uint8_t, 32>& local) {
  bool ok = true;
  auto expect = meta.hash;
  if (is_zero_hash(expect)) {
    expect = dec.hash;
  }
  if (!is_zero_hash(expect) && local != expect) {
    ok = false;
  }
  if (!is_zero_hash(dec.hash) && dec.hash != local) {
    ok = false;
  }
  std::error_code ec;
  conn.send(encode_done(meta.id, ok, local), ec);
  if (ec) {
    return map_conn_err(ec);
  }
  if (!ok) {
    return make_error_code(errc::hash_mismatch);
  }
  return {};
}

std::error_code receive_once(Conn& conn, WriterAt& w, std::int64_t resume_offset, bool expect_meta,
                             const Meta& want, Meta& out_meta, std::int64_t& written_out,
                             const Options& opts) {
  std::error_code ec;
  auto msg = conn.receive(ec);
  if (ec) {
    written_out = resume_offset;
    return map_conn_err(ec);
  }
  Decoded dec;
  if (auto e = decode_frame(msg, dec)) {
    written_out = resume_offset;
    return e;
  }
  if (dec.typ != kTypeOffer) {
    written_out = resume_offset;
    return make_error_code(errc::bad_frame);
  }
  Meta meta = dec.meta;
  if (expect_meta && meta.id != want.id) {
    conn.send(encode_reject(meta.id, "unexpected transfer id"), ec);
    written_out = resume_offset;
    return make_error_code(errc::bad_frame);
  }
  if (resume_offset > meta.size) {
    conn.send(encode_reject(meta.id, "resume past end"), ec);
    out_meta = meta;
    written_out = resume_offset;
    return make_error_code(errc::resume_past_end);
  }
  if (opts.accept) {
    if (auto aec = opts.accept(meta)) {
      conn.send(encode_reject(meta.id, aec.message()), ec);
      out_meta = meta;
      written_out = resume_offset;
      return make_error_code(errc::rejected);
    }
  }
  conn.send(encode_accept(meta.id, resume_offset), ec);
  if (ec) {
    out_meta = meta;
    written_out = resume_offset;
    return map_conn_err(ec);
  }
  if (opts.on_progress) {
    opts.on_progress(resume_offset, meta.size);
  }
  out_meta = meta;

  if (resume_offset == meta.size) {
    std::array<std::uint8_t, 32> sum{};
    if (auto* ra = dynamic_cast<ReaderAt*>(&w)) {
      if (auto e = hash_reader(*ra, meta.size, sum)) {
        written_out = resume_offset;
        return e;
      }
    }
    msg = conn.receive(ec);
    if (ec) {
      written_out = resume_offset;
      return map_conn_err(ec);
    }
    if (auto e = decode_frame(msg, dec)) {
      written_out = resume_offset;
      return e;
    }
    if (dec.typ != kTypeDone || dec.id != meta.id) {
      written_out = resume_offset;
      return make_error_code(errc::bad_frame);
    }
    written_out = resume_offset;
    return verify_and_ack_done(conn, meta, resume_offset, dec, sum);
  }

  std::error_code hec;
  HashingWriter hw(w, resume_offset, hec);
  if (hec) {
    conn.send(encode_abort(meta.id, hec.message()), ec);
    written_out = resume_offset;
    return hec;
  }

  std::int64_t written = resume_offset;
  int chunks_since_ack = 0;

  while (written < meta.size) {
    msg = conn.receive(ec);
    if (ec) {
      written_out = written;
      return map_conn_err(ec);
    }
    if (auto e = decode_frame(msg, dec)) {
      written_out = written;
      return e;
    }
    if (dec.typ == kTypeChunk) {
      if (dec.id != meta.id || dec.offset != written ||
          dec.offset + static_cast<std::int64_t>(dec.data.size()) > meta.size) {
        written_out = written;
        return make_error_code(errc::bad_frame);
      }
      if (auto e = hw.write_at(dec.data, dec.offset)) {
        conn.send(encode_abort(meta.id, e.message()), ec);
        written_out = written;
        return e;
      }
      written = dec.offset + static_cast<std::int64_t>(dec.data.size());
      ++chunks_since_ack;
      if (opts.on_progress) {
        opts.on_progress(written, meta.size);
      }
      if (chunks_since_ack >= opts.ack_every || written == meta.size) {
        conn.send(encode_ack(meta.id, written), ec);
        if (ec) {
          written_out = written;
          return map_conn_err(ec);
        }
        chunks_since_ack = 0;
      }
    } else if (dec.typ == kTypeDone) {
      if (dec.id != meta.id || written != meta.size) {
        written_out = written;
        return make_error_code(errc::size_mismatch);
      }
      written_out = written;
      return verify_and_ack_done(conn, meta, written, dec, hw.sum());
    } else if (dec.typ == kTypeAbort) {
      written_out = written;
      return make_error_code(errc::aborted);
    } else {
      written_out = written;
      return make_error_code(errc::bad_frame);
    }
  }

  msg = conn.receive(ec);
  if (ec) {
    written_out = written;
    return map_conn_err(ec);
  }
  if (auto e = decode_frame(msg, dec)) {
    written_out = written;
    return e;
  }
  if (dec.typ != kTypeDone || dec.id != meta.id) {
    written_out = written;
    return make_error_code(errc::bad_frame);
  }
  written_out = written;
  return verify_and_ack_done(conn, meta, written, dec, hw.sum());
}

}  // namespace

std::string error_category::message(int ev) const {
  switch (static_cast<errc>(ev)) {
    case errc::ok:
      return "success";
    case errc::bad_frame:
      return "invalid frame";
    case errc::rejected:
      return "offer rejected";
    case errc::aborted:
      return "aborted by peer";
    case errc::size_mismatch:
      return "size mismatch";
    case errc::hash_mismatch:
      return "content hash mismatch";
    case errc::resume_past_end:
      return "resume offset exceeds size";
    case errc::closed:
      return "connection closed during transfer";
    case errc::too_many_retries:
      return "exceeded MaxAttempts";
    default:
      return "transfer error";
  }
}

const std::error_category& category() {
  static error_category cat;
  return cat;
}

Options default_options() {
  return Options{};
}

ID new_id() {
  ID id{};
#if defined(_WIN32)
  for (auto& b : id) {
    unsigned int v = 0;
    if (rand_s(&v) == 0) {
      b = static_cast<std::uint8_t>(v & 0xff);
    }
  }
#else
  if (FILE* f = std::fopen("/dev/urandom", "rb")) {
    std::fread(id.data(), 1, id.size(), f);
    std::fclose(f);
  }
#endif
  return id;
}

std::string id_to_string(const ID& id) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (auto b : id) {
    oss << std::setw(2) << static_cast<int>(b);
  }
  return oss.str();
}

std::optional<ID> parse_id(std::string_view s) {
  if (s.size() != 32) {
    return std::nullopt;
  }
  ID id{};
  auto hex = [](char c) -> int {
    if (c >= '0' && c <= '9') {
      return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
      return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
      return c - 'A' + 10;
    }
    return -1;
  };
  for (std::size_t i = 0; i < 16; ++i) {
    const int hi = hex(s[i * 2]);
    const int lo = hex(s[i * 2 + 1]);
    if (hi < 0 || lo < 0) {
      return std::nullopt;
    }
    id[i] = static_cast<std::uint8_t>((hi << 4) | lo);
  }
  return id;
}

std::error_code send(Conn& conn, ReaderAt& r, Meta meta, const Options* opts) {
  Options o = normalize(opts);
  if (meta.size < 0) {
    return make_error_code(errc::size_mismatch);
  }
  if (meta.id == ID{}) {
    meta.id = new_id();
  }
  if (is_zero_hash(meta.hash)) {
    if (auto ec = hash_reader(r, meta.size, meta.hash)) {
      return ec;
    }
  }

  Conn* cur = &conn;
  std::unique_ptr<Conn> owned;
  int attempts = 0;
  std::error_code last_err;
  for (;;) {
    ++attempts;
    if (attempts > o.max_attempts) {
      return last_err ? last_err : make_error_code(errc::too_many_retries);
    }
    auto err = send_once(*cur, r, meta, o);
    if (!err) {
      return {};
    }
    last_err = err;
    if (!o.redial || !is_retriable(err)) {
      return err;
    }
    std::error_code dec;
    owned = o.redial(dec);
    if (dec || !owned) {
      return make_error_code(errc::other);
    }
    cur = owned.get();
  }
}

std::error_code send_file(Conn& conn, const std::string& path, const Options* opts) {
  std::fstream f(path, std::ios::binary | std::ios::in);
  if (!f) {
    return make_error_code(errc::other);
  }
  f.seekg(0, std::ios::end);
  const auto size = static_cast<std::int64_t>(f.tellg());
  f.seekg(0);
  Meta meta;
  meta.name = path_base(path);
  meta.size = size;
  FileReaderAt reader(f);
  return send(conn, reader, meta, opts);
}

std::error_code receive(Conn& conn, WriterAt& w, std::int64_t resume_offset, Meta& out_meta,
                        const Options* opts) {
  Options o = normalize(opts);
  if (resume_offset < 0) {
    return make_error_code(errc::resume_past_end);
  }
  Meta meta{};
  bool have_meta = false;
  std::int64_t written = resume_offset;
  Conn* cur = &conn;
  std::unique_ptr<Conn> owned;
  int attempts = 0;
  std::error_code last_err;
  for (;;) {
    ++attempts;
    if (attempts > o.max_attempts) {
      out_meta = meta;
      return last_err ? last_err : make_error_code(errc::too_many_retries);
    }
    Meta got{};
    std::int64_t n = written;
    auto err = receive_once(*cur, w, written, have_meta, meta, got, n, o);
    if (!err) {
      out_meta = got;
      return {};
    }
    last_err = err;
    if (got.id != ID{}) {
      meta = got;
      have_meta = true;
    }
    if (n > written) {
      written = n;
    }
    if (!o.redial || !is_retriable(err)) {
      out_meta = meta;
      return err;
    }
    std::error_code dec;
    owned = o.redial(dec);
    if (dec || !owned) {
      out_meta = meta;
      return make_error_code(errc::other);
    }
    cur = owned.get();
  }
}

std::error_code receive_file(Conn& conn, const std::string& dest_path, Meta& out_meta,
                             const Options* opts) {
  std::int64_t resume = 0;
  {
    std::ifstream st(dest_path, std::ios::binary | std::ios::ate);
    if (st) {
      resume = static_cast<std::int64_t>(st.tellg());
    }
  }
  std::fstream f(dest_path, std::ios::binary | std::ios::in | std::ios::out);
  if (!f) {
    f.open(dest_path, std::ios::binary | std::ios::out | std::ios::trunc);
    f.close();
    f.open(dest_path, std::ios::binary | std::ios::in | std::ios::out);
  }
  if (!f) {
    return make_error_code(errc::other);
  }
  FileWriterAt writer(f);
  auto ec = receive(conn, writer, resume, out_meta, opts);
  if (ec) {
    return ec;
  }
  f.close();
  // Truncate to meta.size — platform specific
#if defined(_WIN32)
  // reopen and truncate via filesystem
  std::error_code fec;
  // Use _chsize_s
  FILE* fp = nullptr;
  if (fopen_s(&fp, dest_path.c_str(), "rb+") == 0 && fp) {
    _chsize_s(_fileno(fp), out_meta.size);
    fclose(fp);
  }
#else
  truncate(dest_path.c_str(), out_meta.size);
#endif
  return {};
}

std::error_code validate_frame(std::span<const std::uint8_t> bytes) {
  Decoded d;
  return decode_frame(bytes, d);
}

}  // namespace cpptcpduplex::transfer
