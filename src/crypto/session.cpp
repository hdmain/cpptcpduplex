#include "cpptcpduplex/crypto/session.hpp"
#include "cpptcpduplex/errors.hpp"
#include "cpptcpduplex/protocol/protocol.hpp"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/gcm.h>
#include <mbedtls/sha256.h>

#include <cstring>
#include <mutex>

namespace cpptcpduplex::crypto {
namespace {

constexpr std::size_t kNonceSize = 12;
constexpr std::size_t kTagSize = 16;

void put_be32(std::uint8_t* p, std::uint32_t v) {
  p[0] = static_cast<std::uint8_t>((v >> 24) & 0xff);
  p[1] = static_cast<std::uint8_t>((v >> 16) & 0xff);
  p[2] = static_cast<std::uint8_t>((v >> 8) & 0xff);
  p[3] = static_cast<std::uint8_t>(v & 0xff);
}

std::error_code random_bytes(std::span<std::uint8_t> out) {
  static std::mutex mu;
  static mbedtls_entropy_context entropy;
  static mbedtls_ctr_drbg_context ctr;
  static bool inited = false;
  std::lock_guard lock(mu);
  if (!inited) {
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr);
    static const char pers[] = "cpptcpduplex-seal";
    if (mbedtls_ctr_drbg_seed(&ctr, mbedtls_entropy_func, &entropy,
                              reinterpret_cast<const unsigned char*>(pers), sizeof(pers) - 1) !=
        0) {
      return make_error_code(errc::io_error);
    }
    inited = true;
  }
  if (mbedtls_ctr_drbg_random(&ctr, out.data(), out.size()) != 0) {
    return make_error_code(errc::io_error);
  }
  return {};
}

}  // namespace

std::vector<std::uint8_t> derive_session_key(std::span<const std::uint8_t> shared_secret,
                                             std::span<const std::uint8_t> psk) {
  std::vector<std::uint8_t> key(32);
  if (psk.empty()) {
    mbedtls_sha256(shared_secret.data(), shared_secret.size(), key.data(), 0);
    return key;
  }
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, shared_secret.data(), shared_secret.size());
  const std::uint8_t zero = 0;
  mbedtls_sha256_update(&ctx, &zero, 1);
  std::uint8_t lb[4];
  put_be32(lb, static_cast<std::uint32_t>(psk.size()));
  mbedtls_sha256_update(&ctx, lb, 4);
  mbedtls_sha256_update(&ctx, psk.data(), psk.size());
  mbedtls_sha256_finish(&ctx, key.data());
  mbedtls_sha256_free(&ctx);
  return key;
}

Session::Session(std::vector<std::uint8_t> key) : key_(std::move(key)) {}

std::error_code Session::create(std::span<const std::uint8_t> shared_secret,
                                std::span<const std::uint8_t> psk, Session& out) {
  out = Session(derive_session_key(shared_secret, psk));
  return {};
}

std::error_code Session::seal(std::span<const std::uint8_t> plaintext,
                              std::vector<std::uint8_t>& out) const {
  const std::size_t max_seal = protocol::kMaxRecordPayload - 1;
  if (kNonceSize + kTagSize + plaintext.size() > max_seal) {
    return make_error_code(errc::bad_frame);
  }
  std::uint8_t nonce[kNonceSize];
  if (auto ec = random_bytes(nonce)) {
    return ec;
  }

  out.resize(kNonceSize + plaintext.size() + kTagSize);
  std::memcpy(out.data(), nonce, kNonceSize);

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key_.data(),
                              static_cast<unsigned int>(key_.size() * 8));
  if (rc != 0) {
    mbedtls_gcm_free(&gcm);
    return make_error_code(errc::other);
  }
  rc = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plaintext.size(), nonce, kNonceSize,
                                 nullptr, 0, plaintext.data(), out.data() + kNonceSize, kTagSize,
                                 out.data() + kNonceSize + plaintext.size());
  mbedtls_gcm_free(&gcm);
  if (rc != 0) {
    return make_error_code(errc::other);
  }
  return {};
}

std::error_code Session::open(std::span<const std::uint8_t> sealed,
                              std::vector<std::uint8_t>& out) const {
  if (sealed.size() < kNonceSize + kTagSize) {
    return make_error_code(errc::bad_frame);
  }
  const std::uint8_t* nonce = sealed.data();
  const std::size_t ct_len = sealed.size() - kNonceSize - kTagSize;
  const std::uint8_t* ct = sealed.data() + kNonceSize;
  const std::uint8_t* tag = sealed.data() + kNonceSize + ct_len;

  out.resize(ct_len);
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key_.data(),
                              static_cast<unsigned int>(key_.size() * 8));
  if (rc != 0) {
    mbedtls_gcm_free(&gcm);
    return make_error_code(errc::other);
  }
  rc = mbedtls_gcm_auth_decrypt(&gcm, ct_len, nonce, kNonceSize, nullptr, 0, tag, kTagSize, ct,
                                out.data());
  mbedtls_gcm_free(&gcm);
  if (rc != 0) {
    return make_error_code(errc::bad_frame);
  }
  return {};
}

}  // namespace cpptcpduplex::crypto
