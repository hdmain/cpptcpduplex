#include "cpptcpduplex/crypto/handshake.hpp"
#include "cpptcpduplex/errors.hpp"
#include "x25519.hpp"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/sha256.h>

#include <algorithm>
#include <array>

namespace cpptcpduplex::crypto {
namespace {

struct Drbg {
  mbedtls_entropy_context entropy{};
  mbedtls_ctr_drbg_context ctr{};
  bool ok{false};

  Drbg() {
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr);
    static const char pers[] = "cpptcpduplex";
    if (mbedtls_ctr_drbg_seed(&ctr, mbedtls_entropy_func, &entropy,
                              reinterpret_cast<const unsigned char*>(pers), sizeof(pers) - 1) ==
        0) {
      ok = true;
    }
  }

  ~Drbg() {
    mbedtls_ctr_drbg_free(&ctr);
    mbedtls_entropy_free(&entropy);
  }

  std::error_code fill(std::span<std::uint8_t> out) {
    if (!ok) {
      return make_error_code(errc::io_error);
    }
    if (mbedtls_ctr_drbg_random(&ctr, out.data(), out.size()) != 0) {
      return make_error_code(errc::io_error);
    }
    return {};
  }
};

}  // namespace

std::array<std::uint8_t, 32> fingerprint_sha256(std::span<const std::uint8_t> pub_key) {
  std::array<std::uint8_t, 32> out{};
  mbedtls_sha256(pub_key.data(), pub_key.size(), out.data(), 0);
  return out;
}

std::error_code client_handshake(protocol::ByteStream& rw, std::uint16_t negotiated_version,
                                 const HandshakeOpts* opts, Session& out) {
  Drbg rng;
  std::array<std::uint8_t, 32> priv{};
  std::array<std::uint8_t, 32> pub{};
  if (auto ec = rng.fill(priv)) {
    return ec;
  }
  x25519_public_from_private(pub, priv);

  if (auto ec = protocol::write_handshake(rw, negotiated_version, pub)) {
    return ec;
  }

  std::uint16_t peer_ver = 0;
  std::vector<std::uint8_t> peer_pub_vec;
  if (auto ec = protocol::read_handshake(rw, peer_ver, peer_pub_vec)) {
    return ec;
  }
  if (peer_ver != negotiated_version || peer_pub_vec.size() != 32) {
    return make_error_code(errc::handshake_authentication);
  }
  if (opts && opts->expected_peer_pubkey_sha256) {
    const auto fp = fingerprint_sha256(peer_pub_vec);
    if (fp != *opts->expected_peer_pubkey_sha256) {
      return make_error_code(errc::peer_fingerprint_mismatch);
    }
  }

  std::array<std::uint8_t, 32> peer_pub{};
  std::copy(peer_pub_vec.begin(), peer_pub_vec.end(), peer_pub.begin());
  std::array<std::uint8_t, 32> shared{};
  x25519_shared_secret(shared, priv, peer_pub);

  std::span<const std::uint8_t> psk;
  if (opts) {
    psk = opts->pre_shared_key;
  }
  return Session::create(shared, psk, out);
}

std::error_code server_handshake(protocol::ByteStream& rw, const HandshakeOpts* opts, Session& out,
                                 std::uint16_t& negotiated_version) {
  Drbg rng;
  std::array<std::uint8_t, 32> priv{};
  std::array<std::uint8_t, 32> pub{};
  if (auto ec = rng.fill(priv)) {
    return ec;
  }
  x25519_public_from_private(pub, priv);

  std::vector<std::uint8_t> peer_pub_vec;
  if (auto ec = protocol::read_handshake(rw, negotiated_version, peer_pub_vec)) {
    return ec;
  }
  if (peer_pub_vec.size() != 32) {
    return make_error_code(errc::bad_handshake);
  }
  if (opts && opts->expected_peer_pubkey_sha256) {
    const auto fp = fingerprint_sha256(peer_pub_vec);
    if (fp != *opts->expected_peer_pubkey_sha256) {
      return make_error_code(errc::peer_fingerprint_mismatch);
    }
  }

  std::array<std::uint8_t, 32> peer_pub{};
  std::copy(peer_pub_vec.begin(), peer_pub_vec.end(), peer_pub.begin());
  std::array<std::uint8_t, 32> shared{};
  x25519_shared_secret(shared, priv, peer_pub);

  if (auto ec = protocol::write_handshake(rw, negotiated_version, pub)) {
    return ec;
  }

  std::span<const std::uint8_t> psk;
  if (opts) {
    psk = opts->pre_shared_key;
  }
  return Session::create(shared, psk, out);
}

}  // namespace cpptcpduplex::crypto
