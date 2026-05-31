#include "tee_keystore.h"

#include <array>
#include <mutex>
#include <stdexcept>
#include <vector>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <tee_client_api.h>

#include "crypto/crypto.h"
#include "crypto/openssl_compat.h"
#include "logging/logging.h"

namespace {

constexpr TEEC_UUID kAktualizrTaUuid = {0xa6f79d6e,
                                        0x1b2c,
                                        0x4f8a,
                                        {0x9b, 0xc3, 0xd1, 0xe5, 0xf2, 0xa8, 0x7b, 0x4c}};

constexpr uint32_t kCmdProvisionKey = 0x01;
constexpr uint32_t kCmdGetPublicKey = 0x02;
constexpr uint32_t kCmdSignRsaPss = 0x03;
constexpr uint32_t kProvModeGenerate = 0;

constexpr size_t kRsa2048ModulusLen = 256;
constexpr size_t kRsaPubOutLen = 4 + kRsa2048ModulusLen + 4;
constexpr size_t kRsaSigLen = 256;

class TeeSession {
 public:
  TeeSession() {
    TEEC_Result res = TEEC_InitializeContext(nullptr, &ctx_);
    if (res != TEEC_SUCCESS) {
      throw std::runtime_error("TEEC_InitializeContext failed");
    }

    uint32_t origin = 0;
    res = TEEC_OpenSession(&ctx_, &sess_, &kAktualizrTaUuid, TEEC_LOGIN_PUBLIC, nullptr, nullptr, &origin);
    if (res != TEEC_SUCCESS) {
      TEEC_FinalizeContext(&ctx_);
      throw std::runtime_error("TEEC_OpenSession failed");
    }
  }

  ~TeeSession() {
    TEEC_CloseSession(&sess_);
    TEEC_FinalizeContext(&ctx_);
  }

  TeeSession(const TeeSession &) = delete;
  TeeSession &operator=(const TeeSession &) = delete;

  TEEC_Session *get() { return &sess_; }

 private:
  TEEC_Context ctx_{};
  TEEC_Session sess_{};
};

TeeSession &Session() {
  static TeeSession session;
  return session;
}

uint32_t ReadBe32(const uint8_t *buf) {
  return (static_cast<uint32_t>(buf[0]) << 24U) | (static_cast<uint32_t>(buf[1]) << 16U) |
         (static_cast<uint32_t>(buf[2]) << 8U) | static_cast<uint32_t>(buf[3]);
}

std::string RsaPublicKeyToPem(const uint8_t *buf, size_t len) {
  if (len < kRsaPubOutLen) {
    return {};
  }

  const uint32_t modulus_len = ReadBe32(buf);
  if (modulus_len != kRsa2048ModulusLen || len < 4 + modulus_len + 4) {
    return {};
  }

  const uint8_t *modulus = buf + 4;
  const uint32_t exponent = ReadBe32(buf + 4 + modulus_len);

  StructGuard<RSA> rsa(RSA_new(), RSA_free);
  if (rsa == nullptr) {
    return {};
  }

  BIGNUM *n = BN_bin2bn(modulus, static_cast<int>(modulus_len), nullptr);
  BIGNUM *e = BN_new();
  if (n == nullptr || e == nullptr || BN_set_word(e, exponent) != 1) {
    BN_free(n);
    BN_free(e);
    return {};
  }

#if AKTUALIZR_OPENSSL_PRE_11
  rsa->n = n;
  rsa->e = e;
#else
  if (RSA_set0_key(rsa.get(), n, e, nullptr) != 1) {
    BN_free(n);
    BN_free(e);
    return {};
  }
#endif

  StructGuard<BIO> bio(BIO_new(BIO_s_mem()), BIO_vfree);
  if (bio == nullptr || PEM_write_bio_RSA_PUBKEY(bio.get(), rsa.get()) != 1) {
    return {};
  }

  char *pem = nullptr;
  const long pem_len = BIO_get_mem_data(bio.get(), &pem);  // NOLINT(runtime/int)
  if (pem == nullptr || pem_len <= 0) {
    return {};
  }
  return std::string(pem, static_cast<size_t>(pem_len));
}

}  // namespace

namespace TeeKeystore {

bool IsAvailable() {
  try {
    (void)Session();
    return true;
  } catch (const std::exception &e) {
    LOG_ERROR << "TEE unavailable: " << e.what();
    return false;
  }
}

bool ProvisionUptaneRsa2048() {
  TEEC_Operation op{};
  op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
  op.params[0].value.a = kKeyUptane;
  op.params[0].value.b = kProvModeGenerate;

  uint32_t origin = 0;
  const TEEC_Result res = TEEC_InvokeCommand(Session().get(), kCmdProvisionKey, &op, &origin);
  if (res != TEEC_SUCCESS) {
    LOG_ERROR << "TEE Uptane key provisioning failed: 0x" << std::hex << res;
    return false;
  }
  return true;
}

bool ReadUptanePublicKey(std::string *public_key_pem) {
  if (public_key_pem == nullptr) {
    return false;
  }

  std::array<uint8_t, kRsaPubOutLen> out{};
  TEEC_Operation op{};
  op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
  op.params[0].value.a = kKeyUptane;
  op.params[1].tmpref.buffer = out.data();
  op.params[1].tmpref.size = out.size();

  uint32_t origin = 0;
  TEEC_Result res = TEEC_InvokeCommand(Session().get(), kCmdGetPublicKey, &op, &origin);
  if (res != TEEC_SUCCESS) {
    if (!ProvisionUptaneRsa2048()) {
      return false;
    }
    op.params[1].tmpref.size = out.size();
    res = TEEC_InvokeCommand(Session().get(), kCmdGetPublicKey, &op, &origin);
  }
  if (res != TEEC_SUCCESS) {
    LOG_ERROR << "TEE Uptane public key read failed: 0x" << std::hex << res;
    return false;
  }

  *public_key_pem = RsaPublicKeyToPem(out.data(), op.params[1].tmpref.size);
  return !public_key_pem->empty();
}

std::string SignRsaPssSha256(const std::string &message) {
  std::string digest = Crypto::sha256digest(message);
  std::array<uint8_t, kRsaSigLen> sig{};

  TEEC_Operation op{};
  op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
  op.params[0].tmpref.buffer = const_cast<char *>(digest.data());
  op.params[0].tmpref.size = digest.size();
  op.params[1].tmpref.buffer = sig.data();
  op.params[1].tmpref.size = sig.size();

  uint32_t origin = 0;
  const TEEC_Result res = TEEC_InvokeCommand(Session().get(), kCmdSignRsaPss, &op, &origin);
  if (res != TEEC_SUCCESS) {
    LOG_ERROR << "TEE RSA-PSS signing failed: 0x" << std::hex << res;
    return {};
  }
  return std::string(reinterpret_cast<const char *>(sig.data()), op.params[1].tmpref.size);
}

}  // namespace TeeKeystore
