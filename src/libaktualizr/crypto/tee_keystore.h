#ifndef TEE_KEYSTORE_H_
#define TEE_KEYSTORE_H_

#include <cstddef>
#include <cstdint>
#include <string>

namespace TeeKeystore {

constexpr uint32_t kKeyUptane = 1;

bool IsAvailable();
bool ProvisionUptaneRsa2048();
bool ReadUptanePublicKey(std::string *public_key_pem);
std::string SignRsaPssSha256(const std::string &message);

}  // namespace TeeKeystore

#endif  // TEE_KEYSTORE_H_
