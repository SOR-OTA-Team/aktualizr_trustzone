#include "tee_keystore.h"

namespace TeeKeystore {

bool IsAvailable() { return false; }

bool ProvisionUptaneRsa2048() { return false; }

bool ReadUptanePublicKey(std::string *public_key_pem) {
  if (public_key_pem != nullptr) {
    public_key_pem->clear();
  }
  return false;
}

std::string SignRsaPssSha256(const std::string &message) {
  (void)message;
  return {};
}

}  // namespace TeeKeystore
