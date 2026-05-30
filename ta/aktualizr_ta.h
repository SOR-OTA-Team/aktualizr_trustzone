#ifndef AKTUALIZR_TA_H
#define AKTUALIZR_TA_H

#include <tee_internal_api.h>

#define TA_AKTUALIZR_UUID \
    { 0xa6f79d6e, 0x1b2c, 0x4f8a, \
      { 0x9b, 0xc3, 0xd1, 0xe5, 0xf2, 0xa8, 0x7b, 0x4c } }

#define CMD_PROVISION_KEY 0x01
#define CMD_GET_PUBLIC_KEY 0x02
#define CMD_SIGN_RSA_PSS 0x03

#define KEY_TYPE_UPTANE 1
#define PROV_MODE_GENERATE 0

#define UPTANE_RSA_KEY_ID "aktualizr_uptane_rsa2048"
#define UPTANE_RSA_KEY_ID_LEN (sizeof(UPTANE_RSA_KEY_ID) - 1)

#define RSA2048_BITS 2048
#define RSA2048_MODULUS_LEN 256
#define RSA2048_SIG_LEN 256
#define SHA256_DIGEST_LEN 32

TEE_Result cmd_provision_key(uint32_t param_types, TEE_Param params[4]);
TEE_Result cmd_get_public_key(uint32_t param_types, TEE_Param params[4]);
TEE_Result cmd_sign_rsa_pss(uint32_t param_types, TEE_Param params[4]);

#endif /* AKTUALIZR_TA_H */
