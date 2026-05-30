#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "aktualizr_ta.h"

static void write_be32(uint8_t *buf, uint32_t value)
{
    buf[0] = (uint8_t)(value >> 24);
    buf[1] = (uint8_t)(value >> 16);
    buf[2] = (uint8_t)(value >> 8);
    buf[3] = (uint8_t)value;
}

static TEE_Result open_uptane_key(uint32_t flags, TEE_ObjectHandle *key)
{
    return TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                    UPTANE_RSA_KEY_ID, UPTANE_RSA_KEY_ID_LEN,
                                    flags, key);
}

static TEE_Result generate_uptane_rsa_key(void)
{
    TEE_ObjectHandle existing = TEE_HANDLE_NULL;
    TEE_ObjectHandle transient = TEE_HANDLE_NULL;
    TEE_ObjectHandle persistent = TEE_HANDLE_NULL;
    TEE_Attribute exponent;
    uint8_t exp[] = {0x01, 0x00, 0x01};
    TEE_Result res;

    res = open_uptane_key(TEE_DATA_FLAG_ACCESS_READ, &existing);
    if (res == TEE_SUCCESS) {
        TEE_CloseObject(existing);
        return TEE_SUCCESS;
    }

    res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, RSA2048_BITS, &transient);
    if (res != TEE_SUCCESS)
        return res;

    TEE_InitRefAttribute(&exponent, TEE_ATTR_RSA_PUBLIC_EXPONENT, exp, sizeof(exp));
    res = TEE_GenerateKey(transient, RSA2048_BITS, &exponent, 1);
    if (res != TEE_SUCCESS)
        goto out;

    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                     UPTANE_RSA_KEY_ID, UPTANE_RSA_KEY_ID_LEN,
                                     TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE,
                                     transient, NULL, 0, &persistent);
    if (res == TEE_SUCCESS)
        TEE_CloseObject(persistent);

out:
    TEE_FreeTransientObject(transient);
    return res;
}

TEE_Result cmd_provision_key(uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE);
    if (param_types != exp)
        return TEE_ERROR_BAD_PARAMETERS;

    if (params[0].value.a != KEY_TYPE_UPTANE ||
        params[0].value.b != PROV_MODE_GENERATE)
        return TEE_ERROR_BAD_PARAMETERS;

    return generate_uptane_rsa_key();
}

TEE_Result cmd_get_public_key(uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                   TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE);
    TEE_ObjectHandle key = TEE_HANDLE_NULL;
    uint8_t modulus[RSA2048_MODULUS_LEN];
    uint8_t exponent[8];
    size_t modulus_len = sizeof(modulus);
    size_t exponent_len = sizeof(exponent);
    uint32_t exponent_value = 0;
    uint8_t *out;
    TEE_Result res;

    if (param_types != exp)
        return TEE_ERROR_BAD_PARAMETERS;
    if (params[0].value.a != KEY_TYPE_UPTANE)
        return TEE_ERROR_BAD_PARAMETERS;
    if (params[1].memref.size < 4 + RSA2048_MODULUS_LEN + 4)
        return TEE_ERROR_SHORT_BUFFER;

    res = open_uptane_key(TEE_DATA_FLAG_ACCESS_READ, &key);
    if (res != TEE_SUCCESS)
        return res;

    res = TEE_GetObjectBufferAttribute(key, TEE_ATTR_RSA_MODULUS,
                                       modulus, &modulus_len);
    if (res != TEE_SUCCESS)
        goto out;
    res = TEE_GetObjectBufferAttribute(key, TEE_ATTR_RSA_PUBLIC_EXPONENT,
                                       exponent, &exponent_len);
    if (res != TEE_SUCCESS)
        goto out;
    if (modulus_len != RSA2048_MODULUS_LEN || exponent_len == 0 ||
        exponent_len > sizeof(exponent)) {
        res = TEE_ERROR_BAD_FORMAT;
        goto out;
    }

    for (size_t i = 0; i < exponent_len; i++)
        exponent_value = (exponent_value << 8) | exponent[i];

    out = params[1].memref.buffer;
    write_be32(out, RSA2048_MODULUS_LEN);
    TEE_MemMove(out + 4, modulus, RSA2048_MODULUS_LEN);
    write_be32(out + 4 + RSA2048_MODULUS_LEN, exponent_value);
    params[1].memref.size = 4 + RSA2048_MODULUS_LEN + 4;

out:
    TEE_CloseObject(key);
    return res;
}

TEE_Result cmd_sign_rsa_pss(uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                   TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE);
    TEE_ObjectHandle key = TEE_HANDLE_NULL;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TEE_Result res;

    if (param_types != exp)
        return TEE_ERROR_BAD_PARAMETERS;
    if (params[0].memref.size != SHA256_DIGEST_LEN)
        return TEE_ERROR_BAD_PARAMETERS;
    if (params[1].memref.size < RSA2048_SIG_LEN)
        return TEE_ERROR_SHORT_BUFFER;

    res = open_uptane_key(TEE_DATA_FLAG_ACCESS_READ, &key);
    if (res != TEE_SUCCESS)
        return res;

    res = TEE_AllocateOperation(&op, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256,
                                TEE_MODE_SIGN, RSA2048_BITS);
    if (res != TEE_SUCCESS)
        goto out;

    res = TEE_SetOperationKey(op, key);
    if (res != TEE_SUCCESS)
        goto out;

    res = TEE_AsymmetricSignDigest(op, NULL, 0,
                                   params[0].memref.buffer,
                                   params[0].memref.size,
                                   params[1].memref.buffer,
                                   &params[1].memref.size);

out:
    if (op != TEE_HANDLE_NULL)
        TEE_FreeOperation(op);
    TEE_CloseObject(key);
    return res;
}
