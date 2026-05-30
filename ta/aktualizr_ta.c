#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "aktualizr_ta.h"

TEE_Result TA_CreateEntryPoint(void)
{
    DMSG("aktualizr TA created");
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
    DMSG("aktualizr TA destroyed");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                    TEE_Param params[4] __unused,
                                    void **sess_ctx __unused)
{
    uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_types != exp)
        return TEE_ERROR_BAD_PARAMETERS;
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx __unused)
{
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx __unused,
                                      uint32_t cmd_id,
                                      uint32_t param_types,
                                      TEE_Param params[4])
{
    switch (cmd_id) {
    case CMD_PROVISION_KEY:
        return cmd_provision_key(param_types, params);
    case CMD_GET_PUBLIC_KEY:
        return cmd_get_public_key(param_types, params);
    case CMD_SIGN_RSA_PSS:
        return cmd_sign_rsa_pss(param_types, params);
    default:
        return TEE_ERROR_NOT_SUPPORTED;
    }
}
