// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 *
 * ele_rsa.c — ELE PKCS#11 RSA Sign and Verify API implementation.
 *
 * Implements PKCS#11 RSA signing and verification with dynamic module
 * loading:
 *
 *   1. dlopen  → load the PKCS#11 .so
 *   2. dlsym   → resolve C_GetFunctionList
 *   3. C_GetFunctionList → obtain full function vtable
 *   4. C_Initialize / C_GetSlotList / C_OpenSession / C_Login
 *   5. C_FindObjects* → locate key by CKA_ID (private for sign,
 *                        public for verify)
 *   6. C_SignInit / C_Sign    → sign data
 *      C_VerifyInit / C_Verify → verify signature
 *   7. C_Logout / C_CloseSession / C_Finalize / dlclose
 *
 * Error convention: system errors return negative errno values;
 * PKCS#11 CKR errors are stored in the context and reported via
 * ele_pkcs11_rsa_strerror().
 */

#include "imx_rsa.h"
#include <pkcs11.h>

#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * Debug printing: enabled by default so the user can diagnose failures on
 * the target hardware.  Set ELE_PKCS11_RSA_DEBUG=0 in the environment or
 * compile with -DELE_PKCS11_RSA_DEBUG=0 to silence.
 */
#ifndef ELE_PKCS11_RSA_DEBUG
#define ELE_PKCS11_RSA_DEBUG  0
#endif

#define DBG(...)  do { \
    if (ELE_PKCS11_RSA_DEBUG) \
        fprintf(stderr, "DBG [ele_pkcs11_rsa] " __VA_ARGS__); \
} while (0)

#define DBG_ERR(...)  fprintf(stderr, "ERROR [ele_pkcs11_rsa] " __VA_ARGS__)

/* ======================================================================
 * Internal context structure
 * ====================================================================== */

struct ele_pkcs11_rsa {
    /* Dynamic library handle (from dlopen). */
    void                *module;

    /* PKCS#11 function table (from C_GetFunctionList). */
    CK_FUNCTION_LIST_PTR funcs;

    /* Open session handle. */
    CK_SESSION_HANDLE    session;

    /* Key object handle (private key for sign, public key for verify). */
    CK_OBJECT_HANDLE     key_handle;

    /* Cached PSS parameters. */
    CK_RSA_PKCS_PSS_PARAMS pss_params;

    /* State flags. */
    int initialized;      /**< C_Initialize has been called. */
    int session_open;     /**< C_OpenSession succeeded. */
    int logged_in;        /**< C_Login succeeded. */

    /* Last PKCS#11 error code (for ele_pkcs11_rsa_strerror). */
    CK_RV                last_ckr;
};

/* ======================================================================
 * PKCS#11 error → string mapping
 * ====================================================================== */

static const char *ckr_to_string(CK_RV rv)
{
    switch (rv) {
    case CKR_OK:                            return "OK";
    case CKR_CANCEL:                        return "Cancel";
    case CKR_HOST_MEMORY:                   return "Host memory";
    case CKR_SLOT_ID_INVALID:               return "Slot ID invalid";
    case CKR_GENERAL_ERROR:                 return "General error";
    case CKR_FUNCTION_FAILED:               return "Function failed";
    case CKR_ARGUMENTS_BAD:                 return "Bad arguments";
    case CKR_NO_EVENT:                      return "No event";
    case CKR_ATTRIBUTE_READ_ONLY:           return "Attribute read-only";
    case CKR_ATTRIBUTE_SENSITIVE:           return "Attribute sensitive";
    case CKR_ATTRIBUTE_TYPE_INVALID:        return "Attribute type invalid";
    case CKR_ATTRIBUTE_VALUE_INVALID:       return "Attribute value invalid";
    case CKR_DATA_INVALID:                  return "Data invalid";
    case CKR_DATA_LEN_RANGE:                return "Data length range invalid";
    case CKR_DEVICE_ERROR:                  return "Device error";
    case CKR_DEVICE_MEMORY:                 return "Device memory";
    case CKR_FUNCTION_NOT_SUPPORTED:        return "Function not supported";
    case CKR_KEY_HANDLE_INVALID:            return "Key handle invalid";
    case CKR_KEY_SIZE_RANGE:                return "Key size range invalid";
    case CKR_KEY_TYPE_INCONSISTENT:         return "Key type inconsistent";
    case CKR_KEY_FUNCTION_NOT_PERMITTED:    return "Key function not permitted";
    case CKR_MECHANISM_INVALID:             return "Mechanism invalid";
    case CKR_MECHANISM_PARAM_INVALID:       return "Mechanism param invalid";
    case CKR_OBJECT_HANDLE_INVALID:         return "Object handle invalid";
    case CKR_OPERATION_ACTIVE:              return "Operation active";
    case CKR_OPERATION_NOT_INITIALIZED:     return "Operation not initialized";
    case CKR_PIN_INCORRECT:                 return "PIN incorrect";
    case CKR_PIN_INVALID:                   return "PIN invalid";
    case CKR_SESSION_HANDLE_INVALID:        return "Session handle invalid";
    case CKR_SIGNATURE_INVALID:             return "Signature invalid";
    case CKR_SIGNATURE_LEN_RANGE:           return "Signature length range";
    case CKR_TOKEN_NOT_PRESENT:             return "Token not present";
    case CKR_USER_NOT_LOGGED_IN:            return "User not logged in";
    case CKR_USER_PIN_NOT_INITIALIZED:      return "User PIN not initialized";
    case CKR_BUFFER_TOO_SMALL:              return "Buffer too small";
    case CKR_CRYPTOKI_NOT_INITIALIZED:      return "Cryptoki not initialized";
    case CKR_CRYPTOKI_ALREADY_INITIALIZED:  return "Cryptoki already initialized";
    case CKR_FUNCTION_REJECTED:             return "Function rejected";
    default:
        return "Unknown PKCS#11 error";
    }
}

/* ======================================================================
 * Public: ele_pkcs11_rsa_strerror
 * ====================================================================== */

const char *ele_pkcs11_rsa_strerror(int err)
{
    switch (err) {
    case 0:              return "Success";
    case -EINVAL:        return "Invalid parameter";
    case -ENOMEM:        return "Memory allocation failed";
    case -ENOENT:        return "Key not found";
    case -ENODEV:        return "PKCS#11 device not available";
    case -EIO:           return "PKCS#11 operation failed";
    case -EACCES:        return "Permission denied or PIN incorrect";
    case -EBADMSG:       return "Signature verification failed";
    default:
        if (err < 0)
            return "Unknown system error";
        return ckr_to_string((CK_RV)(unsigned int)err);
    }
}

/* ======================================================================
 * Internal helpers
 * ====================================================================== */

/**
 * pkcs11_init_module — Load and initialise a PKCS#11 module.
 *
 * @param[out] ctx    Context (module, funcs fields filled on success).
 * @param[in]  path   Path to the PKCS#11 shared library.
 *
 * @return 0 on success, or a negative errno value.
 */
static int pkcs11_init_module(struct ele_pkcs11_rsa *ctx, const char *path)
{
    CK_RV (*get_func_list)(CK_FUNCTION_LIST_PTR_PTR);
    CK_RV rv;

    DBG("dlopen(\"%s\") ...\n", path);
    ctx->module = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!ctx->module) {
        DBG_ERR("dlopen failed: %s\n", dlerror());
        return -ENODEV;
    }

    DBG("dlsym(C_GetFunctionList) ...\n");
    *(void **)(&get_func_list) = dlsym(ctx->module, "C_GetFunctionList");
    if (!get_func_list) {
        DBG_ERR("dlsym(C_GetFunctionList) failed: %s\n", dlerror());
        dlclose(ctx->module);
        ctx->module = NULL;
        return -ENODEV;
    }

    DBG("C_GetFunctionList ...\n");
    rv = get_func_list(&ctx->funcs);
    if (rv != CKR_OK) {
        DBG_ERR("C_GetFunctionList failed: CKR=0x%lx\n", (unsigned long)rv);
        ctx->last_ckr = rv;
        dlclose(ctx->module);
        ctx->module = NULL;
        return -EIO;
    }

    DBG("C_Initialize ...\n");
    rv = ctx->funcs->C_Initialize(NULL);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        DBG_ERR("C_Initialize failed: CKR=0x%lx (%s)\n",
                (unsigned long)rv, ckr_to_string(rv));
        ctx->last_ckr = rv;
        dlclose(ctx->module);
        ctx->module = NULL;
        return -EIO;
    }
    if (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
        DBG("C_Initialize: already initialized\n");
    ctx->initialized = 1;

    return 0;
}

/**
 * pkcs11_open_session — Open a PKCS#11 session on the first token-present
 *                        slot.
 *
 * @param[in,out] ctx  Context (session field set on success).
 *
 * @return 0 on success, or a negative errno value.
 */
static int pkcs11_open_session(struct ele_pkcs11_rsa *ctx)
{
    CK_SLOT_ID slots[16];
    CK_ULONG slot_count;
    CK_RV rv;

    DBG("C_GetSlotList(CK_TRUE) ...\n");
    slot_count = sizeof(slots) / sizeof(slots[0]);
    rv = ctx->funcs->C_GetSlotList(CK_TRUE, slots, &slot_count);
    if (rv != CKR_OK) {
        DBG_ERR("C_GetSlotList failed: CKR=0x%lx (%s)\n",
                (unsigned long)rv, ckr_to_string(rv));
        ctx->last_ckr = rv;
        return -ENODEV;
    }
    if (slot_count == 0) {
        DBG_ERR("C_GetSlotList returned 0 slots (token not present?)\n");
        return -ENODEV;
    }
    DBG("C_GetSlotList: %lu slot(s), using slot 0x%lx\n",
        (unsigned long)slot_count, (unsigned long)slots[0]);

    DBG("C_OpenSession ...\n");
    rv = ctx->funcs->C_OpenSession(slots[0],
                                    CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                    NULL, NULL,
                                    &ctx->session);
    if (rv != CKR_OK) {
        DBG_ERR("C_OpenSession failed: CKR=0x%lx (%s)\n",
                (unsigned long)rv, ckr_to_string(rv));
        ctx->last_ckr = rv;
        return -EIO;
    }
    ctx->session_open = 1;
    DBG("C_OpenSession OK, session=0x%lx\n", (unsigned long)ctx->session);

    return 0;
}

/**
 * pkcs11_login — Log in to the token.
 *
 * @param[in,out] ctx  Context (logged_in flag set on success).
 * @param[in]     pin  User PIN string, or NULL to skip login.
 *
 * @return 0 on success, or a negative errno value.
 */
static int pkcs11_login(struct ele_pkcs11_rsa *ctx, const char *pin)
{
    CK_RV rv = 0;

    /* When pin is NULL or empty, pass NULL pPin with ulPinLen=0
     * (per PKCS#11 spec: zero-length pin means pPin should be NULL).
     * This matches pkcs11-tool --login without --pin on NXP SMW. */
    DBG("C_Login(CKU_USER) ...\n");
    rv = ctx->funcs->C_Login(ctx->session, CKU_USER,
                              (CK_UTF8CHAR_PTR)(pin && pin[0] ? pin : NULL),
                              (CK_ULONG)(pin ? strlen(pin) : 0));
    if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
        DBG_ERR("C_Login failed: CKR=0x%lx (%s)\n",
                (unsigned long)rv, ckr_to_string(rv));
        ctx->last_ckr = rv;
        return -EACCES;
    }
    ctx->logged_in = 1;
    DBG("C_Login OK\n");

    return 0;
}

/**
 * pkcs11_find_key — Find a key object by CKA_ID and class.
 *
 * @param[in,out] ctx       Context (key_handle field set on success).
 * @param[in]     key_id    Key identifier bytes.
 * @param[in]     key_id_len  Length of key_id.
 * @param[in]     obj_class Key object class (CKO_PRIVATE_KEY for sign,
 *                           CKO_PUBLIC_KEY for verify).
 *
 * @return 0 on success, or a negative errno value.
 */
static int pkcs11_find_key(struct ele_pkcs11_rsa *ctx,
                            const uint8_t *key_id,
                            size_t key_id_len,
                            CK_OBJECT_CLASS obj_class)
{
    CK_KEY_TYPE     key_type  = CKK_RSA;
    CK_BBOOL        true_val = CK_TRUE;
    CK_ATTRIBUTE    tmpl[] = {
        {CKA_CLASS,   &obj_class, sizeof(obj_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_ID,      (void *)key_id, (CK_ULONG)key_id_len},
        {CKA_TOKEN,   &true_val, sizeof(true_val)},
    };
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_ULONG obj_count = 0;
    CK_RV rv;
    size_t tmpl_count = sizeof(tmpl) / sizeof(tmpl[0]);
    size_t i;

    DBG("C_FindObjectsInit (class=%lu + CKK_RSA + CKA_ID=",
        (unsigned long)obj_class);
    for (i = 0; i < key_id_len; i++)
        fprintf(stderr, "%02x", key_id[i]);
    fprintf(stderr, ") ...\n");

    rv = ctx->funcs->C_FindObjectsInit(ctx->session, tmpl, (CK_ULONG)tmpl_count);
    if (rv != CKR_OK) {
        DBG_ERR("C_FindObjectsInit failed: CKR=0x%lx (%s)\n",
                (unsigned long)rv, ckr_to_string(rv));
        ctx->last_ckr = rv;
        return -EIO;
    }

    rv = ctx->funcs->C_FindObjects(ctx->session, &obj, 1, &obj_count);
    if (rv != CKR_OK) {
        DBG_ERR("C_FindObjects failed: CKR=0x%lx (%s)\n",
                (unsigned long)rv, ckr_to_string(rv));
        ctx->last_ckr = rv;
        ctx->funcs->C_FindObjectsFinal(ctx->session);
        return -EIO;
    }

    /* Terminate the search. */
    rv = ctx->funcs->C_FindObjectsFinal(ctx->session);
    if (rv != CKR_OK)
        ctx->last_ckr = rv;

    if (obj_count == 0 || obj == CK_INVALID_HANDLE) {
        DBG_ERR("C_FindObjects: key not found (count=%lu)\n",
                (unsigned long)obj_count);
        return -ENOENT;
    }

    DBG("C_FindObjects: found key, handle=0x%lx\n", (unsigned long)obj);
    ctx->key_handle = obj;
    return 0;
}

/* ======================================================================
 * Internal: common init (shared by sign_init and verify_init)
 * ====================================================================== */

/**
 * pkcs11_init_common — Common initialisation for PKCS#11 RSA operations.
 *
 * Loads the PKCS#11 module, opens a session, logs in, and finds the key
 * identified by @p key_id with the given @p key_class (CKO_PRIVATE_KEY
 * for sign, CKO_PUBLIC_KEY for verify).
 *
 * @param[in] module_path  Path to PKCS#11 .so (NULL for default).
 * @param[in] key_id       Key identifier bytes.
 * @param[in] key_id_len   Length of key_id.
 * @param[in] pin          User PIN, or NULL.
 * @param[in] key_class    CKO_PRIVATE_KEY or CKO_PUBLIC_KEY.
 *
 * @return New context on success, NULL on failure (errno set).
 */
static struct ele_pkcs11_rsa *pkcs11_init_common(
    const char *module_path,
    const uint8_t *key_id, size_t key_id_len,
    const char *pin,
    CK_OBJECT_CLASS key_class)
{
    struct ele_pkcs11_rsa *ctx;
    int ret;

    /* ---- Validate parameters ---- */
    if (!key_id || key_id_len == 0 || key_id_len > ELE_PKCS11_RSA_MAX_KEY_ID_LEN) {
        errno = EINVAL;
        return NULL;
    }

    /* Use default module path if none given. */
    if (!module_path)
        module_path = ELE_PKCS11_RSA_DEFAULT_MODULE;

    DBG("=== pkcs11_init_common ===\n");
    DBG("  module_path = %s\n", module_path);
    DBG("  key_id_len  = %zu\n", key_id_len);
    DBG("  pin         = %s\n", pin ? "(provided)" : "NULL");
    DBG("  key_class   = %lu (%s)\n", (unsigned long)key_class,
        key_class == CKO_PRIVATE_KEY ? "PRIVATE" : "PUBLIC");

    /* ---- Allocate context ---- */
    ctx = (struct ele_pkcs11_rsa *)calloc(1, sizeof(*ctx));
    if (!ctx) {
        errno = ENOMEM;
        return NULL;
    }

    ctx->key_handle = CK_INVALID_HANDLE;

    /* ---- Load PKCS#11 module ---- */
    ret = pkcs11_init_module(ctx, module_path);
    if (ret) {
        DBG_ERR("pkcs11_init_module failed (errno=%d)\n", -ret);
        errno = -ret;
        goto fail;
    }
    DBG("Module loaded and initialized.\n");

    /* ---- Open session ---- */
    ret = pkcs11_open_session(ctx);
    if (ret) {
        DBG_ERR("pkcs11_open_session failed (errno=%d)\n", -ret);
        errno = -ret;
        goto fail;
    }
    DBG("Session opened.\n");

    /* ---- Login ---- */
    ret = pkcs11_login(ctx, pin);
    if (ret) {
        DBG_ERR("pkcs11_login failed (errno=%d)\n", -ret);
        errno = -ret;
        goto fail;
    }
    DBG("Login OK.\n");

    /* ---- Find key ---- */
    ret = pkcs11_find_key(ctx, key_id, key_id_len, key_class);
    if (ret) {
        DBG_ERR("pkcs11_find_key failed (errno=%d)\n", -ret);
        errno = -ret;
        goto fail;
    }
    DBG("Key found, handle=0x%lx\n", (unsigned long)ctx->key_handle);

    /* ---- Populate PSS parameters ---- */
    ctx->pss_params.hashAlg = CKM_SHA256;
    ctx->pss_params.mgf     = CKG_MGF1_SHA256;
    ctx->pss_params.sLen    = 32;

    DBG("=== pkcs11_init_common OK ===\n");
    return ctx;

fail:
    ele_pkcs11_rsa_free(ctx);
    return NULL;
}

/* ======================================================================
 * Public: ele_pkcs11_rsa_sign_init
 * ====================================================================== */

struct ele_pkcs11_rsa *ele_pkcs11_rsa_sign_init(
    const char *module_path,
    const uint8_t *key_id, size_t key_id_len,
    const char *pin,
    enum ele_pkcs11_rsa_mechanism mechanism)
{
    (void)mechanism;
    return pkcs11_init_common(module_path, key_id, key_id_len, pin,
                              CKO_PRIVATE_KEY);
}

/* ======================================================================
 * Public: ele_pkcs11_rsa_sign
 * ====================================================================== */

int ele_pkcs11_rsa_sign(struct ele_pkcs11_rsa *ctx,
                         const uint8_t *data, size_t data_len,
                         uint8_t **sig, size_t *sig_len)
{
    CK_MECHANISM mech;
    CK_RV rv;
    CK_ULONG ck_sig_len;

    if (!ctx || !data || !sig || !sig_len)
        return -EINVAL;

    *sig     = NULL;
    *sig_len = 0;

    /* ---- Set up signing mechanism ---- */
    memset(&mech, 0, sizeof(mech));
    mech.mechanism     = CKM_SHA256_RSA_PKCS_PSS;
    mech.pParameter    = &ctx->pss_params;
    mech.ulParameterLen = sizeof(ctx->pss_params);

    DBG("C_SignInit(mech=CKM_SHA256_RSA_PKCS_PSS, key=0x%lx) ...\n",
        (unsigned long)ctx->key_handle);
    rv = ctx->funcs->C_SignInit(ctx->session, &mech, ctx->key_handle);
    if (rv != CKR_OK) {
        DBG_ERR("C_SignInit failed: CKR=0x%lx (%s)\n",
                (unsigned long)rv, ckr_to_string(rv));
        ctx->last_ckr = rv;
        return -EIO;
    }
    DBG("C_SignInit OK\n");

    /* ---- Two-call C_Sign with the raw message data.
     *   CKM_SHA256_RSA_PKCS_PSS is a DigestSign mechanism — the token
     *   hashes the data with SHA-256 internally, then applies RSA-PSS.
     *   First call with NULL output gets the signature length.
     *   Second call with allocated buffer produces the actual signature.
     */
    ck_sig_len = 0;
    DBG("C_Sign (first call, length query) data_len=%zu ...\n", data_len);
    rv = ctx->funcs->C_Sign(ctx->session,
                             (CK_BYTE_PTR)data, (CK_ULONG)data_len,
                             NULL, &ck_sig_len);
    if (rv != CKR_OK) {
        DBG_ERR("C_Sign (length query) failed: CKR=0x%lx (%s)\n",
                (unsigned long)rv, ckr_to_string(rv));
        ctx->last_ckr = rv;
        return -EIO;
    }
    DBG("C_Sign (length query): sig_len=%lu\n", (unsigned long)ck_sig_len);

    /* Sanity check. */
    if (ck_sig_len == 0 || ck_sig_len > ELE_PKCS11_RSA_MAX_SIGNATURE_SIZE) {
        DBG_ERR("C_Sign returned invalid signature length %lu\n",
                (unsigned long)ck_sig_len);
        return -EIO;
    }

    /* Allocate output buffer. */
    *sig = (uint8_t *)malloc((size_t)ck_sig_len);
    if (!*sig) {
        DBG_ERR("malloc(%lu) failed\n", (unsigned long)ck_sig_len);
        return -ENOMEM;
    }

    /* Second call: produce the actual signature. */
    DBG("C_Sign (second call, actual signature) ...\n");
    rv = ctx->funcs->C_Sign(ctx->session,
                             (CK_BYTE_PTR)data, (CK_ULONG)data_len,
                             (CK_BYTE_PTR)*sig, &ck_sig_len);
    if (rv != CKR_OK) {
        DBG_ERR("C_Sign (actual signature) failed: CKR=0x%lx (%s)\n",
                (unsigned long)rv, ckr_to_string(rv));
        ctx->last_ckr = rv;
        free(*sig);
        *sig = NULL;
        return -EIO;
    }
    DBG("C_Sign OK, sig_len=%lu\n", (unsigned long)ck_sig_len);

    *sig_len = (size_t)ck_sig_len;

    return 0;
}

/* ======================================================================
 * Public: ele_pkcs11_rsa_verify_init
 * ====================================================================== */

struct ele_pkcs11_rsa *ele_pkcs11_rsa_verify_init(
    const char *module_path,
    const uint8_t *key_id, size_t key_id_len,
    const char *pin,
    enum ele_pkcs11_rsa_mechanism mechanism)
{
    (void)mechanism;
    return pkcs11_init_common(module_path, key_id, key_id_len, pin,
                              CKO_PUBLIC_KEY);
}

/* ======================================================================
 * Public: ele_pkcs11_rsa_verify
 * ====================================================================== */

int ele_pkcs11_rsa_verify(struct ele_pkcs11_rsa *ctx,
                           const uint8_t *data, size_t data_len,
                           const uint8_t *sig, size_t sig_len)
{
    CK_MECHANISM mech;
    CK_RV rv;

    if (!ctx || !data || !sig || sig_len == 0)
        return -EINVAL;

    /* ---- Set up verification mechanism ---- */
    memset(&mech, 0, sizeof(mech));
    mech.mechanism     = CKM_SHA256_RSA_PKCS_PSS;
    mech.pParameter    = &ctx->pss_params;
    mech.ulParameterLen = sizeof(ctx->pss_params);

    DBG("C_VerifyInit(mech=CKM_SHA256_RSA_PKCS_PSS, key=0x%lx) ...\n",
        (unsigned long)ctx->key_handle);
    rv = ctx->funcs->C_VerifyInit(ctx->session, &mech, ctx->key_handle);
    if (rv != CKR_OK) {
        DBG_ERR("C_VerifyInit failed: CKR=0x%lx (%s)\n",
                (unsigned long)rv, ckr_to_string(rv));
        ctx->last_ckr = rv;
        return -EIO;
    }
    DBG("C_VerifyInit OK\n");

    /* ---- C_Verify with raw message data (single call).
     *   CKM_SHA256_RSA_PKCS_PSS is a DigestVerify mechanism — the token
     *   hashes the data with SHA-256 internally, then verifies the RSA-PSS
     *   signature.  Unlike C_Sign, no two-call length query is needed since
     *   the signature length is already known.
     */
    DBG("C_Verify data_len=%zu, sig_len=%zu ...\n", data_len, sig_len);
    rv = ctx->funcs->C_Verify(ctx->session,
                               (CK_BYTE_PTR)data, (CK_ULONG)data_len,
                               (CK_BYTE_PTR)sig, (CK_ULONG)sig_len);
    if (rv != CKR_OK) {
        DBG_ERR("C_Verify failed: CKR=0x%lx (%s)\n",
                (unsigned long)rv, ckr_to_string(rv));
        ctx->last_ckr = rv;
        if (rv == CKR_SIGNATURE_INVALID)
            return -EBADMSG;  /* distinct: signature is invalid */
        return -EIO;           /* general PKCS#11 failure */
    }

    DBG("C_Verify OK — signature is VALID\n");
    return 0;
}

/* ======================================================================
 * Public: ele_pkcs11_rsa_free
 * ====================================================================== */

void ele_pkcs11_rsa_free(struct ele_pkcs11_rsa *ctx)
{
    if (!ctx)
        return;

    /* Logout. */
    if (ctx->session_open && ctx->logged_in && ctx->funcs)
        ctx->funcs->C_Logout(ctx->session);

    /* Close session. */
    if (ctx->session_open && ctx->funcs)
        ctx->funcs->C_CloseSession(ctx->session);

    /* Finalize. */
    if (ctx->initialized && ctx->funcs)
        ctx->funcs->C_Finalize(NULL);

    /* Unload module. */
    if (ctx->module)
        dlclose(ctx->module);

    /* Clear and free. */
    memset(ctx, 0, sizeof(*ctx));
    free(ctx);
}

/* ======================================================================
 * Public: ele_pkcs11_rsa_free_buf
 * ====================================================================== */

void ele_pkcs11_rsa_free_buf(void *buf)
{
    free(buf);
}
