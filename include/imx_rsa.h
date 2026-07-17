// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 *
 * imx_rsa.h — ELE PKCS#11 RSA Sign and Verify API.
 *
 * Provides RSA signing and signature verification using the PKCS#11
 * interface (Cryptoki) backed by the NXP i.MX ELE cryptographic hardware.
 * The PKCS#11 module is loaded dynamically at runtime via dlopen/dlsym —
 * no compile-time dependency on a specific PKCS#11 library is required.
 *
 * Only the SHA256-RSA-PKCS-PSS mechanism (CKM_SHA256_RSA_PKCS_PSS) is
 * supported — the token performs SHA-256 hashing internally.  No
 * software hashing is done by this API.
 *
 * Calling convention (three-stage lifecycle):
 *
 *   Sign:
 *     1. ele_pkcs11_rsa_sign_init()  — load module, init Cryptoki, open
 *                                       session, login, find private key
 *                                       by CKA_ID
 *     2. ele_pkcs11_rsa_sign()       — sign data (call any number of times)
 *     3. ele_pkcs11_rsa_free()       — logout, close, finalize, unload
 *
 *   Verify:
 *     1. ele_pkcs11_rsa_verify_init() — load module, init Cryptoki, open
 *                                       session, login, find public key
 *                                       by CKA_ID
 *     2. ele_pkcs11_rsa_verify()      — verify signature (call any number
 *                                       of times)
 *     3. ele_pkcs11_rsa_free()        — logout, close, finalize, unload
 *
 * All functions return 0 on success or a negative errno value on failure.
 * Use ele_pkcs11_rsa_strerror() for a human-readable description.
 *
 * Usage example (sign):
 *
 *   #include "imx_rsa.h"
 *
 *   uint8_t key_id[] = { 0x02 };
 *   struct ele_pkcs11_rsa *ctx =
 *       ele_pkcs11_rsa_sign_init(NULL, key_id, sizeof(key_id), NULL,
 *                                ELE_PKCS11_RSA_PKCS_PSS);
 *   if (!ctx) { ... error ... }
 *
 *   uint8_t *sig;
 *   size_t   sig_len;
 *   ele_pkcs11_rsa_sign(ctx, data, data_len, &sig, &sig_len);
 *
 *   ele_pkcs11_rsa_free_buf(sig);
 *   ele_pkcs11_rsa_free(ctx);
 *
 * Usage example (verify):
 *
 *   struct ele_pkcs11_rsa *ctx =
 *       ele_pkcs11_rsa_verify_init(NULL, key_id, sizeof(key_id), NULL,
 *                                  ELE_PKCS11_RSA_PKCS_PSS);
 *   if (!ctx) { ... error ... }
 *
 *   int ret = ele_pkcs11_rsa_verify(ctx, data, data_len, sig, sig_len);
 *   if (ret == 0)
 *       printf("Signature is VALID\n");
 *   else if (ret == -EBADMSG)
 *       printf("Signature is INVALID\n");
 *
 *   ele_pkcs11_rsa_free(ctx);
 */

#ifndef IMX_RSA_H
#define IMX_RSA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------
 * Signature mechanisms
 * --------------------------------------------------------------------------- */

/** Supported RSA signature mechanisms. */
enum ele_pkcs11_rsa_mechanism {
    ELE_PKCS11_RSA_PKCS_PSS = 0,  /**< SHA256-RSA-PKCS-PSS (default) */
};

/* ---------------------------------------------------------------------------
 * Opaque context
 * --------------------------------------------------------------------------- */

struct ele_pkcs11_rsa;

/* ---------------------------------------------------------------------------
 * Sign API — Lifecycle
 * --------------------------------------------------------------------------- */

/**
 * ele_pkcs11_rsa_sign_init — Initialize a PKCS#11 signing session.
 *
 * Opens the PKCS#11 module at @p module_path, initialises the Cryptoki
 * interface, opens a session, logs in, and locates the **private** key
 * identified by @p key_id.
 *
 * If @p module_path is NULL, the default path
 * ELE_PKCS11_RSA_DEFAULT_MODULE ("/usr/lib/libsmw_pkcs11.so.5") is used.
 *
 * If @p pin is NULL, an empty (zero-length) PIN is used.  This matches
 * the behaviour of pkcs11-tool --login without --pin, which is the
 * common case for NXP SMW tokens.
 *
 * @param[in] module_path  Path to the PKCS#11 shared library (NULL for
 *                          default).
 * @param[in] key_id       Key identifier bytes (e.g. {0x02} for key "02").
 * @param[in] key_id_len   Length of @p key_id in bytes.
 * @param[in] pin          User PIN string, or NULL to skip login.
 * @param[in] mechanism    Signature mechanism.  Pass 0 for
 *                          SHA256-RSA-PKCS-PSS (the only currently
 *                          supported mechanism).
 *
 * @return A new ele_pkcs11_rsa context on success, or NULL on failure.
 */
struct ele_pkcs11_rsa *ele_pkcs11_rsa_sign_init(
    const char *module_path,
    const uint8_t *key_id, size_t key_id_len,
    const char *pin,
    enum ele_pkcs11_rsa_mechanism mechanism);

/**
 * ele_pkcs11_rsa_sign — Sign data using the ELE PKCS#11 token.
 *
 * Signs @p data with the private key and mechanism configured in
 * ele_pkcs11_rsa_sign_init().  The data is the raw message (not pre-hashed);
 * the token performs SHA-256 hashing internally as part of the
 * CKM_SHA256_RSA_PKCS_PSS mechanism.
 *
 * The signature buffer is heap-allocated.  The caller must free it
 * with ele_pkcs11_rsa_free_buf().
 *
 * @param[in,out] ctx      Signing context (from ele_pkcs11_rsa_sign_init).
 * @param[in]     data     Message to sign (raw bytes).
 * @param[in]     data_len Length of @p data in bytes.
 * @param[out]    sig      On success, heap-allocated signature bytes.
 * @param[out]    sig_len  Length of the signature in bytes.
 *
 * @return 0 on success, or a negative errno value on failure.
 */
int ele_pkcs11_rsa_sign(struct ele_pkcs11_rsa *ctx,
                         const uint8_t *data, size_t data_len,
                         uint8_t **sig, size_t *sig_len);

/* ---------------------------------------------------------------------------
 * Verify API — Lifecycle
 * --------------------------------------------------------------------------- */

/**
 * ele_pkcs11_rsa_verify_init — Initialize a PKCS#11 verification session.
 *
 * Opens the PKCS#11 module at @p module_path, initialises the Cryptoki
 * interface, opens a session, logs in, and locates the **public** key
 * identified by @p key_id.
 *
 * Parameter semantics are identical to ele_pkcs11_rsa_sign_init(), except
 * that the key located is CKO_PUBLIC_KEY (not CKO_PRIVATE_KEY).
 *
 * @param[in] module_path  Path to the PKCS#11 shared library (NULL for
 *                          default).
 * @param[in] key_id       Key identifier bytes (e.g. {0x02} for key "02").
 * @param[in] key_id_len   Length of @p key_id in bytes.
 * @param[in] pin          User PIN string, or NULL to skip login.
 * @param[in] mechanism    Signature mechanism.  Pass 0 for
 *                          SHA256-RSA-PKCS-PSS (the only currently
 *                          supported mechanism).
 *
 * @return A new ele_pkcs11_rsa context on success, or NULL on failure.
 */
struct ele_pkcs11_rsa *ele_pkcs11_rsa_verify_init(
    const char *module_path,
    const uint8_t *key_id, size_t key_id_len,
    const char *pin,
    enum ele_pkcs11_rsa_mechanism mechanism);

/**
 * ele_pkcs11_rsa_verify — Verify an RSA signature using the ELE PKCS#11
 *                          token.
 *
 * Verifies that @p sig is a valid RSA-PSS signature over the raw message
 * @p data, using the public key and mechanism configured in
 * ele_pkcs11_rsa_verify_init().  The token performs SHA-256 hashing
 * internally.
 *
 * Unlike ele_pkcs11_rsa_sign(), the signature buffer is owned by the
 * caller — no heap allocation is performed.
 *
 * @param[in,out] ctx      Verification context (from
 *                          ele_pkcs11_rsa_verify_init).
 * @param[in]     data     Raw message that was signed.
 * @param[in]     data_len Length of @p data in bytes.
 * @param[in]     sig      Signature bytes to verify.
 * @param[in]     sig_len  Length of @p sig in bytes.
 *
 * @return 0 on success (signature is valid), -EBADMSG if the signature is
 *         invalid (does not match data/key), or another negative errno
 *         value on other failures.
 */
int ele_pkcs11_rsa_verify(struct ele_pkcs11_rsa *ctx,
                           const uint8_t *data, size_t data_len,
                           const uint8_t *sig, size_t sig_len);

/* ---------------------------------------------------------------------------
 * Shared lifecycle functions (sign and verify)
 * --------------------------------------------------------------------------- */

/**
 * ele_pkcs11_rsa_free — Destroy a PKCS#11 RSA context.
 *
 * Logs out, closes the session, finalises the Cryptoki interface,
 * unloads the PKCS#11 module, and frees all associated memory.
 * Safe to call with a NULL pointer (no-op).
 *
 * @param[in,out] ctx  Context to destroy, or NULL.
 */
void ele_pkcs11_rsa_free(struct ele_pkcs11_rsa *ctx);

/**
 * ele_pkcs11_rsa_free_buf — Free a buffer allocated by this API.
 *
 * @param[in] buf  Buffer to free, or NULL (no-op).
 */
void ele_pkcs11_rsa_free_buf(void *buf);

/* ---------------------------------------------------------------------------
 * Error reporting
 * --------------------------------------------------------------------------- */

/**
 * ele_pkcs11_rsa_strerror — Return a human-readable error string.
 *
 * Handles both negative errno-style codes and PKCS#11 CKR_* return
 * values.  The error context is obtained from the last failed PKCS#11
 * operation (if applicable).
 *
 * @param[in] err  Negative errno value or internal PKCS#11 error code.
 *
 * @return Pointer to a statically allocated string (never NULL).
 */
const char *ele_pkcs11_rsa_strerror(int err);

/* ---------------------------------------------------------------------------
 * Constants
 * --------------------------------------------------------------------------- */

/** Default PKCS#11 module path (when NULL is passed to init). */
#define ELE_PKCS11_RSA_DEFAULT_MODULE  "/usr/lib/libsmw_pkcs11.so.5"

/** Maximum supported signature length (RSA 4096 = 512 bytes). */
#define ELE_PKCS11_RSA_MAX_SIGNATURE_SIZE  512

/** Maximum supported key ID length. */
#define ELE_PKCS11_RSA_MAX_KEY_ID_LEN  64

#ifdef __cplusplus
}
#endif

#endif /* IMX_RSA_H */
