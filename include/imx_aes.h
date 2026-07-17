// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 *
 * imx_aes.h — Unified FCE AES API.
 *
 * This is the single public API for AES encryption/decryption using the
 * i.MX943 PRIME FCE hardware (with automatic fallback to OpenSSL software
 * when the hardware is not available).
 *
 * Calling convention (three-stage lifecycle):
 *
 *   1. fce_aes_init()     — create context, open PRIME session, load key
 *   2. fce_aes_encrypt()  — encrypt data (call any number of times)
 *      fce_aes_decrypt()  — decrypt data (call any number of times)
 *   3. fce_aes_free()     — close session, free context
 *
 * The IV is an explicit parameter for encrypt/decrypt.  Callers can obtain
 * a cryptographically random IV via fce_aes_generate_iv().
 *
 * Usage example:
 *
 *   struct fce_aes *ctx = fce_aes_init(FCE_AES_CBC, key, 16, NULL, 0);
 *   if (!ctx) { ... error ... }
 *
 *   uint8_t *iv;
 *   size_t   iv_len;
 *   fce_aes_generate_iv(FCE_AES_CBC, &iv, &iv_len);
 *
 *   uint8_t *ct;
 *   size_t   ct_len;
 *   fce_aes_encrypt(ctx, iv, iv_len, plain, plain_len, &ct, &ct_len);
 *
 *   fce_aes_free_buf(iv);
 *   fce_aes_free_buf(ct);
 *   fce_aes_free(ctx);
 *
 * Supported modes: ECB, CBC, CTR, GCM
 * Key sizes:       16 (AES-128), 24 (AES-192), 32 (AES-256)
 *
 * Output format for fce_aes_encrypt / fce_aes_decrypt:
 *   ECB:          [ciphertext]                   (no IV, no tag)
 *   CBC / CTR:    [ciphertext]                   (IV managed by caller)
 *   GCM:          [ciphertext][16-byte tag]      (tag appended)
 *
 * All functions return 0 on success or a negative errno-style value on
 * failure.  Use fce_aes_strerror() for a human-readable description.
 */

#ifndef IMX_AES_H
#define IMX_AES_H

#include "internal/fce_aes_session.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------
 * Opaque context
 * --------------------------------------------------------------------------- */

struct fce_aes;

/* ---------------------------------------------------------------------------
 * Flags for fce_aes_init_ex
 * --------------------------------------------------------------------------- */

/** Skip PRIME hardware and use OpenSSL software backend. */
#define FCE_AES_FLAG_FORCE_OPENSSL  (1u << 0)

/* ---------------------------------------------------------------------------
 * Lifecycle
 * --------------------------------------------------------------------------- */

/**
 * fce_aes_init — Create an AES encryption context.
 *
 * Opens a PRIME service session and loads the AES key into hardware.  If
 * the PRIME hardware is not available (e.g. no i.MX hardware or USE_PRIME=0
 * build), falls back to the OpenSSL software backend transparently.
 *
 * GCM callers must provide non-zero AAD.  For non-GCM modes pass NULL/0.
 *
 * @param[in] mode    AES cipher mode (ECB, CBC, CTR, GCM).
 * @param[in] key     Key bytes (16, 24, or 32 bytes).
 * @param[in] key_len Number of key bytes.
 * @param[in] aad     GCM additional authenticated data (may be NULL).
 * @param[in] aad_len AAD length in bytes (0 if @p aad is NULL).
 *
 * @return A new fce_aes context on success, or NULL on failure.
 */
struct fce_aes *fce_aes_init(enum fce_aes_mode mode,
                              const uint8_t *key, size_t key_len,
                              const uint8_t *aad, size_t aad_len);

/**
 * fce_aes_init_ex — Create an AES context with extended flags.
 *
 * Like fce_aes_init() but accepts a @p flags bitmask.
 * Pass FCE_AES_FLAG_FORCE_OPENSSL to skip the PRIME hardware and always
 * use the OpenSSL software backend.
 *
 * @param[in] mode    AES cipher mode.
 * @param[in] key     Key bytes.
 * @param[in] key_len Key length.
 * @param[in] aad     GCM AAD (may be NULL).
 * @param[in] aad_len AAD length.
 * @param[in] flags   Bitmask of FCE_AES_FLAG_* values (0 for default).
 *
 * @return A new fce_aes context on success, or NULL on failure.
 */
struct fce_aes *fce_aes_init_ex(enum fce_aes_mode mode,
                                 const uint8_t *key, size_t key_len,
                                 const uint8_t *aad, size_t aad_len,
                                 unsigned int flags);

/**
 * fce_aes_free — Destroy an AES context and release all resources.
 *
 * Closes the PRIME service session (if one was opened) and frees memory.
 * Safe to call with a NULL pointer (no-op).
 *
 * @param[in,out] ctx  Context to destroy, or NULL.
 */
void fce_aes_free(struct fce_aes *ctx);

/**
 * fce_aes_free_buf — Free a buffer returned by fce_aes_encrypt() or
 *                    fce_aes_decrypt().
 *
 * @param[in] buf  Buffer to free, or NULL (no-op).
 */
void fce_aes_free_buf(void *buf);

/* ---------------------------------------------------------------------------
 * Crypto operations
 * --------------------------------------------------------------------------- */

/**
 * fce_aes_encrypt — Encrypt data.
 *
 * Encrypts @p input with the given IV.  The output buffer is heap-allocated
 * and contains:
 *   ECB:          [ciphertext]
 *   CBC / CTR:    [ciphertext]
 *   GCM:          [ciphertext][16-byte tag]
 *
 * The caller must free @p *output with fce_aes_free_buf().
 *
 * @param[in,out] ctx       AES context (from fce_aes_init).
 * @param[in]     iv        IV / nonce (NULL for ECB).
 * @param[in]     iv_len    IV length (0 for ECB).
 * @param[in]     input     Plaintext.
 * @param[in]     input_len Plaintext length.
 * @param[out]    output    On success, heap-allocated ciphertext buffer.
 * @param[out]    output_len Number of bytes in @p *output.
 *
 * @return 0 on success, or a negative errno value on failure.
 */
int fce_aes_encrypt(struct fce_aes *ctx,
                    const uint8_t *iv, size_t iv_len,
                    const uint8_t *input, size_t input_len,
                    uint8_t **output, size_t *output_len);

/**
 * fce_aes_decrypt — Decrypt data.
 *
 * Decrypts @p input using the given IV.  For GCM mode the last 16 bytes
 * of @p input must be the authentication tag.
 *
 * The output plaintext buffer is heap-allocated.  The caller must free it
 * with fce_aes_free_buf().
 *
 * @param[in,out] ctx       AES context (from fce_aes_init).
 * @param[in]     iv        IV / nonce (NULL for ECB).
 * @param[in]     iv_len    IV length (0 for ECB).
 * @param[in]     input     Ciphertext (for GCM: [ciphertext][16-byte tag]).
 * @param[in]     input_len Input length.
 * @param[out]    output    On success, heap-allocated plaintext buffer.
 * @param[out]    output_len Number of bytes in @p *output.
 *
 * @return 0 on success, or a negative errno value on failure.
 */
int fce_aes_decrypt(struct fce_aes *ctx,
                    const uint8_t *iv, size_t iv_len,
                    const uint8_t *input, size_t input_len,
                    uint8_t **output, size_t *output_len);

/* ---------------------------------------------------------------------------
 * IV generation
 * --------------------------------------------------------------------------- */

/**
 * fce_aes_generate_iv — Generate a cryptographically random IV/nonce.
 *
 * Uses /dev/urandom to produce an IV of the correct length for the given
 * mode (16 bytes for CBC/CTR, 12 bytes for GCM, no-op for ECB).
 *
 * @param[in]  mode    AES cipher mode.
 * @param[out] iv      On success, heap-allocated random IV (caller frees
 *                     with fce_aes_free_buf()).
 * @param[out] iv_len  IV length in bytes (0 for ECB).
 *
 * @return 0 on success, or a negative errno value on failure.
 */
int fce_aes_generate_iv(enum fce_aes_mode mode,
                         uint8_t **iv, size_t *iv_len);

/* ---------------------------------------------------------------------------
 * Query helpers
 * --------------------------------------------------------------------------- */

/**
 * fce_aes_iv_length — Return the IV length for the configured mode.
 *
 * @param[in] ctx  AES context.
 *
 * @return IV length in bytes (0 for ECB).
 */
size_t fce_aes_iv_length(struct fce_aes *ctx);

/**
 * fce_aes_tag_length — Return the GCM authentication tag length.
 *
 * @param[in] ctx  AES context.
 *
 * @return Tag length in bytes (0 for non-GCM modes).
 */
size_t fce_aes_tag_length(struct fce_aes *ctx);

/**
 * fce_aes_strerror — Return a human-readable error string.
 *
 * @param[in] err  Negative errno-style error code.
 *
 * @return Pointer to a statically allocated string (never NULL).
 */
const char *fce_aes_strerror(int err);

#ifdef __cplusplus
}
#endif

#endif /* IMX_AES_H */
