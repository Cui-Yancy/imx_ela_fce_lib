// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 *
 * fce_aes.c — Unified FCE AES API implementation.
 *
 * Provides the fce_aes_* unified API that wraps the low-level PRIME
 * session API (aes_session_*) and the OpenSSL software backend
 * (aes_openssl_operation) under a single init/encrypt-decrypt/free
 * lifecycle.
 *
 * Backend selection (in fce_aes_init / fce_aes_init_ex):
 *   1. If FCE_AES_FLAG_FORCE_OPENSSL is set, skip PRIME entirely.
 *   2. Try PRIME: aes_session_open() + aes_session_load_key().
 *   3. If PRIME returns -ENODEV, fall back to OpenSSL.
 *   4. Any other PRIME error causes init to fail.
 */

#include "imx_aes.h"
#include "internal/aes_openssl.h"
#include "internal/fce_aes_format.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* ======================================================================
 * Internal context
 * ====================================================================== */

/** Maximum AAD size we can store in the context (enough for any sane AAD). */
#define FCE_AES_MAX_AAD_SIZE  64U

struct fce_aes {
    enum fce_aes_mode  mode;         /**< AES mode (ECB, CBC, CTR, GCM). */
    uint8_t            key[32];      /**< Key storage (up to AES-256). */
    size_t             key_len;      /**< Actual key length in bytes. */
    uint8_t            aad[FCE_AES_MAX_AAD_SIZE]; /**< GCM AAD storage. */
    size_t             aad_len;      /**< GCM AAD length (0 for non-GCM). */
    int                use_prime;    /**< Non-zero if PRIME session active. */
    struct aes_session sess;         /**< PRIME session (valid if use_prime). */
};

/* ======================================================================
 * Lifecycle
 * ====================================================================== */

struct fce_aes *fce_aes_init(enum fce_aes_mode mode,
                              const uint8_t *key, size_t key_len,
                              const uint8_t *aad, size_t aad_len)
{
    return fce_aes_init_ex(mode, key, key_len, aad, aad_len, 0);
}

struct fce_aes *fce_aes_init_ex(enum fce_aes_mode mode,
                                 const uint8_t *key, size_t key_len,
                                 const uint8_t *aad, size_t aad_len,
                                 unsigned int flags)
{
    struct fce_aes *ctx;
    int ret;

    /* ---- Parameter validation ---- */
    if (!key)
        return NULL;
    if (key_len != 16 && key_len != 24 && key_len != 32)
        return NULL;
    if (mode < FCE_AES_ECB || mode > FCE_AES_GCM)
        return NULL;
    if ((aad && aad_len == 0) || (!aad && aad_len > 0))
        return NULL;
    if (aad_len > FCE_AES_MAX_AAD_SIZE)
        return NULL;
    /* GCM requires non-zero AAD for the PRIME firmware. */
    if (mode == FCE_AES_GCM && aad_len == 0)
        return NULL;

    /* ---- Allocate context ---- */
    ctx = (struct fce_aes *)calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    ctx->mode    = mode;
    ctx->key_len = key_len;
    memcpy(ctx->key, key, key_len);

    if (aad && aad_len > 0) {
        memcpy(ctx->aad, aad, aad_len);
        ctx->aad_len = aad_len;
    }

    /* ---- Backend selection ---- */

    /* If FORCE_OPENSSL is set, skip PRIME entirely. */
    if (flags & FCE_AES_FLAG_FORCE_OPENSSL) {
        ctx->use_prime = 0;
        return ctx;
    }

    /* Try PRIME hardware backend. */
    ret = aes_session_open(&ctx->sess);
    if (ret == 0) {
        ret = aes_session_load_key(&ctx->sess, key, key_len);
        if (ret == 0) {
            ctx->use_prime = 1;
            return ctx;
        }
        /* Load-key failed; close the session and fall through. */
        aes_session_close(&ctx->sess);
    }

    /* If PRIME returned "service not available", fall back to OpenSSL. */
    if (ret == -ENODEV) {
        ctx->use_prime = 0;
        return ctx;
    }

    /* Any other error: fail. */
    free(ctx);
    return NULL;
}

void fce_aes_free(struct fce_aes *ctx)
{
    if (!ctx)
        return;

    if (ctx->use_prime)
        aes_session_close(&ctx->sess);

    memset(ctx, 0, sizeof(*ctx));
    free(ctx);
}

void fce_aes_free_buf(void *buf)
{
    free(buf);
}

/* ======================================================================
 * Encryption
 * ====================================================================== */

int fce_aes_encrypt(struct fce_aes *ctx,
                    const uint8_t *iv, size_t iv_len,
                    const uint8_t *input, size_t input_len,
                    uint8_t **output, size_t *output_len)
{
    struct aes_params params;
    size_t tag_len;
    size_t padded_len;
    uint8_t *buf;
    int ret;

    if (!ctx || !input || !output || !output_len)
        return -EINVAL;
    if (input_len == 0)
        return -EINVAL;

    /* ECB has no IV; all other modes require one. */
    if (ctx->mode != FCE_AES_ECB && (!iv || iv_len == 0))
        return -EINVAL;
    if (ctx->mode == FCE_AES_ECB && iv)
        return -EINVAL;

    if (ctx->mode == FCE_AES_GCM && ctx->aad_len == 0)
        return -EINVAL;

    *output     = NULL;
    *output_len = 0;

    tag_len = format_get_tag_length(ctx->mode);

    /*
     * Calculate the maximum ciphertext size.
     *
     * ECB / CBC (encrypt): PKCS#7 padding rounds up to the next 16-byte
     *   boundary, always adding at least 1 byte.
     * CTR / GCM:           ciphertext size equals plaintext size.
     */
    if ((ctx->mode == FCE_AES_ECB || ctx->mode == FCE_AES_CBC))
        padded_len = (input_len + 16) & ~(size_t)15;
    else
        padded_len = input_len;

    /* Allocate output: ciphertext (padded) + GCM tag (if any). */
    buf = (uint8_t *)malloc(padded_len + tag_len);
    if (!buf)
        return -ENOMEM;

    /* Set up AES parameters. */
    memset(&params, 0, sizeof(params));
    params.dir       = FCE_AES_ENCRYPT;
    params.mode      = ctx->mode;
    params.key       = ctx->key;
    params.key_len   = ctx->key_len;
    params.iv        = iv;
    params.iv_len    = iv_len;
    params.aad       = ctx->aad_len > 0 ? ctx->aad : NULL;
    params.aad_len   = ctx->aad_len;
    params.input     = input;
    params.input_len = input_len;
    params.output    = buf;
    params.output_len = padded_len;

    /* GCM: tag goes after the ciphertext. */
    if (tag_len > 0) {
        params.tag     = buf + padded_len;
        params.tag_len = tag_len;
    }

    /* Execute the crypto operation. */
    if (ctx->use_prime)
        ret = aes_session_crypto(&ctx->sess, &params);
    else
        ret = aes_openssl_operation(&params);

    if (ret) {
        free(buf);
        return ret;
    }

    /*
     * Total output length: actual ciphertext (with padding) + GCM tag.
     * For non-GCM modes tag_len is 0, so this reduces to output_used.
     */
    *output_len = params.output_used + tag_len;
    *output     = buf;

    return 0;
}

/* ======================================================================
 * Decryption
 * ====================================================================== */

int fce_aes_decrypt(struct fce_aes *ctx,
                    const uint8_t *iv, size_t iv_len,
                    const uint8_t *input, size_t input_len,
                    uint8_t **output, size_t *output_len)
{
    struct aes_params params;
    size_t tag_len;
    uint8_t *buf;
    const uint8_t *tag_ptr;
    int ret;

    if (!ctx || !input || !output || !output_len)
        return -EINVAL;
    if (input_len == 0)
        return -EINVAL;

    /* ECB has no IV; all other modes require one. */
    if (ctx->mode != FCE_AES_ECB && (!iv || iv_len == 0))
        return -EINVAL;
    if (ctx->mode == FCE_AES_ECB && iv)
        return -EINVAL;

    if (ctx->mode == FCE_AES_GCM && ctx->aad_len == 0)
        return -EINVAL;

    *output     = NULL;
    *output_len = 0;

    tag_len = format_get_tag_length(ctx->mode);

    /*
     * GCM: the authentication tag is appended to the ciphertext in the
     * input buffer.  Separate it out for the backend.
     */
    if (tag_len > 0) {
        if (input_len < tag_len)
            return -EINVAL;
        tag_ptr = input + input_len - tag_len;
    } else {
        tag_ptr = NULL;
    }

    /* Allocate output buffer for plaintext.  Max size = input_len. */
    buf = (uint8_t *)malloc(input_len);
    if (!buf)
        return -ENOMEM;

    /* Set up AES parameters. */
    memset(&params, 0, sizeof(params));
    params.dir       = FCE_AES_DECRYPT;
    params.mode      = ctx->mode;
    params.key       = ctx->key;
    params.key_len   = ctx->key_len;
    params.iv        = iv;
    params.iv_len    = iv_len;
    params.aad       = ctx->aad_len > 0 ? ctx->aad : NULL;
    params.aad_len   = ctx->aad_len;
    params.input     = input;
    params.input_len = tag_len > 0 ? input_len - tag_len : input_len;
    params.output    = buf;
    params.output_len = input_len;

    if (tag_len > 0 && tag_ptr) {
        params.tag     = (uint8_t *)tag_ptr;
        params.tag_len = tag_len;
    }

    /* Execute the crypto operation. */
    if (ctx->use_prime)
        ret = aes_session_crypto(&ctx->sess, &params);
    else
        ret = aes_openssl_operation(&params);

    if (ret) {
        free(buf);
        return ret;
    }

    *output_len = params.output_used;
    *output     = buf;

    return 0;
}

/* ======================================================================
 * IV generation
 * ====================================================================== */

int fce_aes_generate_iv(enum fce_aes_mode mode,
                         uint8_t **iv, size_t *iv_len)
{
    /* Forward to the existing format-layer IV generator. */
    return format_generate_iv(mode, iv, iv_len);
}

/* ======================================================================
 * Query helpers
 * ====================================================================== */

size_t fce_aes_iv_length(struct fce_aes *ctx)
{
    if (!ctx)
        return 0;
    return format_get_iv_length(ctx->mode);
}

size_t fce_aes_tag_length(struct fce_aes *ctx)
{
    if (!ctx)
        return 0;
    return format_get_tag_length(ctx->mode);
}

const char *fce_aes_strerror(int err)
{
    return aes_strerror(err);
}
