// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 *
 * crypto_stream.c — Streaming AES encryption wrapper implementation.
 *
 * Provides per-frame AES encryption with automatic PRIME/OpenSSL backend
 * selection.  Each frame is encrypted with a fresh random IV, producing:
 *   [IV][ciphertext][+GCM-tag]
 *
 * Backend selection:
 *   - If the PRIME service session opens successfully, the session-based
 *     API (aes_session_*) is used for best performance.
 *   - If PRIME returns -ENODEV (no hardware or USE_PRIME=0 build), falls
 *     back to aes_openssl_operation() per frame.
 *   - Any other PRIME error causes crypto_stream_new() to fail.
 */

#include "crypto_stream.h"
#include "aes_openssl.h"
#include "fce_aes_format.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* ======================================================================
 * Internal context
 * ====================================================================== */

struct crypto_stream {
    enum fce_aes_mode  mode;         /**< AES mode (ECB, CBC, CTR, GCM). */
    uint8_t            key[32];      /**< Key storage (up to AES-256). */
    size_t             key_len;      /**< Actual key length in bytes. */
    int                use_prime;    /**< Non-zero if PRIME session active. */
    struct aes_session sess;         /**< PRIME session (valid if use_prime). */
};

/* ======================================================================
 * Lifecycle
 * ====================================================================== */

struct crypto_stream *crypto_stream_new(enum fce_aes_mode mode,
                                        const uint8_t *key,
                                        size_t key_len)
{
    struct crypto_stream *cs;
    int ret;

    /* Validate parameters. */
    if (!key)
        return NULL;
    if (key_len != 16 && key_len != 24 && key_len != 32)
        return NULL;
    if (mode < FCE_AES_ECB || mode > FCE_AES_GCM)
        return NULL;

    /* Allocate context. */
    cs = (struct crypto_stream *)calloc(1, sizeof(*cs));
    if (!cs)
        return NULL;

    cs->mode    = mode;
    cs->key_len = key_len;
    memcpy(cs->key, key, key_len);

    /* Try PRIME hardware backend. */
    ret = aes_session_open(&cs->sess);
    if (ret == 0) {
        ret = aes_session_load_key(&cs->sess, key, key_len);
        if (ret == 0) {
            cs->use_prime = 1;
            return cs;
        }
        /* Load-key failed; close the session and fall through. */
        aes_session_close(&cs->sess);
    }

    /* If PRIME returned "service not available", fall back to OpenSSL. */
    if (ret == -ENODEV) {
        cs->use_prime = 0;
        return cs;
    }

    /* Any other error: fail. */
    free(cs);
    return NULL;
}

void crypto_stream_free(struct crypto_stream *cs)
{
    if (!cs)
        return;

    if (cs->use_prime)
        aes_session_close(&cs->sess);

    memset(cs, 0, sizeof(*cs));
    free(cs);
}

/* ======================================================================
 * Encryption
 * ====================================================================== */

int crypto_stream_encrypt(struct crypto_stream *cs,
                          const uint8_t *plain, size_t plain_len,
                          uint8_t **out, size_t *out_len)
{
    uint8_t *iv = NULL;
    size_t   iv_len;
    size_t   tag_len;
    size_t   padded_len;
    uint8_t *buf;
    size_t   buf_capacity;
    struct aes_params params;
    int ret;

    if (!cs || !plain || !out || !out_len)
        return -EINVAL;

    *out     = NULL;
    *out_len = 0;

    /* ---- Generate random IV (ECB has no IV). ---- */
    if (cs->mode == FCE_AES_ECB) {
        iv     = NULL;
        iv_len = 0;
    } else {
        ret = format_generate_iv(cs->mode, &iv, &iv_len);
        if (ret)
            return ret;
    }

    tag_len = format_get_tag_length(cs->mode);

    /*
     * Calculate the maximum ciphertext size.
     *
     * ECB / CBC (encrypt): PKCS#7 padding rounds up to the next 16-byte
     *   boundary, always adding at least 1 byte.
     * CTR / GCM:           ciphertext size equals plaintext size.
     */
    if ((cs->mode == FCE_AES_ECB || cs->mode == FCE_AES_CBC))
        padded_len = (plain_len + 16) & ~(size_t)15;
    else
        padded_len = plain_len;

    /* Allocate output: IV + ciphertext (padded) + tag. */
    buf_capacity = iv_len + padded_len + tag_len;
    buf = (uint8_t *)malloc(buf_capacity);
    if (!buf) {
        free(iv);
        return -ENOMEM;
    }

    /* Copy IV to the start of the output buffer. */
    if (iv_len > 0)
        memcpy(buf, iv, iv_len);

    /* Set up AES parameters. */
    memset(&params, 0, sizeof(params));
    params.dir       = FCE_AES_ENCRYPT;
    params.mode      = cs->mode;
    params.key       = cs->key;
    params.key_len   = cs->key_len;
    params.iv        = iv;
    params.iv_len    = iv_len;
    params.input     = plain;
    params.input_len = plain_len;
    params.output    = buf + iv_len;
    params.output_len = buf_capacity - iv_len;   /* >= padded_len + tag_len */

    /* GCM: tag goes after the ciphertext. */
    if (tag_len > 0) {
        params.tag     = buf + iv_len + padded_len;
        params.tag_len = tag_len;
    }

    /* Execute the crypto operation. */
    if (cs->use_prime)
        ret = aes_session_crypto(&cs->sess, &params);
    else
        ret = aes_openssl_operation(&params);

    if (ret) {
        free(buf);
        free(iv);
        return ret;
    }

    /*
     * Total output length: IV + actual ciphertext (with padding) + GCM tag.
     * For non-GCM modes tag_len is 0, so this reduces to iv_len + output_used.
     */
    *out_len = iv_len + params.output_used + tag_len;
    *out     = buf;

    free(iv);
    return 0;
}

/* ======================================================================
 * Wire-format helpers
 * ====================================================================== */

size_t crypto_stream_iv_length(struct crypto_stream *cs)
{
    return cs ? format_get_iv_length(cs->mode) : 0;
}

size_t crypto_stream_tag_length(struct crypto_stream *cs)
{
    return cs ? format_get_tag_length(cs->mode) : 0;
}

size_t crypto_stream_overhead(struct crypto_stream *cs)
{
    if (!cs)
        return 0;
    return format_get_iv_length(cs->mode) + format_get_tag_length(cs->mode);
}

/* ======================================================================
 * Buffer management
 * ====================================================================== */

void crypto_stream_free_buf(void *buf)
{
    free(buf);
}
