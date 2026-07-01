// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 *
 * fce_aes_openssl.c — OpenSSL-based AES software implementation.
 *
 * Implements aes_openssl_operation() using the OpenSSL EVP API for all
 * four modes (ECB, CBC, CTR, GCM) and all three key sizes (128/192/256).
 *
 * Padding:
 *   ECB and CBC use PKCS#7 padding (OpenSSL default).  The encrypt path
 *   produces a ciphertext that is always a multiple of the AES block size
 *   (16 bytes) and at least one block.  The decrypt path strips the padding
 *   automatically, returning the original plaintext.
 *
 * CTR mode uses a 16-byte counter block (IV).  When a 12-byte nonce is
 * provided it is padded to 16 bytes as [nonce || 0x00000001]
 * (NIST SP 800-38A initial counter value = 1).
 */

#include "fce_aes_openssl.h"

#include <openssl/evp.h>

#include <errno.h>
#include <string.h>

/* ======================================================================
 * Cipher selection  (mode + key size → EVP_CIPHER)
 * ====================================================================== */

/**
 * cipher_for_mode — Return the OpenSSL EVP_CIPHER for a given mode + key size.
 *
 * @param[in] mode    AES mode (ECB, CBC, CTR, GCM).
 * @param[in] key_len Key length in bytes (16, 24, or 32).
 *
 * @return A valid EVP_CIPHER pointer, or NULL if the combination is
 *         unsupported.
 */
static const EVP_CIPHER *cipher_for_mode(enum fce_aes_mode mode,
                                         size_t key_len)
{
    switch (mode) {
    case FCE_AES_ECB:
        switch (key_len) {
        case 16: return EVP_aes_128_ecb();
        case 24: return EVP_aes_192_ecb();
        case 32: return EVP_aes_256_ecb();
        }
        break;

    case FCE_AES_CBC:
        switch (key_len) {
        case 16: return EVP_aes_128_cbc();
        case 24: return EVP_aes_192_cbc();
        case 32: return EVP_aes_256_cbc();
        }
        break;

    case FCE_AES_CTR:
        switch (key_len) {
        case 16: return EVP_aes_128_ctr();
        case 24: return EVP_aes_192_ctr();
        case 32: return EVP_aes_256_ctr();
        }
        break;

    case FCE_AES_GCM:
        switch (key_len) {
        case 16: return EVP_aes_128_gcm();
        case 24: return EVP_aes_192_gcm();
        case 32: return EVP_aes_256_gcm();
        }
        break;
    }

    return NULL;
}

/* ======================================================================
 * Public API
 * ====================================================================== */

int aes_openssl_operation(struct aes_params *params)
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher;
    int outlen = 0;
    int tmplen = 0;
    int ret;

    /* ---- Parameter validation ---- */
    if (!params || !params->key || !params->input || !params->output)
        return -EINVAL;

    cipher = cipher_for_mode(params->mode, params->key_len);
    if (!cipher)
        return -EINVAL;

    /* ---- CTR: build 16-byte counter block ----
     *
     * The PRIME firmware expects a full 16-byte counter block for
     * CTR mode.  OpenSSL's AES-CTR also expects a 16-byte IV.
     *
     * When the caller provides a 16-byte IV we use it directly as
     * the initial counter block.  When a 12-byte nonce is provided we
     * pad it with [0x00000001] per NIST SP 800-38A.
     */
    uint8_t ctr_iv[16];
    const uint8_t *iv = params->iv;

    if (params->mode == FCE_AES_CTR) {
        if (!iv || params->iv_len < 12)
            return -EINVAL;

        if (params->iv_len >= 16) {
            /* Full 16-byte counter block — use as-is. */
            memcpy(ctr_iv, iv, 16);
        } else {
            /* 12-byte nonce — pad with initial counter = 1. */
            memcpy(ctr_iv, iv, 12);
            ctr_iv[12] = 0x00;
            ctr_iv[13] = 0x00;
            ctr_iv[14] = 0x00;
            ctr_iv[15] = 0x01;
        }
        iv = ctr_iv;
    }

    /* ---- Create context ---- */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -ENOMEM;

    /* ---- Initialise encrypt or decrypt ---- */
    if (params->dir == FCE_AES_ENCRYPT)
        ret = EVP_EncryptInit_ex(ctx, cipher, NULL, params->key, iv);
    else
        ret = EVP_DecryptInit_ex(ctx, cipher, NULL, params->key, iv);

    if (ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -EIO;
    }

    /* ---- ECB and CBC: PKCS#7 padding is enabled by default.
     *
     * OpenSSL enables PKCS#7 padding by default, which matches our
     * PRIME backend's software padding.  The encrypt path pads the
     * plaintext to a multiple of 16 bytes; the decrypt path strips
     * the padding automatically.
     */

    /* ---- GCM: process AAD and (for decrypt) set expected tag ---- */
    if (params->mode == FCE_AES_GCM) {
        if (params->aad && params->aad_len > 0) {
            if (params->dir == FCE_AES_ENCRYPT)
                EVP_EncryptUpdate(ctx, NULL, &outlen,
                                  params->aad, (int)params->aad_len);
            else
                EVP_DecryptUpdate(ctx, NULL, &outlen,
                                  params->aad, (int)params->aad_len);
        }

        if (params->dir == FCE_AES_DECRYPT &&
            params->tag && params->tag_len > 0) {
            if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                     (int)params->tag_len,
                                     (void *)params->tag)) {
                EVP_CIPHER_CTX_free(ctx);
                return -EIO;
            }
        }
    }

    /* ---- Encrypt / decrypt the data ---- */
    outlen = 0;
    if (params->dir == FCE_AES_ENCRYPT) {
        if (!EVP_EncryptUpdate(ctx, params->output, &outlen,
                               params->input, (int)params->input_len)) {
            EVP_CIPHER_CTX_free(ctx);
            return -EIO;
        }
    } else {
        if (!EVP_DecryptUpdate(ctx, params->output, &outlen,
                               params->input, (int)params->input_len)) {
            EVP_CIPHER_CTX_free(ctx);
            return -EIO;
        }
    }

    /* ---- Finalise ----
     *
     * With padding disabled (ECB/CBC) any remaining partial block
     * will cause EVP_*Final_ex to fail.  For CTR/GCM there is no
     * padding so tmplen will normally be zero after Update consumed
     * everything.
     */
    tmplen = 0;
    if (params->dir == FCE_AES_ENCRYPT) {
        if (!EVP_EncryptFinal_ex(ctx, params->output + outlen, &tmplen)) {
            EVP_CIPHER_CTX_free(ctx);
            return -EIO;
        }
    } else {
        if (!EVP_DecryptFinal_ex(ctx, params->output + outlen, &tmplen)) {
            EVP_CIPHER_CTX_free(ctx);
            /* For GCM this means authentication failed (tag mismatch). */
            return (params->mode == FCE_AES_GCM) ? -EBADMSG : -EIO;
        }
    }

    /* ---- GCM encrypt: retrieve authentication tag ---- */
    if (params->mode == FCE_AES_GCM &&
        params->dir == FCE_AES_ENCRYPT &&
        params->tag && params->tag_len > 0) {
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                                 (int)params->tag_len,
                                 params->tag)) {
            EVP_CIPHER_CTX_free(ctx);
            return -EIO;
        }
    }

    EVP_CIPHER_CTX_free(ctx);

    /* Report the actual number of bytes written to the output buffer.
     * For ECB/CBC this includes the PKCS#7 padding (encrypt) or
     * excludes it (decrypt).  For CTR/GCM it equals input_len. */
    params->output_used = (size_t)(outlen + tmplen);
    return 0;
}
