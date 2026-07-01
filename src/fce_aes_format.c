// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 *
 * fce_aes_format.c — File format layer implementation.
 *
 * Implements the on-disk layout [IV][ciphertext][GCM-tag] that couples
 * the encrypt output format with the decrypt input parser.
 *
 * The layout is mode-dependent:
 *   ECB:  [ciphertext]
 *   CBC:  [16-byte IV][ciphertext]
 *   CTR:  [16-byte IV][ciphertext]
 *   GCM:  [12-byte IV][ciphertext][16-byte tag]
 */

#include "fce_aes_format.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ======================================================================
 * IV / tag size helpers
 * ====================================================================== */

size_t format_get_iv_length(enum fce_aes_mode mode)
{
    switch (mode) {
    case FCE_AES_CBC:
    case FCE_AES_CTR: return 16;
    case FCE_AES_GCM: return 12;
    default:          return 0;
    }
}

size_t format_get_tag_length(enum fce_aes_mode mode)
{
    return (mode == FCE_AES_GCM) ? FCE_AES_GCM_TAG_SIZE : 0;
}

/* ======================================================================
 * IV generation  (/dev/urandom)
 * ====================================================================== */

int format_generate_iv(enum fce_aes_mode mode,
                       uint8_t **iv, size_t *iv_len)
{
    FILE *urandom;
    size_t gen_len;
    size_t nread;

    if (!iv || !iv_len)
        return -EINVAL;

    *iv     = NULL;
    *iv_len = 0;

    gen_len = format_get_iv_length(mode);
    if (gen_len == 0)
        return -EINVAL;  /* ECB does not use an IV */

    *iv = (uint8_t *)malloc(gen_len);
    if (!*iv)
        return -ENOMEM;

    urandom = fopen("/dev/urandom", "rb");
    if (!urandom) {
        free(*iv);
        *iv = NULL;
        return -errno;
    }

    nread = fread(*iv, 1, gen_len, urandom);
    fclose(urandom);

    if (nread != gen_len) {
        free(*iv);
        *iv = NULL;
        return -EIO;
    }

    *iv_len = gen_len;
    return 0;
}

/* ======================================================================
 * Decrypt-path parsing
 * ====================================================================== */

int format_parse_decrypt_input(enum fce_aes_mode mode,
                               const uint8_t *input, size_t input_len,
                               const uint8_t **iv, size_t *iv_len,
                               const uint8_t **tag,
                               const uint8_t **ciphertext,
                               size_t *ciphertext_len)
{
    size_t iv_file_len;
    size_t tag_file_len;

    if (!input || !iv || !iv_len || !ciphertext || !ciphertext_len)
        return -EINVAL;

    *iv           = NULL;
    *iv_len       = 0;
    *tag          = NULL;
    *ciphertext   = NULL;
    *ciphertext_len = 0;

    iv_file_len  = format_get_iv_length(mode);
    tag_file_len = format_get_tag_length(mode);

    /* The file must contain at least the IV + tag overhead. */
    if (input_len <= iv_file_len + tag_file_len)
        return -EINVAL;

    *iv           = input;
    *iv_len       = iv_file_len;
    *ciphertext   = input + iv_file_len;
    *ciphertext_len = input_len - iv_file_len - tag_file_len;

    if (tag_file_len > 0)
        *tag = input + input_len - tag_file_len;

    return 0;
}

/* ======================================================================
 * Encrypt-path assembly
 * ====================================================================== */

int format_build_encrypt_output(enum fce_aes_mode mode,
                                const uint8_t *iv, size_t iv_len,
                                const uint8_t *ciphertext,
                                size_t ciphertext_len,
                                const uint8_t *tag,
                                uint8_t **out, size_t *out_len)
{
    size_t iv_out_len;
    size_t tag_out_len;
    size_t total_len;
    uint8_t *buf;

    if (!ciphertext || !out || !out_len)
        return -EINVAL;

    *out     = NULL;
    *out_len = 0;

    iv_out_len  = format_get_iv_length(mode);
    tag_out_len = format_get_tag_length(mode);

    /* For GCM we require a tag buffer. */
    if (tag_out_len > 0 && !tag)
        return -EINVAL;

    /* For non-ECB modes we require an IV (and its length must match). */
    if (iv_out_len > 0 && (!iv || iv_len < iv_out_len))
        return -EINVAL;

    total_len = iv_out_len + ciphertext_len + tag_out_len;

    buf = (uint8_t *)malloc(total_len);
    if (!buf)
        return -ENOMEM;

    if (iv_out_len > 0)
        memcpy(buf, iv, iv_out_len);
    memcpy(buf + iv_out_len, ciphertext, ciphertext_len);
    if (tag_out_len > 0)
        memcpy(buf + iv_out_len + ciphertext_len, tag, tag_out_len);

    *out     = buf;
    *out_len = total_len;
    return 0;
}

/* ======================================================================
 * Display helpers
 * ====================================================================== */

void format_print_iv(const uint8_t *iv, size_t iv_len)
{
    printf("Generated random %zu-byte IV: ", iv_len);
    for (size_t i = 0; i < iv_len; i++)
        printf("%02x", iv[i]);
    printf("\n");
}

void format_print_tag(const uint8_t *tag, size_t tag_len, int is_encrypt)
{
    printf("GCM authentication tag: ");
    for (size_t i = 0; i < tag_len; i++)
        printf("%02x", tag[i]);
    if (is_encrypt)
        printf(" (embedded in output file)\n");
    else
        printf(" (extracted from input file)\n");
}
