// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 *
 * fce_aes_format.h — File format layer for the FCE AES application.
 *
 * Handles the on-disk layout [IV][ciphertext][GCM-tag] that the encrypt
 * path produces and the decrypt path consumes.
 *
 * Each format function works from the AES mode alone — the caller does
 * not need to repeat IV-length or tag-length logic.
 */

#ifndef FCE_AES_FORMAT_H
#define FCE_AES_FORMAT_H

#include "fce_aes_api.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------
 * IV / tag size helpers
 * --------------------------------------------------------------------------- */

/**
 * format_get_iv_length — Return the IV length in bytes for a given mode.
 *
 * @param[in] mode  AES mode.
 *
 * @return IV length: 16 for CBC, 12 for CTR/GCM, 0 for ECB.
 */
size_t format_get_iv_length(enum fce_aes_mode mode);

/**
 * format_get_tag_length — Return the authentication tag length in bytes.
 *
 * @param[in] mode  AES mode.
 *
 * @return FCE_AES_GCM_TAG_SIZE for GCM, 0 for cipher modes.
 */
size_t format_get_tag_length(enum fce_aes_mode mode);

/* ---------------------------------------------------------------------------
 * IV generation
 * --------------------------------------------------------------------------- */

/**
 * format_generate_iv — Generate a cryptographically random IV / nonce.
 *
 * The IV length is chosen automatically from @p mode.  The caller owns
 * the returned buffer and must free() it.
 *
 * @param[in]  mode   AES mode (CBC → 16 bytes, CTR/GCM → 12 bytes).
 * @param[out] iv     On success, a malloc'd buffer with random bytes.
 * @param[out] iv_len Number of bytes generated.
 *
 * @return 0 on success, or a negative errno value on failure.
 */
int format_generate_iv(enum fce_aes_mode mode,
                       uint8_t **iv, size_t *iv_len);

/* ---------------------------------------------------------------------------
 * Decrypt-path parsing
 * --------------------------------------------------------------------------- */

/**
 * format_parse_decrypt_input — Parse a file that was produced by an encrypt
 *                              operation.
 *
 * Validates the file layout and returns pointers into the original buffer
 * for the IV, ciphertext, and (for GCM) authentication tag.  No copies
 * are made — the caller should memcpy the IV and tag if it needs them
 * after the input buffer is freed.
 *
 * File layout per mode:
 *   ECB:  [ciphertext]
 *   CBC:  [16-byte IV][ciphertext]
 *   CTR:  [16-byte IV][ciphertext]
 *   GCM:  [12-byte IV][ciphertext][16-byte tag]
 *
 * @param[in]  mode           AES mode.
 * @param[in]  input          Raw file contents.
 * @param[in]  input_len      File size in bytes.
 * @param[out] iv             Pointer to the IV within @p input (NULL for ECB).
 * @param[out] iv_len         IV length in bytes (0 for ECB).
 * @param[out] tag            Pointer to the tag within @p input (NULL for
 *                            non-GCM modes).
 * @param[out] ciphertext     Pointer to the raw ciphertext within @p input.
 * @param[out] ciphertext_len Ciphertext length in bytes.
 *
 * @return 0 on success, -EINVAL if the input is too short for the layout,
 *         or another negative errno value.
 */
int format_parse_decrypt_input(enum fce_aes_mode mode,
                               const uint8_t *input, size_t input_len,
                               const uint8_t **iv, size_t *iv_len,
                               const uint8_t **tag,
                               const uint8_t **ciphertext,
                               size_t *ciphertext_len);

/* ---------------------------------------------------------------------------
 * Encrypt-path assembly
 * --------------------------------------------------------------------------- */

/**
 * format_build_encrypt_output — Assemble the on-disk output layout.
 *
 * Allocates a buffer with the layout [IV][ciphertext][GCM-tag] matching
 * what format_parse_decrypt_input() expects.  The caller owns the buffer.
 *
 * @param[in]  mode           AES mode.
 * @param[in]  iv             IV / nonce bytes (ignored for ECB).
 * @param[in]  iv_len         IV length.
 * @param[in]  ciphertext     Raw ciphertext from the AES engine.
 * @param[in]  ciphertext_len Ciphertext length.
 * @param[in]  tag            GCM authentication tag (may be NULL for non-GCM).
 * @param[out] out            On success, a malloc'd buffer with the layout.
 * @param[out] out_len        Total output file size.
 *
 * @return 0 on success, or a negative errno value on failure.
 */
int format_build_encrypt_output(enum fce_aes_mode mode,
                                const uint8_t *iv, size_t iv_len,
                                const uint8_t *ciphertext,
                                size_t ciphertext_len,
                                const uint8_t *tag,
                                uint8_t **out, size_t *out_len);

/* ---------------------------------------------------------------------------
 * Display helpers
 * --------------------------------------------------------------------------- */

/**
 * format_print_iv — Print a hex dump of an IV / nonce to stdout.
 */
void format_print_iv(const uint8_t *iv, size_t iv_len);

/**
 * format_print_tag — Print a GCM authentication tag to stdout, annotated
 *                    with whether it was embedded or extracted.
 *
 * @param[in] tag        Tag bytes.
 * @param[in] tag_len    Tag length in bytes.
 * @param[in] is_encrypt Non-zero if this was an encryption operation
 *                       (prints "embedded in output file"), zero for
 *                       decryption ("extracted from input file").
 */
void format_print_tag(const uint8_t *tag, size_t tag_len, int is_encrypt);

#ifdef __cplusplus
}
#endif

#endif /* FCE_AES_FORMAT_H */
