// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 *
 * crypto_stream.h — Streaming AES encryption wrapper for per-frame encryption.
 *
 * Provides a simple API for encrypting a stream of independent data frames
 * (e.g. video frames) using the PRIME FCE hardware or OpenSSL fallback.
 *
 * Each frame is encrypted independently with a fresh random IV, producing the
 * wire format:
 *   [IV][ciphertext][+GCM-tag]
 *
 * The caller (e.g. an MJPEG streaming server) does not need to manage keys,
 * IVs, or hardware sessions — crypto_stream handles all of that internally.
 *
 * Usage:
 *   struct crypto_stream *cs = crypto_stream_new(FCE_AES_CTR, key, 16);
 *   if (!cs) { ... error handling ... }
 *
 *   for each frame {
 *       uint8_t *enc;
 *       size_t enc_len;
 *       crypto_stream_encrypt(cs, jpeg, jpeg_size, &enc, &enc_len);
 *       send(client, enc, enc_len);
 *       crypto_stream_free_buf(enc);
 *   }
 *
 *   crypto_stream_free(cs);
 */

#ifndef CRYPTO_STREAM_H
#define CRYPTO_STREAM_H

#include "fce_aes_api.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------
 * Opaque context
 * --------------------------------------------------------------------------- */

struct crypto_stream;

/* ---------------------------------------------------------------------------
 * Lifecycle
 * --------------------------------------------------------------------------- */

/**
 * crypto_stream_new — Create a streaming encryption context.
 *
 * Opens a PRIME service session and loads the AES key into hardware.  If the
 * PRIME hardware is not available (e.g. running on a non-i.MX platform, or
 * USE_PRIME=0 build), falls back to per-frame AES via OpenSSL in software.
 *
 * @param[in] mode    AES cipher mode (ECB, CBC, CTR, GCM).
 * @param[in] key     Key bytes (16, 24, or 32 bytes).
 * @param[in] key_len Key length in bytes.
 *
 * @return A new crypto_stream on success, or NULL on failure (invalid
 *         parameters, memory allocation failure, PRIME/OpenSSL error).
 */
struct crypto_stream *crypto_stream_new(enum fce_aes_mode mode,
                                        const uint8_t *key,
                                        size_t key_len);

/**
 * crypto_stream_free — Destroy a streaming encryption context.
 *
 * Closes the PRIME service session (if one was opened) and frees all
 * resources.  Safe to call with a NULL pointer (no-op).
 *
 * @param[in,out] cs  Context to destroy, or NULL.
 */
void crypto_stream_free(struct crypto_stream *cs);

/* ---------------------------------------------------------------------------
 * Encryption
 * --------------------------------------------------------------------------- */

/**
 * crypto_stream_encrypt — Encrypt one frame.
 *
 * Encrypts @p plaintext with the configured AES mode and a fresh random IV.
 * The output buffer is heap-allocated and contains the wire format:
 *   [IV bytes][ciphertext][+GCM tag]
 *
 * The caller must free @p *out with crypto_stream_free_buf().
 *
 * @param[in,out] cs        Encryption context.
 * @param[in]     plain     Plaintext input (e.g. raw JPEG frame).
 * @param[in]     plain_len Plaintext length in bytes.
 * @param[out]    out       On success, a heap-allocated output buffer.
 * @param[out]    out_len   Number of bytes written to @p *out.
 *
 * @return 0 on success, or a negative errno value on failure.
 */
int crypto_stream_encrypt(struct crypto_stream *cs,
                          const uint8_t *plain, size_t plain_len,
                          uint8_t **out, size_t *out_len);

/* ---------------------------------------------------------------------------
 * Wire-format helpers
 * --------------------------------------------------------------------------- */

/**
 * crypto_stream_iv_length — Return the IV length for the configured mode.
 */
size_t crypto_stream_iv_length(struct crypto_stream *cs);

/**
 * crypto_stream_tag_length — Return the GCM tag length.
 *                            0 for non-GCM modes.
 */
size_t crypto_stream_tag_length(struct crypto_stream *cs);

/**
 * crypto_stream_overhead — Return the total per-frame wire overhead
 *                          (iv_length + tag_length).
 */
size_t crypto_stream_overhead(struct crypto_stream *cs);

/* ---------------------------------------------------------------------------
 * Buffer management
 * --------------------------------------------------------------------------- */

/**
 * crypto_stream_free_buf — Free a buffer returned by crypto_stream_encrypt().
 *
 * @param[in] buf  Buffer to free, or NULL (no-op).
 */
void crypto_stream_free_buf(void *buf);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_STREAM_H */
