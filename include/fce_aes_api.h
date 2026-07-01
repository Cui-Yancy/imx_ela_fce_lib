// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 *
 * fce_aes_api.h — Public API for i.MX943 FCE AES operations via the PRIME
 *                 cryptographic hardware engine.
 *
 * This module provides two tiers of API:
 *
 *   1. One-shot convenience API (aes_operation):
 *      Opens a PRIME service session, loads the key, performs a single
 *      encrypt/decrypt operation, then tears down the session.
 *
 *   2. Session-based API (aes_session_*):
 *      For repeated operations with the same key.  The caller opens a session
 *      once, loads a key, performs any number of crypto operations, then
 *      closes the session.  This avoids the overhead of allocating shared
 *      memory and re-loading the key on every call.
 *
 * All supported AES modes:
 *   - ECB  (Electronic Codebook)         — no IV required
 *   - CBC  (Cipher Block Chaining)       — 16-byte IV
 *   - CTR  (Counter)                     — 16-byte counter block (IV)
 *   - GCM  (Galois/Counter Mode, AEAD)   — 12-byte nonce/IV, AAD, 16-byte tag
 *
 * Key sizes: 16 bytes (AES-128), 24 bytes (AES-192), 32 bytes (AES-256).
 *
 * All functions return 0 on success or a negative errno-style value on
 * failure.  Use aes_strerror() to obtain a human-readable description.
 */

#ifndef FCE_AES_API_H
#define FCE_AES_API_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------
 * Constants
 * --------------------------------------------------------------------------- */

/** Maximum number of data bytes in a single operation.
 *  The PRIME firmware has exactly 1 GiB reserved memory
 *  (dmesg: "Prime Reserved mem: size=0x400 MB").  We leave a small
 *  margin for GCM status-buffer overhead (tag alignment + status).
 */
#define FCE_AES_MAX_DATA_SIZE          ((1UL * 1024UL * 1024UL * 1024UL) - 128UL)

/** Size of the PRIME shared-memory buffer.
 *  Must not exceed the firmware-reserved region (1 GiB). */
#define FCE_AES_SHARED_BUF_SIZE        (1UL * 1024UL * 1024UL * 1024UL)

/** Supported AES key lengths in bytes. */
#define FCE_AES_128_KEY_SIZE           16
#define FCE_AES_192_KEY_SIZE           24
#define FCE_AES_256_KEY_SIZE           32

/** Maximum IV / nonce length (CBC/CTR use 16, GCM uses 12). */
#define FCE_AES_MAX_IV_SIZE            16

/** GCM authentication tag length (always 16 bytes for PRIME). */
#define FCE_AES_GCM_TAG_SIZE           16

/* ---------------------------------------------------------------------------
 * Enumerations
 * --------------------------------------------------------------------------- */

/** AES cipher mode. */
enum fce_aes_mode {
    FCE_AES_ECB = 0,   /**< Electronic Codebook (no IV). */
    FCE_AES_CBC,        /**< Cipher Block Chaining. */
    FCE_AES_CTR,        /**< Counter mode. */
    FCE_AES_GCM,        /**< Galois/Counter Mode (AEAD). */
};

/** Operation direction. */
enum fce_aes_dir {
    FCE_AES_DECRYPT = 0, /**< Decryption. */
    FCE_AES_ENCRYPT = 1, /**< Encryption. */
};

/* ---------------------------------------------------------------------------
 * Structures
 * --------------------------------------------------------------------------- */

/**
 * struct aes_params — Parameters for a single AES encrypt / decrypt operation.
 *
 * All pointer fields must remain valid for the duration of the call.  The
 * caller owns the output buffer and must guarantee that @output_len is at
 * least @input_len (for cipher modes) or @input_len + @tag_len (for GCM).
 *
 * For GCM decryption the caller should supply the expected tag via @tag
 * so that the authentication result can be checked after the operation
 * completes.
 */
struct aes_params {
    /** Encrypt or decrypt. */
    enum fce_aes_dir  dir;
    /** AES mode (ECB, CBC, CTR, GCM). */
    enum fce_aes_mode mode;

    /* ---- Key ---- */
    const uint8_t    *key;         /**< Key bytes (16, 24, or 32 bytes). */
    size_t            key_len;     /**< Length of the key in bytes. */

    /* ---- IV / nonce ---- */
    const uint8_t    *iv;          /**< Initialization vector (NULL for ECB). */
    size_t            iv_len;      /**< IV length (16 for CBC/CTR, 12 for GCM). */

    /* ---- GCM only: additional authenticated data ---- */
    const uint8_t    *aad;         /**< Additional authenticated data (may be NULL). */
    size_t            aad_len;     /**< AAD length in bytes (may be 0). */

    /* ---- Data buffers ---- */
    const uint8_t    *input;       /**< Input plaintext or ciphertext. */
    size_t            input_len;   /**< Input length in bytes. */
    uint8_t          *output;      /**< Output buffer (caller-allocated). */
    size_t            output_len;  /**< Output buffer capacity. */

    /* ---- GCM only: authentication tag ---- */
    uint8_t          *tag;         /**< Authentication tag (16 bytes for GCM). */
    size_t            tag_len;     /**< Tag buffer size (0 for cipher modes). */
};

/**
 * struct aes_session — Opaque handle for a PRIME service session.
 *
 * Zero-initialise before first use (e.g. @c {0}).  Internal fields must
 * not be accessed directly by callers.
 */
struct aes_session {
    /** @cond private */
    uint32_t    service_hdl;   /**< PRIME service handle. */
    uint8_t     keyslot;       /**< Loaded key-slot index. */
    int         is_open;       /**< Non-zero after a successful open. */
    void       *shmem_va;      /**< Virtual address of shared buffer. */
    uint64_t    shmem_pa;      /**< Physical address of shared buffer. */
    /** @endcond */
};

/* ---------------------------------------------------------------------------
 * Session-based API
 * --------------------------------------------------------------------------- */

/**
 * Open a PRIME service session.
 *
 * Allocates a shared-memory buffer (256 MiB) via the SE library.  The caller
 * must zero-initialise @p sess before the first call.
 *
 * @param[out] sess  Session handle (initialised on success).
 *
 * @return 0 on success, or a negative errno value on failure.
 */
int aes_session_open(struct aes_session *sess);

/**
 * Load an AES key into a hardware key slot.
 *
 * The session must already be open (aes_session_open).  After a successful
 * call the key is resident in the PRIME hardware and @p sess internally
 * remembers which slot was used.
 *
 * @param[in,out] sess    Open session handle.
 * @param[in]     key     Key bytes (16, 24, or 32).
 * @param[in]     key_len Number of key bytes.
 *
 * @return 0 on success, or a negative errno value on failure.
 */
int aes_session_load_key(struct aes_session *sess,
                         const uint8_t *key, size_t key_len);

/**
 * Perform a single AES encrypt / decrypt operation within an active session.
 *
 * The key must have been loaded beforehand via aes_session_load_key().
 *
 * @param[in,out] sess   Open session with a loaded key.
 * @param[in,out] params Operation parameters (output is written to
 *                        params->output and, for GCM, params->tag).
 *
 * @return 0 on success, or a negative errno value on failure.
 */
int aes_session_crypto(struct aes_session *sess, struct aes_params *params);

/**
 * Close a PRIME service session and release all resources.
 *
 * Safe to call on a zero-initialised or already-closed session (idempotent).
 *
 * @param[in,out] sess Session handle to close.
 */
void aes_session_close(struct aes_session *sess);

/* ---------------------------------------------------------------------------
 * One-shot convenience API
 * --------------------------------------------------------------------------- */

/**
 * aes_operation — Open session, load key, perform one crypto op, close
 *                  session.
 *
 * This is a convenience wrapper that internally calls:
 *   aes_session_open()   →   aes_session_load_key()   →
 *   aes_session_crypto()   →   aes_session_close()
 *
 * Use this when you only need a single encrypt or decrypt call.  For
 * repeated operations prefer the session-based API for better performance.
 *
 * @param[in,out] params Operation parameters (see struct aes_params).
 *
 * @return 0 on success, or a negative errno value on failure.
 */
int aes_operation(struct aes_params *params);

/* ---------------------------------------------------------------------------
 * Error reporting
 * --------------------------------------------------------------------------- */

/**
 * Return a human-readable string for an error code returned by any of the
 * functions above.
 *
 * @param[in] err  Negative errno-style value (e.g. -EINVAL, -ENODEV).
 *
 * @return Pointer to a statically-allocated string (never NULL).
 */
const char *aes_strerror(int err);

#ifdef __cplusplus
}
#endif

#endif /* FCE_AES_API_H */
