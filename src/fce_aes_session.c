// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 *
 * fce_aes_session.c — PRIME AES session API implementation.
 *
 * This file translates the public fce_aes_session.h interface into calls to the
 * NXP PRIME SE library.  It manages:
 *   - PRIME service session lifecycle (open / close)
 *   - AES key loading into hardware key slots
 *   - Shared-memory buffer layout and cache coherency
 *   - Submission of cipher (ECB/CBC/CTR) and AEAD (GCM) operations
 *
 * When compiled without USE_PRIME (USE_PRIME=0 in the Makefile), all public
 * functions become stubs that return -ENODEV ("Crypto service not available").
 * This allows the application to be built on any Linux platform using only
 * the OpenSSL backend (aes_openssl_operation).
 *
 * Cache coherency notes (PRIME build only)
 * ------------------------------------------
 * The PRIME hardware accesses data via DMA.  Before submitting an operation
 * we must clean (write back) the data cache so that the hardware sees the
 * latest values.  After the operation completes we must clean-and-invalidate
 * so that subsequent CPU reads do not hit stale cache lines.
 *
 * ARMv8 data-cache instructions used:
 *   - "dc cvac"   — clean (write back) to Point of Coherency
 *   - "dc civac"  — clean AND invalidate
 */

#include "fce_aes_session.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ======================================================================
 * PRIME hardware backend
 * ====================================================================== */
#ifdef USE_PRIME

/* PRIME library headers (from the ELE tree).
 * The build system must add the appropriate -I paths.
 */
#include "prime/prime.h"
#include "prime/internal/prime_aes.h"
#include "prime/internal/prime_handle.h"
#include "prime/internal/prime_service.h"
#include "prime/internal/prime_utils.h"

/* ======================================================================
 * Constants & macros
 * ====================================================================== */

/** PRIME hardware cache-line size (confirmed by the test suite). */
#define FCE_CACHE_LINE_SIZE     32

/** Round X up to the next multiple of ALIGN. */
#define ALIGN_UP(x, align)  (((x) + (typeof(x))(align) - 1u) & ~((typeof(x))(align) - 1u))

/* ======================================================================
 * ARM cache-coherency helpers
 * ====================================================================== */

/*
 * Data cache clean (write-back) — use before DMA to ensure the hardware
 * reads the most recent values from memory.
 */
static inline void dc_clean(void *addr)
{
    asm volatile("dc cvac, %0" : : "r"(addr) : "memory");
}

/*
 * Data cache clean AND invalidate — use after DMA so that the CPU does
 * not read stale cache lines.
 */
static inline void dc_clean_inval(void *addr)
{
    asm volatile("dc civac, %0" : : "r"(addr) : "memory");
}

/*
 * Ensure all cache operations above have completed before proceeding.
 */
static inline void dsb(void)
{
    asm volatile("dsb sy" : : : "memory");
}

/**
 * data_cache_clean — Managed cache maintenance over a buffer.
 *
 * @param[in,out] buf        Start of the buffer (need not be cache-line aligned).
 * @param[in]     len        Length of the buffer in bytes.
 * @param[in]     clean_only 1 = clean only (before DMA); 0 = clean + invalidate
 *                           (after DMA).
 */
static void data_cache_clean(uint8_t *buf, uint32_t len, int clean_only)
{
    uint32_t i;

    if (!buf || len == 0)
        return;

    for (i = 0; i < len; i += FCE_CACHE_LINE_SIZE) {
        if (clean_only)
            dc_clean(buf + i);
        else
            dc_clean_inval(buf + i);
    }
    dsb();
}

/* ======================================================================
 * PRIME error → errno mapping
 * ====================================================================== */

/**
 * prime_err_to_errno — Convert a PRIME library error code to a negated
 *                      errno value.
 */
static int prime_err_to_errno(prime_err_t err)
{
    switch (err) {
    case PRIME_ERR_NONE:          return 0;
    case PRIME_ERR_INVALID_PARAM: return -EINVAL;
    case PRIME_ERR_MEMORY_ALLOC:  return -ENOMEM;
    case PRIME_ERR_SERVICE_OPEN:  return -ENODEV;
    case PRIME_ERR_SERVICE_CLOSE: return -ENODEV;
    default:                      return -EIO;
    }
}

/* ======================================================================
 * Parameter validation helpers
 * ====================================================================== */

/**
 * Check that an AES key length is one of the three allowed sizes.
 */
static int valid_key_len(size_t len)
{
    return len == 16 || len == 24 || len == 32;
}

/**
 * Check that a mode is one of the four supported values.
 */
static int valid_mode(enum fce_aes_mode mode)
{
    return mode >= FCE_AES_ECB && mode <= FCE_AES_GCM;
}

/* ======================================================================
 * Session-based API
 * ====================================================================== */

int aes_session_open(struct aes_session *sess)
{
    open_service_args_t serv_args;
    prime_hdl_t hdl;
    prime_err_t perr;

    if (!sess)
        return -EINVAL;

    /* Idempotent: if already open, succeed silently. */
    if (sess->is_open)
        return 0;

    memset(&serv_args, 0, sizeof(serv_args));
    serv_args.serv_type     = SERVICE_TYPE_ALL;
    serv_args.size          = FCE_AES_SHARED_BUF_SIZE;
    serv_args.physical_addr = 0;   /* let the SE library allocate */
    serv_args.virtual_addr  = 0;   /* let the SE library allocate */

    perr = prime_open_service(&serv_args, &hdl);
    if (perr != PRIME_ERR_NONE)
        return prime_err_to_errno(perr);

    sess->service_hdl = hdl;
    sess->is_open     = 1;
    sess->shmem_va    = (void *)serv_args.virtual_addr;
    sess->shmem_pa    = serv_args.physical_addr;
    sess->keyslot     = 0;

    return 0;
}

int aes_session_load_key(struct aes_session *sess,
                         const uint8_t *key, size_t key_len)
{
    aes_key_t key_args;
    prime_err_t perr;

    if (!sess || !sess->is_open)
        return -EINVAL;
    if (!key || !valid_key_len(key_len))
        return -EINVAL;

    memset(&key_args, 0, sizeof(key_args));
    key_args.key    = key;
    key_args.keylen = (uint32_t)key_len;

    perr = prime_cipher_init(sess->service_hdl, &key_args);
    if (perr != PRIME_ERR_NONE)
        return prime_err_to_errno(perr);

    /* Remember the slot assigned by the library. */
    sess->keyslot = key_args.keyslot;

    return 0;
}

int aes_session_crypto(struct aes_session *sess, struct aes_params *params)
{
    crypto_op_args_t op;
    crypto_op_args_t *ops_ptr;
    uint8_t *data_buf;        /* start of data area in shared memory */
    uint8_t *status_area;     /* start of status buffer */
    uint8_t *aad_buf = NULL;  /* AAD buffer (GCM only) */
    uint8_t *tag_buf = NULL;  /* tag buffer (GCM only) */
    uint32_t aad_offset = 0;  /* byte offset of AAD from data_buf (GCM) */
    uint32_t nb_ops;
    size_t status_offset;     /* byte offset of status from data_buf */
    size_t total_needed;      /* total bytes needed in shared buffer */
    int err;

    /* ---- parameter validation ---- */
    if (!sess || !sess->is_open)
        return -EINVAL;
    if (!params || !params->input || !params->output)
        return -EINVAL;
    if (!valid_mode(params->mode))
        return -EINVAL;
    if (!valid_key_len(params->key_len))
        return -EINVAL;

    /* IV required for CBC, CTR, GCM. */
    if (params->mode != FCE_AES_ECB && (!params->iv || params->iv_len == 0))
        return -EINVAL;

    /* Check that the output buffer is large enough. */
    if (params->output_len < params->input_len)
        return -ENOSPC;

    /* ---- Determine shared-buffer data length (includes PKCS#7 padding) ----
     *
     * For ECB and CBC on encrypt we pad the plaintext to a multiple of the
     * AES block size (16 bytes) using PKCS#7.  The PRIME hardware always
     * processes full blocks, so we must present block-aligned data.
     *
     * For decrypt the ciphertext is already block-aligned (it was padded
     * during encryption).  CTR and GCM do not use padding.
     */
    uint32_t buf_data_len = (uint32_t)params->input_len;

    if ((params->mode == FCE_AES_ECB || params->mode == FCE_AES_CBC) &&
        params->dir == FCE_AES_ENCRYPT) {
        buf_data_len = (uint32_t)((params->input_len + 16) & ~(size_t)15);
    }

    /* ---- calculate shared-buffer layout ----
     *
     * Cipher modes (ECB, CBC, CTR):
     *   [data: buf_data_len bytes]
     *   [padding to 64-byte boundary]
     *   [status: 4 bytes]
     *
     * GCM (AEAD mode) — matches the reference test_aes_gcm.c layout:
     *   [data: input_len bytes]
     *   [AAD: aad_len bytes]        <- immediately after data
     *   [tag: 16 bytes]             <- immediately after AAD
     *   [padding to 64-byte boundary from tag start]
     *   [status: 4 bytes]
     */
    if (params->mode == FCE_AES_GCM) {
        /* GCM: data + padding + AAD + tag, status aligned after tag
         *
         * The PRIME firmware's DMA engine requires the AAD and tag
         * buffers to be 16-byte aligned within shared memory.  Since
         * the AAD is 16 bytes, aligning the AAD offset to 16 bytes
         * automatically aligns the tag that follows it. */
        aad_offset = ALIGN_UP((uint32_t)params->input_len, 16);
        status_offset = aad_offset + params->aad_len +
                        ALIGN_UP(FCE_AES_GCM_TAG_SIZE, 64);
        total_needed  = status_offset + sizeof(status_buf_t);
    } else {
        /* Cipher modes: data + padding + status */
        status_offset = ALIGN_UP(buf_data_len, 64);
        total_needed  = status_offset + sizeof(status_buf_t);
    }

    /* Safety check: does it fit in our shared buffer? */
    if (total_needed > FCE_AES_SHARED_BUF_SIZE)
        return -EFBIG;

    /* Check output buffer capacity: need room for padded data. */
    if (params->output_len < buf_data_len)
        return -ENOSPC;

    /* ---- populate crypto_op_args_t ---- */
    memset(&op, 0, sizeof(op));

    data_buf    = (uint8_t *)sess->shmem_va;
    status_area = data_buf + status_offset;

    /* Copy the input data into the shared buffer. */
    memcpy(data_buf, params->input, params->input_len);

    /* PKCS#7 padding for ECB/CBC encrypt.
     *
     * If the plaintext length is already a multiple of the block size
     * we add a full padding block (16 bytes of 0x10).  This guarantees
     * that the decrypt path can unambiguously strip the padding.
     */
    if ((params->mode == FCE_AES_ECB || params->mode == FCE_AES_CBC) &&
        params->dir == FCE_AES_ENCRYPT) {
        uint32_t pad_len = buf_data_len - (uint32_t)params->input_len;
        uint8_t  pad_val = (uint8_t)pad_len;
        memset(data_buf + params->input_len, pad_val, pad_len);
    }

    /* Source and destination are the same buffer (in-place). */
    op.src.virt_addr = data_buf;
    op.src.phys_addr = sess->shmem_pa;
    op.src.len       = buf_data_len;
    op.dst           = op.src;

    /* ---- status buffer ---- */
    op.crypto_status.phys_addr = (status_buf_t *)(sess->shmem_pa +
                                                   (uint64_t)status_offset);
    op.crypto_status.virt_addr = (status_buf_t *)status_area;

    /* ---- type-specific parameters ---- */
    if (params->mode == FCE_AES_GCM) {
        /* ---- AEAD operation (GCM) ----
         *
         * Buffer layout (matching test_aes_gcm.c):
         *   [0..input_len):          data (plaintext or ciphertext)
         *   [input_len..aad_offset): padding to 16-byte alignment
         *   [aad_offset..+aad_len):   AAD
         *   [aad_offset+aad_len..+16): tag (written by firmware)
         *   [tag + ALIGN_UP(16,64)]:  status
         *
         * The AAD offset is padded to 16 bytes so that the AAD and
         * tag buffers are correctly aligned for the PRIME DMA engine.
         */
        op.op_type = CRYPTO_OP_TYPE_AEAD;

        /* AAD placed after padding gap for alignment */
        aad_buf = data_buf + aad_offset;
        /* Tag placed immediately after AAD */
        tag_buf = aad_buf + params->aad_len;

        /* Copy AAD.  Even if aad_len == 0 we provide a valid buffer
         * because the PRIME firmware requires a non-NULL address.
         */
        if (params->aad && params->aad_len > 0) {
            memcpy(aad_buf, params->aad, params->aad_len);
            data_cache_clean(aad_buf, (uint32_t)params->aad_len, 1);
        } else if (params->aad_len == 0) {
            /* Firmware needs a valid address even for zero-length AAD.
             * Point it at the tag buffer (which is valid memory). */
            aad_buf = tag_buf;
        }

        /* For GCM decrypt, copy the expected authentication tag to
         * shared memory so the firmware can perform the verification.
         * (For encrypt the tag buffer is an output written by the
         * firmware, so no copy is needed here.) */
        if (params->dir == FCE_AES_DECRYPT &&
            params->tag && params->tag_len >= FCE_AES_GCM_TAG_SIZE) {
            memcpy(tag_buf, params->tag, FCE_AES_GCM_TAG_SIZE);
            data_cache_clean(tag_buf, FCE_AES_GCM_TAG_SIZE, 1);
        }

        op.op_aead_args.algo    = CRYPTO_AEAD_AES_GCM;
        op.op_aead_args.keyslot = sess->keyslot;
        /* AEAD uses the same enc convention as cipher ops:
         *   0 = decrypt, non-zero = encrypt.
         */
        op.op_aead_args.enc    = (uint8_t)(params->dir == FCE_AES_ENCRYPT ?
                                            CRYPTO_CIPHER_OP_ENCRYPT :
                                            CRYPTO_CIPHER_OP_DECRYPT);
        op.op_aead_args.iv     = (uint8_t *)params->iv;
        op.op_aead_args.ivlen  = (uint16_t)params->iv_len;

        /* AAD buffer descriptor. */
        op.op_aead_args.aad.virt_addr = aad_buf;
        op.op_aead_args.aad.phys_addr = sess->shmem_pa +
                                        (uint64_t)(aad_buf - data_buf);
        op.op_aead_args.aad.len       = (uint32_t)params->aad_len;

        /* Tag buffer (output — written by the firmware). */
        op.op_aead_args.tag.virt_addr = tag_buf;
        op.op_aead_args.tag.phys_addr = sess->shmem_pa +
                                        (uint64_t)(tag_buf - data_buf);
        op.op_aead_args.tag.len       = FCE_AES_GCM_TAG_SIZE;

        /* GCM preserves output size; no padding needed. */
        params->output_used = params->input_len;

    } else {
        /* ---- Cipher operation (ECB, CBC, CTR) ---- */
        op.op_type = CRYPTO_OP_TYPE_AES;

        /* Map our mode to the PRIME cipher algorithm enum. */
        switch (params->mode) {
        case FCE_AES_ECB:
            op.op_aes_args.algo = CRYPTO_CIPHER_AES_ECB;
            break;
        case FCE_AES_CBC:
            op.op_aes_args.algo = CRYPTO_CIPHER_AES_CBC;
            break;
        case FCE_AES_CTR:
            op.op_aes_args.algo = CRYPTO_CIPHER_AES_CTR;
            break;
        default:
            /* Should not happen — validated above. */
            return -EINVAL;
        }

        op.op_aes_args.keyslot = sess->keyslot;
        op.op_aes_args.enc     = (uint8_t)(params->dir == FCE_AES_ENCRYPT ?
                                            CRYPTO_CIPHER_OP_ENCRYPT :
                                            CRYPTO_CIPHER_OP_DECRYPT);
        op.op_aes_args.iv      = (uint8_t *)params->iv;
        op.op_aes_args.ivlen   = (uint16_t)params->iv_len;

        /* CTR does not use padding; output size equals input. */
        if (params->mode == FCE_AES_CTR)
            params->output_used = params->input_len;
    }

    /* ---- cache-clean input data before DMA ---- */
    data_cache_clean(data_buf, buf_data_len, 1);

    /* ---- submit to PRIME hardware ---- */
    ops_ptr = &op;
    nb_ops  = 1;

    err = prime_process_ops(sess->service_hdl, &ops_ptr, nb_ops);
    if (err) {
        /* prime_process_ops returns non-zero on failure. */
        return -EIO;
    }

    /*
     * Host-side pipeline check.
     *
     * The PRIME library's enqueue path may set op_status to CRYPTO_OP_FIFO_FULL
     * (or another error) even when prime_process_ops returns 0.  This catches
     * push-command failures (0xYY29) where the firmware never ran.
     */
    if (op.op_status != CRYPTO_OP_COMPLETED) {
        return -EIO;
    }

    /* ---- cache-clean-and-invalidate output after DMA ---- */
    data_cache_clean(data_buf, buf_data_len, 0);

    /*
     * Firmware status check.
     *
     * Per NXP convention the firmware writes 0xYYD6 into the status buffer's
     * first byte to signal success.  Any other value (including the push-
     * command error 0xYY29) means the operation failed at the firmware level.
     *
     * Invalidate the status buffer before reading because the firmware wrote
     * it via DMA and the data cache may hold stale lines.
     */
    {
        status_buf_t *fw_st = (status_buf_t *)op.crypto_status.virt_addr;
        data_cache_clean((uint8_t *)fw_st, sizeof(status_buf_t), 0);
        if (fw_st->status_code != 0xD6) {
            return -EIO;
        }
    }

    /* ---- copy result back to caller, stripping padding for ECB/CBC decrypt ---- */
    if ((params->mode == FCE_AES_ECB || params->mode == FCE_AES_CBC) &&
        params->dir == FCE_AES_DECRYPT) {
        /* Strip PKCS#7 padding.
         *
         * The last byte of the decrypted data is the padding value
         * (range 1–16).  Verify that all <pad_val> trailing bytes
         * equal <pad_val>, then exclude them from the output.
         */
        uint8_t  pad_val = data_buf[buf_data_len - 1];
        uint32_t pad_len = (uint32_t)pad_val;

        if (pad_len > 0 && pad_len <= 16 && pad_len <= buf_data_len) {
            uint32_t i;
            uint8_t  padding_ok = 1;
            for (i = buf_data_len - pad_len; i < buf_data_len; i++) {
                if (data_buf[i] != pad_val) {
                    padding_ok = 0;
                    break;
                }
            }
            if (padding_ok) {
                buf_data_len -= pad_len;
            }
            /* If padding is invalid (should not happen with valid
             * ciphertext), leave buf_data_len unchanged so the caller
             * still gets all the decrypted bytes. */
        }

        memcpy(params->output, data_buf, buf_data_len);
        params->output_used = buf_data_len;

    } else {
        memcpy(params->output, data_buf, buf_data_len);
        params->output_used = buf_data_len;
    }

    if (params->mode == FCE_AES_GCM) {
        data_cache_clean(tag_buf, FCE_AES_GCM_TAG_SIZE, 0);
        if (params->tag && params->tag_len >= FCE_AES_GCM_TAG_SIZE)
            memcpy(params->tag, tag_buf, FCE_AES_GCM_TAG_SIZE);
    }

    return 0;
}

void aes_session_close(struct aes_session *sess)
{
    if (!sess)
        return;

    if (sess->is_open && sess->service_hdl != PRIME_HANDLE_NONE) {
        prime_close_service(sess->service_hdl);
    }

    memset(sess, 0, sizeof(*sess));
}

/* ======================================================================
 * PRIME build — error string
 * ====================================================================== */

#else /* !USE_PRIME */

/* ======================================================================
 * Stub implementations (pure OpenSSL / no-PRIME build)
 *
 * When USE_PRIME is not set, the PRIME hardware is unavailable.  These
 * stubs return -ENODEV so that any caller that tries to use the PRIME
 * backend gets a clear diagnostic.  The application always uses the
 * OpenSSL backend in this configuration.
 * ====================================================================== */

int aes_session_open(struct aes_session *sess)
{
    (void)sess;
    return -ENODEV;
}

int aes_session_load_key(struct aes_session *sess,
                         const uint8_t *key, size_t key_len)
{
    (void)sess;
    (void)key;
    (void)key_len;
    return -ENODEV;
}

int aes_session_crypto(struct aes_session *sess, struct aes_params *params)
{
    (void)sess;
    (void)params;
    return -ENODEV;
}

void aes_session_close(struct aes_session *sess)
{
    /* Idempotent: just clear the struct. */
    if (sess)
        memset(sess, 0, sizeof(*sess));
}

#endif /* USE_PRIME */

/* ======================================================================
 * Error string (common to both build configurations)
 * ====================================================================== */

const char *aes_strerror(int err)
{
    switch (err) {
    case 0:              return "Success";
    case -EINVAL:        return "Invalid parameter";
    case -ENOMEM:        return "Memory allocation failed";
    case -ENODEV:        return "Crypto service not available";
    case -ENOSPC:        return "Output buffer too small";
    case -EFBIG:         return "Input data too large";
    case -EIO:           return "Crypto operation failed";
    case -EBADMSG:       return "Authentication failed (GCM tag mismatch)";
    default:             return "Unknown error";
    }
}
