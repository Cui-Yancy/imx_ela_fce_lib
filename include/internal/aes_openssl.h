// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 *
 * aes_openssl.h — OpenSSL-based AES software implementation.
 *
 * Provides an aes_openssl_operation() function with the same interface as
 * the low-level aes_session_crypto() / struct aes_params convention
 * (from fce_aes_session.h) but implemented using the OpenSSL
 * EVP API in software.  This is a standalone AES software backend,
 * independent of the PRIME hardware engine.
 *
 * Supported modes: ECB, CBC, CTR, GCM
 * Key sizes:       16, 24, 32 bytes
 *
 * Padding:
 *   ECB and CBC use PKCS#7 padding (OpenSSL default) — any plaintext
 *   length is accepted.
 *
 * CTR IV:
 *   CTR mode uses a 16-byte counter block (IV).  When a 12-byte nonce
 *   is provided it is padded to 16 bytes as [nonce || 0x00000001]
 *   (standard NIST SP 800-38A initial counter value).
 */

#ifndef AES_OPENSSL_H
#define AES_OPENSSL_H

#include "internal/fce_aes_session.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * aes_openssl_operation — AES encrypt / decrypt using OpenSSL (software).
 *
 * Same semantics as aes_operation() from the PRIME API.  @p params
 * is set up identically (see struct aes_params in fce_aes_session.h).
 *
 * @param[in,out] params  Operation parameters.
 *
 * @return 0 on success, or a negative errno value on failure.
 */
int aes_openssl_operation(struct aes_params *params);

#ifdef __cplusplus
}
#endif

#endif /* AES_OPENSSL_H */
