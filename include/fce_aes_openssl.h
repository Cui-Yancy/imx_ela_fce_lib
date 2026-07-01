// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 *
 * fce_aes_openssl.h — OpenSSL-based AES software implementation.
 *
 * Provides an aes_openssl_operation() function with the same interface as
 * aes_operation() (from fce_aes_api.h) but implemented using the OpenSSL
 * EVP API in software rather than the i.MX943 PRIME hardware engine.
 *
 * Purpose:
 *   Use this alongside the PRIME-based path to cross-verify correctness.
 *   Run the same key / IV / plaintext through both backends and compare
 *   ciphertext and (for GCM) authentication tags.
 *
 * Supported modes: ECB, CBC, CTR, GCM  (matching fce_aes_api.h)
 * Key sizes:       16, 24, 32 bytes
 *
 * Padding:
 *   ECB and CBC use PKCS#7 padding (OpenSSL default) to match the
 *   PRIME backend behaviour — any plaintext length is accepted.
 *
 * CTR IV:
 *   CTR mode uses a 16-byte counter block (IV).  When a 12-byte nonce
 *   is provided it is padded to 16 bytes as [nonce || 0x00000001]
 *   (standard NIST SP 800-38A initial counter value).
 */

#ifndef FCE_AES_OPENSSL_H
#define FCE_AES_OPENSSL_H

#include "fce_aes_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * aes_openssl_operation — AES encrypt / decrypt using OpenSSL (software).
 *
 * Same semantics as aes_operation() from the PRIME API.  @p params
 * is set up identically (see struct aes_params in fce_aes_api.h).
 *
 * @param[in,out] params  Operation parameters.
 *
 * @return 0 on success, or a negative errno value on failure.
 */
int aes_openssl_operation(struct aes_params *params);

#ifdef __cplusplus
}
#endif

#endif /* FCE_AES_OPENSSL_H */
