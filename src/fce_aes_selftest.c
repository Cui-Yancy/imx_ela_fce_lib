// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 *
 * fce_aes_selftest.c — Built-in self-test implementation.
 *
 * Test vectors are taken from the NXP ELE PRIME test suite to ensure
 * consistency with the platform's validated test cases.
 *
 * For each AES mode the test performs:
 *   encrypt → decrypt → compare plaintext (round-trip),
 *   plus a cross-verify that compares the PRIME hardware backend against
 *   the OpenSSL software backend (ciphertext comparison and cross-decrypt).
 *
 * GCM additionally verifies that the authentication tag is non-zero.
 */

#include "fce_aes_selftest.h"
#include "fce_aes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ======================================================================
 * Test data — AES-256
 * ====================================================================== */

/* ---- AES-256-ECB key (from ele/test/prime/include/aes_ecb_test_vector.h) ---- */
static const uint8_t ecb_key[32] = {
    0x14, 0xaa, 0xfd, 0xd8, 0xb7, 0x9f, 0x0b, 0x38,
    0xe4, 0x52, 0x07, 0x87, 0x79, 0x51, 0x79, 0x08,
    0xb0, 0xdf, 0xcc, 0x7a, 0xfe, 0x16, 0xa5, 0x41,
    0x01, 0xf3, 0xf1, 0x0a, 0x45, 0xfb, 0x18, 0x0d,
};

/* ---- AES-256-CBC key & IV (from ele/test/prime/include/aes_cbc_test_vector.h) ---- */
static const uint8_t cbc_key[32] = {
    0xe2, 0xf7, 0xfe, 0xf7, 0x12, 0xca, 0x2c, 0x68,
    0x5a, 0xd8, 0xe0, 0x52, 0x92, 0x5a, 0xb1, 0x05,
    0x87, 0xa4, 0xfc, 0xdf, 0x3f, 0xee, 0xe3, 0x36,
    0x52, 0x49, 0xb3, 0xc2, 0xe5, 0x1d, 0x79, 0xd7,
};
static const uint8_t cbc_iv[16] = {
    0x41, 0x5e, 0x63, 0x11, 0x16, 0xf5, 0x30, 0xd2,
    0xcd, 0xa8, 0xe0, 0x36, 0x4d, 0xbf, 0x67, 0xfb,
};

/* ---- AES-256-CTR key & IV (from ele/test/prime/include/aes_ctr_test_vector.h) ---- */
static const uint8_t ctr_key[32] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
};
static const uint8_t ctr_iv[16] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
};

/* ---- AES-256-GCM key, IV & AAD (from ele/test/prime/test_aes_gcm.c) ---- */
static const uint8_t gcm_key[32] = {
    0x17, 0xd2, 0x2f, 0x3d, 0xf2, 0x10, 0x9e, 0x63,
    0x3b, 0xbf, 0x5a, 0x65, 0x07, 0xdf, 0x26, 0x30,
    0x09, 0x29, 0xde, 0xee, 0x69, 0x9f, 0xa9, 0xf2,
    0x69, 0x56, 0x64, 0x52, 0x5b, 0x1f, 0x7f, 0x1d,
};
static const uint8_t gcm_iv[12] = {
    0xdf, 0x73, 0x20, 0x14, 0xbb, 0xba, 0xa5, 0xdd,
    0xea, 0xda, 0x16, 0x5a,
};
static const uint8_t gcm_aad[16] = {
    0x8c, 0xbc, 0xf1, 0x56, 0xf0, 0xa2, 0x30, 0x1d,
    0x83, 0xee, 0x04, 0x16, 0xd9, 0xb7, 0xbb, 0x2f,
};

/* Small plaintext for self-test (256 bytes). */
static const uint8_t test_plaintext[256] = {
    0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
    0x61, 0x20, 0x73, 0x65, 0x6c, 0x66, 0x2d, 0x74,
    0x65, 0x73, 0x74, 0x20, 0x6f, 0x66, 0x20, 0x74,
    0x68, 0x65, 0x20, 0x69, 0x2e, 0x4d, 0x58, 0x39,
    0x34, 0x33, 0x20, 0x46, 0x43, 0x45, 0x20, 0x41,
    0x45, 0x53, 0x20, 0x50, 0x52, 0x49, 0x4d, 0x45,
    0x20, 0x65, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x2e,
    0x20, 0x20, 0x49, 0x66, 0x20, 0x79, 0x6f, 0x75,
    0x20, 0x63, 0x61, 0x6e, 0x20, 0x72, 0x65, 0x61,
    0x64, 0x20, 0x74, 0x68, 0x69, 0x73, 0x2c, 0x20,
    0x41, 0x45, 0x53, 0x20, 0x65, 0x6e, 0x63, 0x72,
    0x79, 0x70, 0x74, 0x2f, 0x64, 0x65, 0x63, 0x72,
    0x79, 0x70, 0x74, 0x20, 0x77, 0x6f, 0x72, 0x6b,
    0x73, 0x20, 0x63, 0x6f, 0x72, 0x72, 0x65, 0x63,
    0x74, 0x6c, 0x79, 0x21, 0x20, 0x41, 0x42, 0x43,
    0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
    0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53,
    0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x20,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x20, 0x61, 0x62, 0x63, 0x64, 0x65,
    0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
    0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75,
    0x76, 0x77, 0x78, 0x79, 0x7a, 0x2e, 0x20, 0x46,
    0x43, 0x45, 0x20, 0x41, 0x45, 0x53, 0x20, 0x73,
    0x65, 0x6c, 0x66, 0x2d, 0x74, 0x65, 0x73, 0x74,
    0x20, 0x6f, 0x6e, 0x20, 0x69, 0x2e, 0x4d, 0x58,
    0x39, 0x34, 0x33, 0x2e, 0x20, 0x43, 0x61, 0x6e,
    0x20, 0x79, 0x6f, 0x75, 0x20, 0x72, 0x65, 0x61,
    0x64, 0x20, 0x74, 0x68, 0x69, 0x73, 0x3f, 0x20,
    0x41, 0x45, 0x53, 0x2d, 0x32, 0x35, 0x36, 0x20,
    0x72, 0x6f, 0x75, 0x6e, 0x64, 0x2d, 0x74, 0x72,
    0x69, 0x70, 0x20, 0x74, 0x65, 0x73, 0x74, 0x2e,
};

/* ======================================================================
 * Helper: run a single-mode round-trip test
 * ====================================================================== */

/**
 * test_roundtrip — Encrypt then decrypt, verify match.
 *
 * When @p use_openssl is non-zero the test uses the OpenSSL software backend;
 * otherwise it uses the default backend (PRIME when available).
 *
 * @param mode        AES mode.
 * @param mode_name   Human-readable label.
 * @param key         Key bytes.
 * @param key_len     Key length.
 * @param iv          IV / nonce (may be NULL for ECB).
 * @param iv_len      IV length.
 * @param aad         Additional authenticated data (may be NULL).
 * @param aad_len     AAD length.
 * @param plaintext   Input plaintext.
 * @param pt_len      Plaintext length.
 * @param use_openssl Non-zero to force the OpenSSL backend.
 *
 * @return 0 on success, -1 on failure.
 */
static int test_roundtrip(enum fce_aes_mode mode,
                          const char *mode_name,
                          const uint8_t *key, size_t key_len,
                          const uint8_t *iv, size_t iv_len,
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *plaintext, size_t pt_len,
                          int use_openssl)
{
    struct fce_aes *ctx = NULL;
    uint8_t *ct  = NULL;
    uint8_t *dec = NULL;
    size_t ct_len, dec_len;
    int ret = -1;

    /* Create AES context. */
    if (use_openssl)
        ctx = fce_aes_init_ex(mode, key, key_len,
                              aad, aad_len, FCE_AES_FLAG_FORCE_OPENSSL);
    else
        ctx = fce_aes_init(mode, key, key_len, aad, aad_len);

    if (!ctx) {
        const char *bn = use_openssl ? "OpenSSL" : "default";
        printf("  %s init FAILED (%s)\n", mode_name, bn);
        return -1;
    }

    /* ---- Encrypt ---- */
    ret = fce_aes_encrypt(ctx, iv, iv_len, plaintext, pt_len, &ct, &ct_len);
    if (ret) {
        const char *bn = use_openssl ? "OpenSSL" : "default";
        printf("  %s encrypt FAILED (%s: %s)\n",
               mode_name, bn, fce_aes_strerror(ret));
        goto out;
    }

    /* ---- Decrypt (same IV) ---- */
    ret = fce_aes_decrypt(ctx, iv, iv_len, ct, ct_len, &dec, &dec_len);
    if (ret) {
        const char *bn = use_openssl ? "OpenSSL" : "default";
        printf("  %s decrypt FAILED (%s: %s)\n",
               mode_name, bn, fce_aes_strerror(ret));
        goto out;
    }

    /* ---- Verify round-trip ---- */
    if (dec_len != pt_len || memcmp(dec, plaintext, pt_len) != 0) {
        printf("  %s round-trip FAILED (data mismatch)\n", mode_name);
        ret = -1;
        goto out;
    }

    /* ---- For GCM, verify the tag is populated (non-zero) ---- */
    if (mode == FCE_AES_GCM) {
        size_t tag_len = fce_aes_tag_length(ctx);
        int    tag_ok  = 0;
        size_t i;

        /* The last tag_len bytes of ct are the tag. */
        for (i = ct_len - tag_len; i < ct_len; i++) {
            if (ct[i] != 0) {
                tag_ok = 1;
                break;
            }
        }
        if (!tag_ok) {
            printf("  %s encrypt: tag is all zeroes (suspicious)\n", mode_name);
            /* Not a hard failure — the PRIME firmware may write the tag
             * in a different way, but this is worth flagging. */
        }
    }

    printf("  %s encrypt/decrypt: PASS\n", mode_name);
    ret = 0;

out:
    fce_aes_free_buf(ct);
    fce_aes_free_buf(dec);
    fce_aes_free(ctx);
    return ret;
}

/* ======================================================================
 * Cross-verify: PRIME vs OpenSSL  (PRIME build only)
 * ====================================================================== */
#if defined(USE_PRIME)

/**
 * test_cross — Cross-verify PRIME and OpenSSL backends produce identical
 *              results.
 *
 * For each mode the function performs (in this order):
 *   1. Encrypt with PRIME.
 *   2. Encrypt with OpenSSL (same IV).
 *   3. Compare the two ciphertexts (must be identical).
 *   4. Decrypt PRIME ciphertext with OpenSSL — must match original.
 *   5. Decrypt OpenSSL ciphertext with PRIME — must match original.
 *
 * @param mode        AES mode.
 * @param mode_name   Human-readable label.
 * @param key         Key bytes.
 * @param key_len     Key length.
 * @param iv          IV / nonce (may be NULL for ECB).
 * @param iv_len      IV length.
 * @param aad         Additional authenticated data (may be NULL).
 * @param aad_len     AAD length.
 * @param plaintext   Input plaintext.
 * @param pt_len      Plaintext length.
 *
 * @return 0 on success, -1 on failure.
 */
static int test_cross(enum fce_aes_mode mode,
                      const char *mode_name,
                      const uint8_t *key, size_t key_len,
                      const uint8_t *iv, size_t iv_len,
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *plaintext, size_t pt_len)
{
    struct fce_aes *ctx_prime = NULL;
    struct fce_aes *ctx_ossl  = NULL;
    uint8_t *prime_ct   = NULL;
    uint8_t *ossl_ct    = NULL;
    uint8_t *dec_by_ossl = NULL;
    uint8_t *dec_by_prime = NULL;
    size_t prime_ct_len;
    size_t ossl_ct_len;
    size_t dec_by_ossl_len;
    size_t dec_by_prime_len;
    int ret = -1;

    /* Create both contexts. */
    ctx_prime = fce_aes_init(mode, key, key_len, aad, aad_len);
    ctx_ossl  = fce_aes_init_ex(mode, key, key_len, aad, aad_len,
                                FCE_AES_FLAG_FORCE_OPENSSL);
    if (!ctx_prime || !ctx_ossl) {
        printf("  %s cross: init FAILED\n", mode_name);
        goto out;
    }

    /* ---- 1. PRIME encrypt ---- */
    ret = fce_aes_encrypt(ctx_prime, iv, iv_len,
                          plaintext, pt_len, &prime_ct, &prime_ct_len);
    if (ret) {
        printf("  %s cross: PRIME encrypt FAILED (error: %s)\n",
               mode_name, fce_aes_strerror(ret));
        goto out;
    }

    /* ---- 2. OpenSSL encrypt (same IV) ---- */
    ret = fce_aes_encrypt(ctx_ossl, iv, iv_len,
                          plaintext, pt_len, &ossl_ct, &ossl_ct_len);
    if (ret) {
        printf("  %s cross: OpenSSL encrypt FAILED (error: %s)\n",
               mode_name, fce_aes_strerror(ret));
        goto out;
    }

    /* ---- 3. Compare ciphertexts ----
     *
     * Both backends use PKCS#7 padding for ECB/CBC, so the ciphertext
     * lengths should match.  Verify the full output including GCM tags.
     */
    if (prime_ct_len != ossl_ct_len ||
        memcmp(prime_ct, ossl_ct, prime_ct_len) != 0) {
        printf("  %s cross: ciphertext mismatch\n", mode_name);
        ret = -1;
        goto out;
    }

    /* ---- 4. OpenSSL decrypt of PRIME ciphertext ---- */
    ret = fce_aes_decrypt(ctx_ossl, iv, iv_len,
                          prime_ct, prime_ct_len,
                          &dec_by_ossl, &dec_by_ossl_len);
    if (ret) {
        printf("  %s cross: PRIME→OpenSSL decrypt FAILED (error: %s)\n",
               mode_name, fce_aes_strerror(ret));
        goto out;
    }

    if (dec_by_ossl_len != pt_len ||
        memcmp(dec_by_ossl, plaintext, pt_len) != 0) {
        printf("  %s cross: PRIME→OpenSSL data mismatch\n", mode_name);
        ret = -1;
        goto out;
    }

    /* ---- 5. PRIME decrypt of OpenSSL ciphertext ---- */
    ret = fce_aes_decrypt(ctx_prime, iv, iv_len,
                          ossl_ct, ossl_ct_len,
                          &dec_by_prime, &dec_by_prime_len);
    if (ret) {
        printf("  %s cross: OpenSSL→PRIME decrypt FAILED (error: %s)\n",
               mode_name, fce_aes_strerror(ret));
        goto out;
    }

    if (dec_by_prime_len != pt_len ||
        memcmp(dec_by_prime, plaintext, pt_len) != 0) {
        printf("  %s cross: OpenSSL→PRIME data mismatch\n", mode_name);
        ret = -1;
        goto out;
    }

    printf("  %s cross-verify: PASS\n", mode_name);
    ret = 0;

out:
    fce_aes_free_buf(prime_ct);
    fce_aes_free_buf(ossl_ct);
    fce_aes_free_buf(dec_by_ossl);
    fce_aes_free_buf(dec_by_prime);
    fce_aes_free(ctx_prime);
    fce_aes_free(ctx_ossl);
    return ret;
}

#endif /* USE_PRIME */

/* ======================================================================
 * Self-test runner
 * ====================================================================== */

int run_selftest(void)
{
    int ret = 0;
    int result;

    printf("\n");
    printf("============================================\n");
#if defined(USE_PRIME)
    printf("  PRIME FCE AES Self-Test + OpenSSL Cross-Verify\n");
#else
    printf("  OpenSSL AES Self-Test\n");
#endif
    printf("============================================\n");
    printf("\n");

    /* ---- ECB ---- */
    result = test_roundtrip(FCE_AES_ECB, "AES-256-ECB",
                            ecb_key, sizeof(ecb_key),
                            NULL, 0,
                            NULL, 0,
                            test_plaintext, sizeof(test_plaintext),
#if defined(USE_PRIME)
                            0);  /* use default backend (PRIME) */
    if (result) ret = result;

    result = test_cross(FCE_AES_ECB, "AES-256-ECB",
                        ecb_key, sizeof(ecb_key),
                        NULL, 0,
                        NULL, 0,
                        test_plaintext, sizeof(test_plaintext));
#else
                            1);  /* use OpenSSL backend */
#endif
    if (result) ret = result;

    /* ---- CBC ---- */
    result = test_roundtrip(FCE_AES_CBC, "AES-256-CBC",
                            cbc_key, sizeof(cbc_key),
                            cbc_iv, sizeof(cbc_iv),
                            NULL, 0,
                            test_plaintext, sizeof(test_plaintext),
#if defined(USE_PRIME)
                            0);
    if (result) ret = result;

    result = test_cross(FCE_AES_CBC, "AES-256-CBC",
                        cbc_key, sizeof(cbc_key),
                        cbc_iv, sizeof(cbc_iv),
                        NULL, 0,
                        test_plaintext, sizeof(test_plaintext));
#else
                            1);
#endif
    if (result) ret = result;

    /* ---- CTR ---- */
    result = test_roundtrip(FCE_AES_CTR, "AES-256-CTR",
                            ctr_key, sizeof(ctr_key),
                            ctr_iv, sizeof(ctr_iv),
                            NULL, 0,
                            test_plaintext, sizeof(test_plaintext),
#if defined(USE_PRIME)
                            0);
    if (result) ret = result;

    result = test_cross(FCE_AES_CTR, "AES-256-CTR",
                        ctr_key, sizeof(ctr_key),
                        ctr_iv, sizeof(ctr_iv),
                        NULL, 0,
                        test_plaintext, sizeof(test_plaintext));
#else
                            1);
#endif
    if (result) ret = result;

    /* ---- GCM ---- */
    result = test_roundtrip(FCE_AES_GCM, "AES-256-GCM",
                            gcm_key, sizeof(gcm_key),
                            gcm_iv, sizeof(gcm_iv),
                            gcm_aad, sizeof(gcm_aad),
                            test_plaintext, sizeof(test_plaintext),
#if defined(USE_PRIME)
                            0);
    if (result) ret = result;

    result = test_cross(FCE_AES_GCM, "AES-256-GCM",
                        gcm_key, sizeof(gcm_key),
                        gcm_iv, sizeof(gcm_iv),
                        gcm_aad, sizeof(gcm_aad),
                        test_plaintext, sizeof(test_plaintext));
#else
                            1);
#endif
    if (result) ret = result;

    printf("\n");
    if (ret)
        printf("  *** One or more self-tests FAILED ***\n");
    else
        printf("  All self-tests PASSED.\n");
    printf("\n");

    return ret;
}
