// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 *
 * fce_aes_selftest.h — Self-test for the FCE AES application.
 *
 * Runs known-answer tests for all four supported AES modes (ECB, CBC, CTR,
 * GCM) using AES-256.  Each test performs an encrypt / decrypt round-trip
 * and verifies the result, plus a cross-verify that compares the PRIME
 * hardware backend against the OpenSSL software backend (cross-decrypt,
 * ciphertext comparison, and GCM tag comparison).
 */

#ifndef FCE_AES_SELFTEST_H
#define FCE_AES_SELFTEST_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * run_selftest — Execute built-in self-tests for all AES modes.
 *
 * Each mode test:
 *   1. Encrypts a known plaintext with a known key (and IV/AAD where
 *      required).
 *   2. Decrypts the resulting ciphertext.
 *   3. Verifies that the decrypted text matches the original plaintext.
 *   4. For GCM, also verifies that the authentication tag is non-zero
 *      and that decryption with the correct tag succeeds.
 *   5. Cross-verifies that the PRIME and OpenSSL backends produce
 *      identical results (ciphertext comparison, cross-decrypt, and
 *      GCM tag comparison).
 *
 * @return 0 if all tests pass, or a negative errno value if any fail.
 */
int run_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* FCE_AES_SELFTEST_H */
