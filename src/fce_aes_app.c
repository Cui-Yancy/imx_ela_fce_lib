// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 *
 * fce_aes_app.c — i.MX943 FCE AES PRIME Application Entry Point.
 *
 * Usage:
 *   fce_aes_app              — run built-in self-test
 *   fce_aes_app [options]    — encrypt / decrypt with user-supplied data
 *
 * See the help text (-h) for full option descriptions.
 */

#include "fce_aes_api.h"
#include "fce_aes_cli.h"
#include "fce_aes_format.h"
#include "fce_aes_io.h"
#include "fce_aes_selftest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    struct fce_aes_cli_args cli;
    struct aes_params params;
    uint8_t *key_buf     = NULL;
    uint8_t *iv_buf      = NULL;
    uint8_t *input_buf   = NULL;
    uint8_t *output_buf  = NULL;
    uint8_t *file_buf    = NULL;
    const uint8_t *crypto_input = NULL;
    size_t   crypto_len   = 0;
    size_t   file_len     = 0;
    uint8_t gcm_tag[FCE_AES_GCM_TAG_SIZE] = {0};
    /* Fixed AAD for GCM mode (firmware requires non-zero-length AAD). */
    static const uint8_t default_aad[16] = "NXP-iMX9-AES-GCM";
    size_t key_len   = 0;
    size_t iv_len    = 0;
    size_t input_len = 0;
    int ret;

    /* ---- No arguments → run self-test ---- */
    if (argc < 2)
        return run_selftest();

    /* ---- Parse CLI arguments ---- */
    ret = parse_cli_args(argc, argv, &cli);
    if (ret)
        return 1;

    /* ---- Load key ---- */
    ret = load_key_or_iv(cli.key_src, cli.key_is_file,
                         &key_buf, &key_len,
                         16, 32);  /* AES key: 16–32 bytes */
    if (ret) {
        fprintf(stderr, "Error: Failed to load key from '%s': %s\n",
                cli.key_src, aes_strerror(ret));
        return 1;
    }

    /* Validate key length is exactly 16, 24, or 32. */
    if (key_len != 16 && key_len != 24 && key_len != 32) {
        fprintf(stderr, "Error: Invalid key length (%zu bytes). "
                "AES key must be 16, 24, or 32 bytes.\n", key_len);
        ret = 1;
        goto out;
    }

    /* ---- Generate IV (encrypt, non-ECB) ----
     *
     * For non-ECB modes during encryption, a random IV is automatically
     * generated from /dev/urandom.  During decryption the IV is extracted
     * from the input file below.
     */
    if (cli.dir == FCE_AES_ENCRYPT && cli.mode != FCE_AES_ECB) {
        ret = format_generate_iv(cli.mode, &iv_buf, &iv_len);
        if (ret) {
            fprintf(stderr, "Error: Failed to generate random IV: %s\n",
                    aes_strerror(ret));
            goto out;
        }
        format_print_iv(iv_buf, iv_len);
    }

    /* ---- Read input file ---- */
    ret = read_binary_file(cli.input_path, &input_buf, &input_len);
    if (ret) {
        fprintf(stderr, "Error: Cannot read input file '%s': %s\n",
                cli.input_path, aes_strerror(ret));
        goto out;
    }

    if (input_len == 0) {
        fprintf(stderr, "Error: Input file is empty.\n");
        ret = 1;
        goto out;
    }

    if (input_len > FCE_AES_MAX_DATA_SIZE) {
        fprintf(stderr, "Error: Input too large (%zu bytes). "
                "Maximum is %lu bytes.\n", input_len, FCE_AES_MAX_DATA_SIZE);
        ret = 1;
        goto out;
    }

    /* ---- Parse embedded IV/tag for decrypt without CLI IV ----
     *
     * When decrypting and no IV was provided on the command line,
     * the input file uses the layout produced by the encrypt path:
     *
     *   ECB:   [ciphertext]
     *   CBC:   [16-byte IV][ciphertext]
     *   CTR:   [12-byte IV][ciphertext]
     *   GCM:   [12-byte IV][ciphertext][16-byte tag]
     */
    if (cli.dir == FCE_AES_DECRYPT && cli.mode != FCE_AES_ECB && !iv_buf) {
        const uint8_t *iv_ptr  = NULL;
        const uint8_t *tag_ptr = NULL;

        ret = format_parse_decrypt_input(cli.mode,
                                         input_buf, input_len,
                                         &iv_ptr, &iv_len,
                                         &tag_ptr,
                                         &crypto_input, &crypto_len);
        if (ret) {
            fprintf(stderr, "Error: Input file too short (%zu bytes) "
                    "to contain embedded layout.\n", input_len);
            ret = 1;
            goto out;
        }

        /* Copy IV out of the input buffer (it will be freed). */
        iv_buf = (uint8_t *)malloc(iv_len);
        if (!iv_buf) {
            ret = 1;
            goto out;
        }
        memcpy(iv_buf, iv_ptr, iv_len);

        /* Copy GCM tag if present. */
        if (tag_ptr)
            memcpy(gcm_tag, tag_ptr, FCE_AES_GCM_TAG_SIZE);

        printf("Extracted %zu-byte IV", iv_len);
        if (tag_ptr)
            printf(" and %zu-byte authentication tag",
                   (size_t)FCE_AES_GCM_TAG_SIZE);
        printf(" from input file.\n");
    }

    /* Set crypto_input / crypto_len for all other cases (encrypt,
     * decrypt with CLI IV, or ECB) — just use the raw file data. */
    if (!crypto_input) {
        crypto_input = input_buf;
        crypto_len   = input_len;
    }

    /* ---- Allocate output buffer ---- */
    output_buf = (uint8_t *)malloc(crypto_len + FCE_AES_GCM_TAG_SIZE);
    if (!output_buf) {
        fprintf(stderr, "Error: Out of memory.\n");
        ret = 1;
        goto out;
    }

    /* ---- Prepare operation parameters ---- */
    memset(&params, 0, sizeof(params));
    params.dir       = cli.dir;
    params.mode      = cli.mode;
    params.key       = key_buf;
    params.key_len   = key_len;
    params.iv        = iv_buf;
    params.iv_len    = iv_len;
    params.aad       = (cli.mode == FCE_AES_GCM) ? default_aad : NULL;
    params.aad_len   = (cli.mode == FCE_AES_GCM) ? sizeof(default_aad) : 0;
    params.input     = crypto_input;
    params.input_len = crypto_len;
    params.output    = output_buf;
    params.output_len = crypto_len + FCE_AES_GCM_TAG_SIZE;
    params.tag       = gcm_tag;
    params.tag_len   = sizeof(gcm_tag);

    /* ---- Execute ---- */
    ret = aes_operation(&params);
    if (ret) {
        fprintf(stderr, "Error: AES operation failed: %s\n",
                aes_strerror(ret));
        goto out;
    }

    /* ---- Write output ----
     *
     * Encrypt (non-ECB): assemble [IV][ciphertext][tag] so that the
     *                      IV and GCM tag travel with the ciphertext.
     * Decrypt / ECB:      write the plaintext / ciphertext only.
     */
    if (cli.dir == FCE_AES_ENCRYPT && cli.mode != FCE_AES_ECB) {
        const uint8_t *tag_ptr = (cli.mode == FCE_AES_GCM) ? gcm_tag : NULL;

        ret = format_build_encrypt_output(cli.mode,
                                          iv_buf, iv_len,
                                          output_buf, crypto_len,
                                          tag_ptr,
                                          &file_buf, &file_len);
        if (ret) {
            fprintf(stderr, "Error: Failed to build output layout: %s\n",
                    aes_strerror(ret));
            goto out;
        }

        ret = write_binary_file(cli.output_path, file_buf, file_len);
        free(file_buf);
        file_buf = NULL;
    } else {
        ret = write_binary_file(cli.output_path, output_buf, crypto_len);
    }

    if (ret) {
        fprintf(stderr, "Error: Failed to write output: %s\n",
                aes_strerror(ret));
        goto out;
    }

    if (cli.output_path)
        printf("Wrote %zu bytes to '%s'.\n",
               file_len ? file_len : crypto_len, cli.output_path);

    /* ---- For GCM, display the authentication tag ---- */
    if (cli.mode == FCE_AES_GCM)
        format_print_tag(gcm_tag, FCE_AES_GCM_TAG_SIZE,
                         cli.dir == FCE_AES_ENCRYPT);

out:
    free(key_buf);
    free(iv_buf);
    free(input_buf);
    free(output_buf);
    return ret ? 1 : 0;
}
