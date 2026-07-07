// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 *
 * fce_aes_app.c — i.MX943 PRIME FCE AES Application Entry Point.
 *
 * Usage:
 *   fce_aes_app              — run built-in self-test
 *   fce_aes_app [options]    — encrypt / decrypt with user-supplied data
 *
 * Build variants:
 *   make USE_PRIME=1   — full build with NXP PRIME hardware backend (default)
 *   make USE_PRIME=0   — portable build using OpenSSL only
 *
 * See the help text (-h) for full option descriptions.
 */

#include "fce_aes.h"
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
    struct fce_aes *ctx = NULL;
    uint8_t *key_buf         = NULL;
    size_t   key_len         = 0;
    uint8_t *iv_buf          = NULL;
    uint8_t *input_buf       = NULL;
    uint8_t *ct_buf          = NULL;    /* encrypt output (ciphertext + tag) */
    uint8_t *pt_buf          = NULL;    /* decrypt output (plaintext) */
    uint8_t *file_buf        = NULL;    /* final wire-format output */
    const uint8_t *crypto_input = NULL; /* pointer into input_buf for decrypt */
    size_t   crypto_len        = 0;
    size_t   file_len          = 0;
    size_t   iv_len            = 0;
    size_t   ct_len            = 0;     /* encrypt output length */
    size_t   pt_len            = 0;     /* decrypt output length */
    int ret;

    /* Fixed AAD for GCM mode (firmware requires non-zero-length AAD). */
    static const uint8_t default_aad[16] = "NXP-iMX9-AES-GCM";

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
                cli.key_src, fce_aes_strerror(ret));
        return 1;
    }

    if (key_len != 16 && key_len != 24 && key_len != 32) {
        fprintf(stderr, "Error: Invalid key length (%zu bytes). "
                "AES key must be 16, 24, or 32 bytes.\n", key_len);
        ret = 1;
        goto out;
    }

    /* ---- Generate or extract IV ---- */

    if (cli.dir == FCE_AES_ENCRYPT && cli.mode != FCE_AES_ECB) {
        /* Encrypt: generate a fresh random IV from /dev/urandom. */
        ret = format_generate_iv(cli.mode, &iv_buf, &iv_len);
        if (ret) {
            fprintf(stderr, "Error: Failed to generate random IV: %s\n",
                    fce_aes_strerror(ret));
            goto out;
        }
        if (!cli.quiet)
            format_print_iv(iv_buf, iv_len);
    }

    /* ---- Read input file ---- */
    {
        size_t input_len = 0;
        ret = read_binary_file(cli.input_path, &input_buf, &input_len);
        if (ret) {
            fprintf(stderr, "Error: Cannot read input file '%s': %s\n",
                    cli.input_path, fce_aes_strerror(ret));
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

        /* For decrypt (non-ECB): extract embedded IV from the file header. */
        if (cli.dir == FCE_AES_DECRYPT && cli.mode != FCE_AES_ECB && !iv_buf) {
            iv_len = format_get_iv_length(cli.mode);

            if (input_len <= iv_len) {
                fprintf(stderr, "Error: Input file too short (%zu bytes) "
                        "to contain %zu-byte IV.\n", input_len, iv_len);
                ret = 1;
                goto out;
            }

            /* Copy IV out of the input buffer (it will be freed). */
            iv_buf = (uint8_t *)malloc(iv_len);
            if (!iv_buf) {
                ret = 1;
                goto out;
            }
            memcpy(iv_buf, input_buf, iv_len);

            crypto_input = input_buf + iv_len;
            crypto_len   = input_len - iv_len;

            if (!cli.quiet)
                printf("Extracted %zu-byte IV from input file.\n", iv_len);
        } else {
            /* Encrypt path, ECB decrypt, or user-provided IV: use raw data. */
            crypto_input = input_buf;
            crypto_len   = input_len;
        }
    }

    /* ---- Create AES context ---- */
    {
        const uint8_t *aad     = (cli.mode == FCE_AES_GCM) ? default_aad : NULL;
        size_t         aad_len = (cli.mode == FCE_AES_GCM) ? sizeof(default_aad) : 0;

        if (cli.use_openssl)
            ctx = fce_aes_init_ex(cli.mode, key_buf, key_len,
                                  aad, aad_len, FCE_AES_FLAG_FORCE_OPENSSL);
        else
            ctx = fce_aes_init(cli.mode, key_buf, key_len,
                               aad, aad_len);

        if (!ctx) {
            fprintf(stderr, "Error: Failed to initialize AES context.\n");
            ret = 1;
            goto out;
        }

        if (!cli.quiet && cli.use_openssl)
            printf("Using OpenSSL software crypto backend.\n");
    }

    /* ---- Execute crypto operation ---- */
    if (cli.dir == FCE_AES_ENCRYPT) {
        ret = fce_aes_encrypt(ctx, iv_buf, iv_len,
                              crypto_input, crypto_len,
                              &ct_buf, &ct_len);
        if (ret) {
            fprintf(stderr, "Error: AES encryption failed: %s\n",
                    fce_aes_strerror(ret));
            goto out;
        }
    } else {
        ret = fce_aes_decrypt(ctx, iv_buf, iv_len,
                              crypto_input, crypto_len,
                              &pt_buf, &pt_len);
        if (ret) {
            fprintf(stderr, "Error: AES decryption failed: %s\n",
                    fce_aes_strerror(ret));
            goto out;
        }
    }

    /* ---- Write output ---- */

    if (cli.dir == FCE_AES_ENCRYPT && cli.mode != FCE_AES_ECB) {
        /*
         * Build wire format: [IV][ciphertext][+GCM tag].
         *
         * fce_aes_encrypt() returns just ciphertext (+ tag for GCM).
         * Prepend the IV so the output is self-describing.
         */
        file_len = iv_len + ct_len;
        file_buf = (uint8_t *)malloc(file_len);
        if (!file_buf) {
            ret = 1;
            goto out;
        }
        memcpy(file_buf, iv_buf, iv_len);
        memcpy(file_buf + iv_len, ct_buf, ct_len);

        ret = write_binary_file(cli.output_path, file_buf, file_len);
        free(file_buf);
        file_buf = NULL;
    } else {
        /* ECB encrypt or any decrypt: output is raw ciphertext / plaintext. */
        const uint8_t *data;
        size_t         data_len;

        if (cli.dir == FCE_AES_ENCRYPT) {
            data     = ct_buf;
            data_len = ct_len;
        } else {
            data     = pt_buf;
            data_len = pt_len;
        }

        ret = write_binary_file(cli.output_path, data, data_len);
    }

    if (ret) {
        fprintf(stderr, "Error: Failed to write output: %s\n",
                fce_aes_strerror(ret));
        goto out;
    }

    if (!cli.quiet && cli.output_path)
        printf("Wrote %zu bytes to '%s'.\n",
               file_len ? file_len : (ct_len ? ct_len : pt_len),
               cli.output_path);

    /* ---- For GCM encrypt, display the authentication tag ---- */
    if (!cli.quiet && cli.mode == FCE_AES_GCM) {
        /* Tag is the last FCE_AES_GCM_TAG_SIZE bytes of the encrypt output. */
        if (cli.dir == FCE_AES_ENCRYPT && ct_buf && ct_len >= FCE_AES_GCM_TAG_SIZE) {
            uint8_t *gcm_tag = ct_buf + ct_len - FCE_AES_GCM_TAG_SIZE;
            format_print_tag(gcm_tag, FCE_AES_GCM_TAG_SIZE, 1);
        }
    }

out:
    fce_aes_free_buf(key_buf);
    fce_aes_free_buf(iv_buf);
    fce_aes_free_buf(input_buf);
    fce_aes_free_buf(ct_buf);
    fce_aes_free_buf(pt_buf);
    fce_aes_free(ctx);
    return ret ? 1 : 0;
}
