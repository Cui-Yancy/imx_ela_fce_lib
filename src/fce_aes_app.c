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
    uint8_t *aad_buf     = NULL;
    uint8_t *input_buf   = NULL;
    uint8_t *output_buf  = NULL;
    uint8_t *crypto_input = NULL;   /* pointer to data actually fed to crypto */
    size_t   crypto_len   = 0;      /* length of crypto_input */
    uint8_t gcm_tag[FCE_AES_GCM_TAG_SIZE];
    /* Fixed AAD for GCM mode (firmware requires non-zero-length AAD). */
    static const uint8_t default_aad[16] = {
        0x8c, 0xbc, 0xf1, 0x56, 0xf0, 0xa2, 0x30, 0x1d,
        0x83, 0xee, 0x04, 0x16, 0xd9, 0xb7, 0xbb, 0x2f,
    };
    size_t key_len   = 0;
    size_t iv_len    = 0;
    size_t aad_len   = 0;
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

    /* ---- Load IV (if required by mode) ----
     *
     * Encryption: IV is mandatory (ECB excluded).
     * Decryption: IV is optional — if not provided here it will be
     *             extracted from the input file below.
     */
    if (cli.mode != FCE_AES_ECB) {
        size_t expected_iv_max = FCE_AES_MAX_IV_SIZE;

        if (cli.iv_src) {
            ret = load_key_or_iv(cli.iv_src, cli.iv_is_file,
                                 &iv_buf, &iv_len,
                                 0, expected_iv_max);
            if (ret) {
                fprintf(stderr, "Error: Failed to load IV from '%s': %s\n",
                        cli.iv_src, aes_strerror(ret));
                goto out;
            }

            /* Warn if IV length doesn't match typical expectations. */
            if (cli.mode == FCE_AES_CBC && iv_len != 16)
                fprintf(stderr, "Warning: CBC typically uses a 16-byte IV "
                        "(got %zu bytes).\n", iv_len);
            else if ((cli.mode == FCE_AES_CTR || cli.mode == FCE_AES_GCM) &&
                     iv_len != 12)
                fprintf(stderr, "Warning: %s typically uses a 12-byte IV/nonce "
                        "(got %zu bytes).\n",
                        cli.mode == FCE_AES_CTR ? "CTR" : "GCM", iv_len);
        } else if (cli.dir == FCE_AES_ENCRYPT) {
            fprintf(stderr, "Error: An IV / nonce is required for %s mode "
                    "(encrypt). Use -v <hex> or -V <file>.\n",
                    cli.mode == FCE_AES_CBC ? "CBC" :
                    cli.mode == FCE_AES_CTR ? "CTR" : "GCM");
            ret = 1;
            goto out;
        }
        /* For decrypt without CLI IV: the IV will be extracted from
         * the input file once it has been read (see below). */
    }

    /* ---- Load AAD (GCM only) ---- */
    if (cli.mode == FCE_AES_GCM && cli.aad_src) {
        ret = load_key_or_iv(cli.aad_src, cli.aad_is_file,
                             &aad_buf, &aad_len,
                             0, 0);  /* any length accepted */
        if (ret) {
            fprintf(stderr, "Error: Failed to load AAD from '%s': %s\n",
                    cli.aad_src, aes_strerror(ret));
            goto out;
        }
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
     * the input file is expected to use the following layout
     * (matching what the encrypt path produces):
     *
     *   ECB:   [ciphertext]
     *   CBC:   [16-byte IV][ciphertext]
     *   CTR:   [12-byte IV][ciphertext]
     *   GCM:   [12-byte IV][ciphertext][16-byte tag]
     *
     * We extract the IV and (for GCM) the authentication tag, then
     * set crypto_input / crypto_len to point at the raw ciphertext.
     */
    if (cli.dir == FCE_AES_DECRYPT && cli.mode != FCE_AES_ECB && !iv_buf) {
        size_t iv_file_len;
        size_t tag_file_len = (cli.mode == FCE_AES_GCM)
                                ? FCE_AES_GCM_TAG_SIZE : 0;

        switch (cli.mode) {
        case FCE_AES_CBC: iv_file_len = 16; break;
        case FCE_AES_CTR:
        case FCE_AES_GCM: iv_file_len = 12; break;
        default:          iv_file_len = 0;  break;
        }

        /* Validate total file size accounts for IV and tag overhead. */
        if (input_len <= iv_file_len + tag_file_len) {
            fprintf(stderr, "Error: Input file too short (%zu bytes) "
                    "to contain embedded %s layout "
                    "(%zu-byte IV + %zu-byte tag minimum).\n",
                    input_len,
                    cli.mode == FCE_AES_CBC ? "CBC" :
                    cli.mode == FCE_AES_CTR ? "CTR" : "GCM",
                    iv_file_len, tag_file_len);
            ret = 1;
            goto out;
        }

        /* Allocate and copy IV from the file header. */
        iv_buf = (uint8_t *)malloc(iv_file_len);
        if (!iv_buf) {
            ret = 1;
            goto out;
        }
        memcpy(iv_buf, input_buf, iv_file_len);
        iv_len = iv_file_len;

        /* Point crypto input past the embedded IV. */
        crypto_input = input_buf + iv_file_len;
        crypto_len   = input_len - iv_file_len - tag_file_len;

        /* For GCM, extract the authentication tag from the end. */
        if (tag_file_len)
            memcpy(gcm_tag, input_buf + input_len - tag_file_len,
                   tag_file_len);

        printf("Extracted %zu-byte IV", iv_file_len);
        if (tag_file_len)
            printf(" and %zu-byte authentication tag", tag_file_len);
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
    params.aad       = (cli.mode == FCE_AES_GCM)
                            ? (aad_buf ? aad_buf : default_aad)
                            : NULL;
    params.aad_len   = (cli.mode == FCE_AES_GCM)
                            ? (aad_buf ? aad_len : sizeof(default_aad))
                            : 0;
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
     * Encrypt (non-ECB): write in [IV][ciphertext][tag] format so the
     *                      IV (and GCM tag) travel with the ciphertext.
     * Decrypt / ECB:      write the plaintext / ciphertext only.
     */
    size_t iv_out_len = 0;
    size_t tag_out_len = 0;

    if (cli.dir == FCE_AES_ENCRYPT && cli.mode != FCE_AES_ECB) {
        /* Determine the IV and tag sizes for the file layout. */
        switch (cli.mode) {
        case FCE_AES_CBC: iv_out_len = 16; break;
        case FCE_AES_CTR:
        case FCE_AES_GCM: iv_out_len = 12; break;
        default:          iv_out_len = 0;  break;
        }
        if (cli.mode == FCE_AES_GCM)
            tag_out_len = FCE_AES_GCM_TAG_SIZE;

        /* Build the composite output buffer. */
        size_t  file_len = iv_out_len + crypto_len + tag_out_len;
        uint8_t *file_buf = (uint8_t *)malloc(file_len);
        if (!file_buf) {
            fprintf(stderr, "Error: Out of memory.\n");
            ret = 1;
            goto out;
        }

        if (iv_out_len > 0)
            memcpy(file_buf, iv_buf, iv_out_len);
        memcpy(file_buf + iv_out_len, output_buf, crypto_len);
        if (tag_out_len > 0)
            memcpy(file_buf + iv_out_len + crypto_len, gcm_tag,
                   tag_out_len);

        ret = write_binary_file(cli.output_path, file_buf, file_len);
        free(file_buf);
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
               crypto_len + iv_out_len + tag_out_len, cli.output_path);

    /* ---- For GCM, display the authentication tag ---- */
    if (cli.mode == FCE_AES_GCM) {
        printf("GCM authentication tag: ");
        for (size_t i = 0; i < FCE_AES_GCM_TAG_SIZE; i++)
            printf("%02x", gcm_tag[i]);
        if (cli.dir == FCE_AES_ENCRYPT)
            printf(" (embedded in output file)\n");
        else
            printf(" (extracted from input file)\n");
    }

out:
    free(key_buf);
    free(iv_buf);
    free(aad_buf);
    free(input_buf);
    free(output_buf);
    return ret ? 1 : 0;
}
