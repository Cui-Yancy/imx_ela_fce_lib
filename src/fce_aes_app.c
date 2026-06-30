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
    uint8_t *input_buf   = NULL;
    uint8_t *output_buf  = NULL;
    uint8_t gcm_tag[FCE_AES_GCM_TAG_SIZE];
    /* Fixed AAD for GCM mode (firmware requires non-zero-length AAD). */
    static const uint8_t default_aad[16] = {
        0x8c, 0xbc, 0xf1, 0x56, 0xf0, 0xa2, 0x30, 0x1d,
        0x83, 0xee, 0x04, 0x16, 0xd9, 0xb7, 0xbb, 0x2f,
    };
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

    /* ---- Load IV (if required by mode) ---- */
    if (cli.mode != FCE_AES_ECB) {
        size_t expected_iv_max = FCE_AES_MAX_IV_SIZE;

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

    /* ---- Allocate output buffer ---- */
    output_buf = (uint8_t *)malloc(input_len + FCE_AES_GCM_TAG_SIZE);
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
    params.input     = input_buf;
    params.input_len = input_len;
    params.output    = output_buf;
    params.output_len = input_len + FCE_AES_GCM_TAG_SIZE;
    params.tag       = gcm_tag;
    params.tag_len   = sizeof(gcm_tag);

    /* ---- Execute ---- */
    ret = aes_operation(&params);
    if (ret) {
        fprintf(stderr, "Error: AES operation failed: %s\n",
                aes_strerror(ret));
        goto out;
    }

    /* ---- Write output ---- */
    ret = write_binary_file(cli.output_path, output_buf, input_len);
    if (ret) {
        fprintf(stderr, "Error: Failed to write output: %s\n",
                aes_strerror(ret));
        goto out;
    }

    if (cli.output_path)
        printf("Wrote %zu bytes to '%s'.\n", input_len, cli.output_path);

    /* ---- For GCM, display the authentication tag ---- */
    if (cli.mode == FCE_AES_GCM) {
        printf("GCM authentication tag: ");
        for (size_t i = 0; i < FCE_AES_GCM_TAG_SIZE; i++)
            printf("%02x", gcm_tag[i]);
        printf("\n");
    }

out:
    free(key_buf);
    free(iv_buf);
    free(input_buf);
    free(output_buf);
    return ret ? 1 : 0;
}
