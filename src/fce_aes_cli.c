// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 *
 * fce_aes_cli.c — Command-line argument parsing.
 *
 * Uses POSIX getopt() to handle the following options:
 *   -e, -d, -m, -i, -o, -k, -K, -h
 */

#include "fce_aes_cli.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ======================================================================
 * Mode-name lookup
 * ====================================================================== */

/**
 * str_to_mode — Case-insensitive mapping from a mode string to the
 *               corresponding fce_aes_mode enum.
 *
 * @return The mode on success; -1 if the string is unknown.
 */
static int str_to_mode(const char *s)
{
    size_t i;
    char upper[8];

    /* Convert to upper case for comparison. */
    for (i = 0; i < sizeof(upper) - 1 && s[i]; i++)
        upper[i] = (char)toupper((unsigned char)s[i]);
    upper[i] = '\0';

    if (strcmp(upper, "ECB") == 0) return FCE_AES_ECB;
    if (strcmp(upper, "CBC") == 0) return FCE_AES_CBC;
    if (strcmp(upper, "CTR") == 0) return FCE_AES_CTR;
    if (strcmp(upper, "GCM") == 0) return FCE_AES_GCM;

    return -1;
}

/* ======================================================================
 * Usage
 * ====================================================================== */

void print_usage(const char *prog)
{
    printf("\n");
    printf("Usage: %s [options]\n", prog);
    printf("\n");
    printf("Encrypt or decrypt data using the i.MX943 PRIME AES hardware engine.\n");
    printf("\n");
    printf("Operation:\n");
    printf("  -e              Encrypt (default)\n");
    printf("  -d              Decrypt\n");
    printf("\n");
    printf("AES mode:\n");
    printf("  -m <mode>       Cipher mode: ECB, CBC, CTR, GCM  (default: CBC)\n");
    printf("\n");
    printf("Input / Output:\n");
    printf("  -i <file>       Input data file (binary)\n");
    printf("  -o <file>       Output data file (binary; default: stdout)\n");
    printf("\n");
    printf("Key (choose one):\n");
    printf("  -k <hex>        AES key as a hex string (32/48/64 hex chars)\n");
    printf("  -K <file>       AES key from a binary file (16/24/32 bytes)\n");
    printf("\n");
    printf("IV / nonce:\n");
    printf("  (auto-generated from /dev/urandom for CBC/CTR/GCM;\n");
    printf("   embedded in output file and extracted on decrypt)\n");
    printf("AAD (GCM only):\n");
    printf("  (built-in default used automatically)\n");
    printf("\n");
    printf("Other:\n");
    printf("  -h              Show this help message and exit\n");
    printf("\n");
    printf("If no arguments are given the application runs a built-in\n");
    printf("self-test using known-answer test vectors for all four modes.\n");
    printf("\n");
}

/* ======================================================================
 * Argument parsing
 * ====================================================================== */

int parse_cli_args(int argc, char *argv[], struct fce_aes_cli_args *args)
{
    int opt;
    int mode_val;
    int has_e = 0, has_d = 0;
    int has_k = 0, has_K = 0;

    if (!args)
        return -EINVAL;

    /* Set defaults. */
    memset(args, 0, sizeof(*args));
    args->mode = FCE_AES_CBC;
    args->dir  = FCE_AES_ENCRYPT;

    /* getopt uses global optind / optarg / optopt. */
    opterr = 0;  /* we handle errors ourselves */

    while ((opt = getopt(argc, argv, "edm:i:o:k:K:h")) != -1) {
        switch (opt) {
        case 'e':
            has_e = 1;
            break;
        case 'd':
            has_d = 1;
            break;
        case 'm':
            mode_val = str_to_mode(optarg);
            if (mode_val < 0) {
                fprintf(stderr, "Error: Unknown AES mode '%s'. "
                        "Valid modes: ECB, CBC, CTR, GCM.\n", optarg);
                return -EINVAL;
            }
            args->mode = (enum fce_aes_mode)mode_val;
            break;
        case 'i':
            args->input_path = optarg;
            break;
        case 'o':
            args->output_path = optarg;
            break;
        case 'k':
            has_k = 1;
            args->key_src     = optarg;
            args->key_is_file = 0;
            break;
        case 'K':
            has_K = 1;
            args->key_src     = optarg;
            args->key_is_file = 1;
            break;
        case 'h':
            print_usage(argv[0]);
            exit(0);
            /* not reached */
        case '?':
            if (optopt)
                fprintf(stderr, "Error: Unknown option '-%c' or "
                        "missing argument.\n", optopt);
            else
                fprintf(stderr, "Error: Unknown option '%s'.\n",
                        argv[optind - 1]);
            print_usage(argv[0]);
            return -EINVAL;
        default:
            fprintf(stderr, "Error: Internal parsing error (opt=%d).\n", opt);
            return -EINVAL;
        }
    }

    /* ---- consistency checks ---- */

    /* Cannot encrypt and decrypt at the same time. */
    if (has_e && has_d) {
        fprintf(stderr, "Error: Options -e (encrypt) and -d (decrypt) "
                "are mutually exclusive.\n");
        return -EINVAL;
    }
    if (has_d)
        args->dir = FCE_AES_DECRYPT;
    /* else keep default (encrypt). */

    /* Key must be provided. */
    if (has_k && has_K) {
        fprintf(stderr, "Error: Options -k (hex key) and -K (key file) "
                "are mutually exclusive.\n");
        return -EINVAL;
    }
    if (!has_k && !has_K) {
        fprintf(stderr, "Error: An AES key is required. "
                "Use -k <hex> or -K <file>.\n");
        return -EINVAL;
    }

    /* IV is always auto-generated on encrypt or extracted from the
     * input file on decrypt (see fce_aes_app.c).  No CLI option. */

    /* Input file is required for normal (non-self-test) mode. */
    if (!args->input_path) {
        fprintf(stderr, "Error: Input file is required. Use -i <file>.\n");
        return -EINVAL;
    }

    return 0;
}
