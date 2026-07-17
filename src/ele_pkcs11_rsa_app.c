// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 *
 * ele_pkcs11_rsa_app.c — ELE PKCS#11 RSA CLI Tool (Sign / Verify).
 *
 * A command-line utility for RSA signing and signature verification using
 * the i.MX ELE hardware via the PKCS#11 interface.
 *
 * Usage:
 *   ele_pkcs11_rsa_app -S -i <input_file> -I <key_id_hex> [-o <output_file>]
 *                       [-M <module_path>] [-P <pin>] [-h] [-q]
 *
 *   ele_pkcs11_rsa_app -V -i <input_file> -s <sig_file> -I <key_id_hex>
 *                       [-M <module_path>] [-P <pin>] [-h] [-q]
 *
 * The key ID is specified as a hex string (e.g. -I 02 for key 0x02).
 * Sign mode (-S): produces a signature using SHA256-RSA-PKCS-PSS.
 * Verify mode (-V): verifies a signature against the input data.
 * One of -S or -V must be specified.
 *
 * Depends on:
 *   - fce_aes_io.h      for read_binary_file / write_binary_file / hexstr_to_bytes
 *   - ele_pkcs11_rsa.h  for the PKCS#11 RSA API
 */

#include "ele_pkcs11_rsa.h"
#include "fce_aes_io.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/* ======================================================================
 * Argument structure
 * ====================================================================== */

struct cli_args {
    const char *input_path;    /**< Input data file (-i). */
    const char *output_path;   /**< Output signature file (-o, sign mode). */
    const char *sig_path;      /**< Signature file for verify mode (-s). */
    const char *key_id_hex;    /**< Key ID as hex string (-I). */
    const char *module_path;   /**< PKCS#11 module path (-M). */
    const char *pin;           /**< User PIN (-P). */
    int         sign_mode;     /**< Sign mode flag (-S). */
    int         verify_mode;   /**< Verify mode flag (-V). */
    int         quiet;         /**< Quiet mode (-q). */
};

/* ======================================================================
 * Usage
 * ====================================================================== */

static void print_usage(const char *prog)
{
    printf("\n");
    printf("Usage: %s -S [options]\n", prog);
    printf("       %s -V [options]\n", prog);
    printf("\n");
    printf("RSA sign/verify using the i.MX ELE hardware via PKCS#11.\n");
    printf("Uses SHA256-RSA-PKCS-PSS (PSS with SHA-256, salt length 32).\n");
    printf("\n");
    printf("Sign mode (-S):\n");
    printf("  -S              Sign mode (produces a signature)\n");
    printf("  -i <file>       Input data file to sign (binary)\n");
    printf("  -I <hex>        Key ID as hex string (e.g. 02)\n");
    printf("  -o <file>       Output signature file (default: stdout)\n");
    printf("\n");
    printf("Verify mode (-V):\n");
    printf("  -V              Verify mode (verifies a signature)\n");
    printf("  -i <file>       Input data file (binary)\n");
    printf("  -I <hex>        Key ID as hex string (e.g. 02)\n");
    printf("  -s <file>       Signature file to verify\n");
    printf("\n");
    printf("Common options:\n");
    printf("  -M <path>       PKCS#11 module path\n");
    printf("                  (default: %s)\n", ELE_PKCS11_RSA_DEFAULT_MODULE);
    printf("  -P <pin>        User PIN for PKCS#11 login\n");
    printf("  -h              Show this help message and exit\n");
    printf("  -q              Quiet mode — suppress informational output\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -S -i data.bin -I 02 -o sig.bin\n", prog);
    printf("  %s -V -i data.bin -I 02 -s sig.bin\n", prog);
    printf("\n");
}

/* ======================================================================
 * Argument parsing
 * ====================================================================== */

static int parse_cli_args(int argc, char *argv[], struct cli_args *args)
{
    int opt;

    if (!args)
        return -1;

    memset(args, 0, sizeof(*args));

    while ((opt = getopt(argc, argv, "i:I:o:M:P:hqVs:S")) != -1) {
        switch (opt) {
        case 'i':
            args->input_path = optarg;
            break;
        case 'I':
            args->key_id_hex = optarg;
            break;
        case 'o':
            args->output_path = optarg;
            break;
        case 'M':
            args->module_path = optarg;
            break;
        case 'P':
            args->pin = optarg;
            break;
        case 'S':
            args->sign_mode = 1;
            break;
        case 'V':
            args->verify_mode = 1;
            break;
        case 's':
            args->sig_path = optarg;
            break;
        case 'h':
            print_usage(argv[0]);
            exit(0);
            /* not reached */
        case 'q':
            args->quiet = 1;
            break;
        case '?':
            if (optopt)
                fprintf(stderr, "Error: Unknown option '-%c' or "
                        "missing argument.\n", optopt);
            else
                fprintf(stderr, "Error: Unknown option '%s'.\n",
                        argv[optind - 1]);
            print_usage(argv[0]);
            return -1;
        default:
            fprintf(stderr, "Error: Internal parsing error (opt=%d).\n", opt);
            return -1;
        }
    }

    /* ---- Validation ---- */

    if (!args->sign_mode && !args->verify_mode) {
        fprintf(stderr, "Error: Specify -S (sign) or -V (verify).\n");
        return -1;
    }

    if (args->sign_mode && args->verify_mode) {
        fprintf(stderr, "Error: -S (sign) and -V (verify) are mutually "
                "exclusive.\n");
        return -1;
    }

    if (!args->input_path) {
        fprintf(stderr, "Error: Input file is required. Use -i <file>.\n");
        return -1;
    }

    if (!args->key_id_hex) {
        fprintf(stderr, "Error: Key ID is required. Use -I <hex>.\n");
        return -1;
    }

    if (args->verify_mode && !args->sig_path) {
        fprintf(stderr, "Error: Signature file is required in verify mode. "
                "Use -s <file>.\n");
        return -1;
    }

    if (args->sign_mode && args->sig_path) {
        fprintf(stderr, "Error: -s is not valid in sign mode.\n");
        return -1;
    }

    if (args->verify_mode && args->output_path) {
        fprintf(stderr, "Error: -o is not valid in verify mode.\n");
        return -1;
    }

    return 0;
}

/* ======================================================================
 * Main
 * ====================================================================== */

int main(int argc, char *argv[])
{
    struct cli_args cli;
    struct ele_pkcs11_rsa *ctx = NULL;
    uint8_t *input_buf   = NULL;
    size_t   input_len   = 0;
    uint8_t *key_id_buf  = NULL;
    size_t   key_id_len  = 0;
    uint8_t *sig_buf     = NULL;
    size_t   sig_len     = 0;
    int ret;

    /* ---- No arguments → show usage ---- */
    if (argc < 2) {
        print_usage(argv[0]);
        return 0;
    }

    /* ---- Parse CLI arguments ---- */
    if (parse_cli_args(argc, argv, &cli) != 0)
        return 1;

    /* ---- Read input data ---- */
    ret = read_binary_file(cli.input_path, &input_buf, &input_len);
    if (ret) {
        fprintf(stderr, "Error: Cannot read input file '%s': %s\n",
                cli.input_path, ele_pkcs11_rsa_strerror(ret));
        return 1;
    }

    if (input_len == 0) {
        fprintf(stderr, "Error: Input file is empty.\n");
        ret = 1;
        goto out;
    }

    /* ---- Convert key ID from hex to bytes ---- */
    ret = hexstr_to_bytes(cli.key_id_hex, &key_id_buf, &key_id_len);
    if (ret) {
        fprintf(stderr, "Error: Invalid key ID '%s'. "
                "Expected hex string (e.g. 02).\n", cli.key_id_hex);
        ret = 1;
        goto out;
    }

    if (key_id_len == 0 || key_id_len > ELE_PKCS11_RSA_MAX_KEY_ID_LEN) {
        fprintf(stderr, "Error: Key ID length %zu is invalid.\n", key_id_len);
        ret = 1;
        goto out;
    }

    /* ==================================================================
     * Verify mode
     * ================================================================== */
    if (cli.verify_mode) {
        /* Read signature file. */
        ret = read_binary_file(cli.sig_path, &sig_buf, &sig_len);
        if (ret) {
            fprintf(stderr, "Error: Cannot read signature file '%s': %s\n",
                    cli.sig_path, ele_pkcs11_rsa_strerror(ret));
            ret = 1;
            goto out;
        }

        if (sig_len == 0) {
            fprintf(stderr, "Error: Signature file is empty.\n");
            ret = 1;
            goto out;
        }

        if (sig_len > ELE_PKCS11_RSA_MAX_SIGNATURE_SIZE) {
            fprintf(stderr, "Error: Signature length %zu exceeds maximum %u.\n",
                    sig_len, ELE_PKCS11_RSA_MAX_SIGNATURE_SIZE);
            ret = 1;
            goto out;
        }

        /* Initialize PKCS#11 verification context. */
        ctx = ele_pkcs11_rsa_verify_init(cli.module_path,
                                          key_id_buf, key_id_len,
                                          cli.pin,
                                          ELE_PKCS11_RSA_PKCS_PSS);
        if (!ctx) {
            fprintf(stderr, "Error: Failed to initialize PKCS#11 verify "
                    "context.\n");
            ret = 1;
            goto out;
        }

        if (!cli.quiet)
            fprintf(stderr, "PKCS#11 module: %s\n",
                    cli.module_path ? cli.module_path
                                    : ELE_PKCS11_RSA_DEFAULT_MODULE);

        /* Verify. */
        ret = ele_pkcs11_rsa_verify(ctx, input_buf, input_len,
                                     sig_buf, sig_len);
        if (ret == 0) {
            if (!cli.quiet)
                fprintf(stderr, "Signature is VALID.\n");
            ret = 0;
        } else if (ret == -EBADMSG) {
            if (!cli.quiet)
                fprintf(stderr, "Signature is INVALID.\n");
            ret = 1;
        } else {
            fprintf(stderr, "Error: Verification failed: %s\n",
                    ele_pkcs11_rsa_strerror(ret));
            ret = 1;
        }

        goto out;
    }

    /* ==================================================================
     * Sign mode (-S)
     * ================================================================== */

    /* ---- Initialize PKCS#11 signing context ---- */
    ctx = ele_pkcs11_rsa_sign_init(cli.module_path,
                                    key_id_buf, key_id_len,
                                    cli.pin,
                                    ELE_PKCS11_RSA_PKCS_PSS);
    if (!ctx) {
        fprintf(stderr, "Error: Failed to initialize PKCS#11 signing "
                "context.\n");
        ret = 1;
        goto out;
    }

    if (!cli.quiet)
        fprintf(stderr, "PKCS#11 module: %s\n",
                cli.module_path ? cli.module_path
                                : ELE_PKCS11_RSA_DEFAULT_MODULE);

    /* ---- Sign ---- */
    ret = ele_pkcs11_rsa_sign(ctx, input_buf, input_len, &sig_buf, &sig_len);
    if (ret) {
        fprintf(stderr, "Error: Signing failed: %s\n",
                ele_pkcs11_rsa_strerror(ret));
        ret = 1;
        goto out;
    }

    if (!cli.quiet)
        fprintf(stderr, "Generated %zu-byte signature.\n", sig_len);

    /* ---- Write signature ---- */
    ret = write_binary_file(cli.output_path, sig_buf, sig_len);
    if (ret) {
        fprintf(stderr, "Error: Failed to write signature: %s\n",
                ele_pkcs11_rsa_strerror(ret));
        ret = 1;
        goto out;
    }

    if (!cli.quiet && cli.output_path)
        fprintf(stderr, "Wrote %zu bytes to '%s'.\n", sig_len, cli.output_path);

out:
    ele_pkcs11_rsa_free_buf(input_buf);
    ele_pkcs11_rsa_free_buf(key_id_buf);
    ele_pkcs11_rsa_free_buf(sig_buf);
    ele_pkcs11_rsa_free(ctx);
    return ret ? 1 : 0;
}
