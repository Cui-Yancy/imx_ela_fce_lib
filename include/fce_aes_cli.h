// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 *
 * fce_aes_cli.h — Command-line interface declarations.
 *
 * Parses command-line arguments for the FCE AES application and produces
 * a structured descriptor (fce_aes_cli_args) that the main program can
 * use to set up an aes_operation call.
 */

#ifndef FCE_AES_CLI_H
#define FCE_AES_CLI_H

#include "fce_aes_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * struct fce_aes_cli_args — Descriptor produced by parse_cli_args().
 *
 * String pointers point into the original argv strings or to static
 * storage; they must not be freed by the caller.
 */
struct fce_aes_cli_args {
    /** AES mode parsed from -m (default: FCE_AES_CBC). */
    enum fce_aes_mode  mode;
    /** Operation direction from -e / -d (default: encrypt). */
    enum fce_aes_dir   dir;

    /** Input file path from -i (NULL if not provided). */
    const char        *input_path;
    /** Output file path from -o (NULL means write to stdout). */
    const char        *output_path;

    /** Key source string from -k or -K (NULL if absent). */
    const char        *key_src;
    /** Non-zero if key_src is a file path (-K rather than -k). */
    int                key_is_file;

    /** Non-zero to suppress informational output (from -q). */
    int                quiet;

    /** Non-zero to use OpenSSL software crypto instead of PRIME hardware
     *  (from -s).  Used for cross-verification of PRIME results.
     *  In builds without PRIME support (USE_PRIME=0) this flag has no
     *  effect — the OpenSSL backend is always used. */
    int                use_openssl;
};

/**
 * parse_cli_args — Parse command-line arguments.
 *
 * Prints an error message to stderr and returns a negative errno value
 * on failure.  On success @p args is filled in and 0 is returned.
 *
 * @param[in]  argc  Argument count (from main).
 * @param[in]  argv  Argument vector (from main).
 * @param[out] args  Parsed arguments.
 *
 * @return 0 on success, negative errno on error.
 */
int parse_cli_args(int argc, char *argv[], struct fce_aes_cli_args *args);

/**
 * print_usage — Print a help message to stdout.
 *
 * @param[in] prog  The program name (argv[0]).
 */
void print_usage(const char *prog);

#ifdef __cplusplus
}
#endif

#endif /* FCE_AES_CLI_H */
