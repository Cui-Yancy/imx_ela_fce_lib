// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 *
 * fce_aes_io.h — I/O utility declarations for the FCE AES application.
 *
 * Provides helpers for:
 *   - Reading / writing binary files
 *   - Parsing hexadecimal strings into byte arrays
 *   - Loading a key or IV from either a hex string or a binary file
 */

#ifndef FCE_AES_IO_H
#define FCE_AES_IO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * read_binary_file — Read an entire file into a heap-allocated buffer.
 *
 * The caller owns the returned buffer and must free() it.
 *
 * @param[in]  path    File path to read.
 * @param[out] out     On success, points to a malloc'd buffer with the file
 *                     contents (NULL on failure).
 * @param[out] out_len Number of bytes read.
 *
 * @return 0 on success, or a negative errno value on failure.
 */
int read_binary_file(const char *path, uint8_t **out, size_t *out_len);

/**
 * write_binary_file — Write a buffer to a file (or stdout).
 *
 * If @p path is NULL the data is written to stdout.
 *
 * @param[in] path  File path to write, or NULL for stdout.
 * @param[in] data  Buffer to write.
 * @param[in] len   Number of bytes to write.
 *
 * @return 0 on success, or a negative errno value on failure.
 */
int write_binary_file(const char *path, const uint8_t *data, size_t len);

/**
 * hexstr_to_bytes — Convert a hexadecimal string to a byte array.
 *
 * Skips an optional "0x" or "0X" prefix.  The string must contain an
 * even number of hex digits.  The caller owns the returned buffer.
 *
 * @param[in]  hexstr  Null-terminated hex string (e.g. "A1B2C3").
 * @param[out] out     On success, points to a malloc'd byte array.
 * @param[out] out_len Number of bytes produced.
 *
 * @return 0 on success, or a negative errno value on failure.
 */
int hexstr_to_bytes(const char *hexstr, uint8_t **out, size_t *out_len);

/**
 * load_key_or_iv — Load key or IV material from either a hex string or a
 *                  binary file.
 *
 * The function first tries to parse @p src as a hex string.  If that fails
 * (non-hex characters or odd length) it attempts to read @p src as a file
 * path.  This gives the user maximum flexibility.
 *
 * @p expected_min and @p expected_max define the acceptable byte-count
 * range (inclusive).  Pass 0 for both to accept any length.
 *
 * @param[in]  src           Hex string or file path.
 * @param[in]  is_file       Non-zero forces file-only mode (skip hex parse).
 * @param[out] out           On success, a malloc'd buffer with the data.
 * @param[out] out_len       Number of bytes loaded.
 * @param[in]  expected_min  Minimum acceptable byte count (0 = no minimum).
 * @param[in]  expected_max  Maximum acceptable byte count (0 = no maximum).
 *
 * @return 0 on success, or a negative errno value on failure.
 */
int load_key_or_iv(const char *src, int is_file,
                   uint8_t **out, size_t *out_len,
                   size_t expected_min, size_t expected_max);

#ifdef __cplusplus
}
#endif

#endif /* FCE_AES_IO_H */
