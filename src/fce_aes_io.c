// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 *
 * fce_aes_io.c — I/O utility implementation.
 *
 * Provides binary file I/O, hexadecimal string parsing, and a combined
 * loader that accepts key/IV data from either a hex string or a file.
 */

#include "fce_aes_io.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ======================================================================
 * Binary file I/O
 * ====================================================================== */

int read_binary_file(const char *path, uint8_t **out, size_t *out_len)
{
    FILE *fp;
    long file_size;
    size_t nread;

    if (!path || !out || !out_len)
        return -EINVAL;

    *out     = NULL;
    *out_len = 0;

    fp = fopen(path, "rb");
    if (!fp)
        return -errno;

    /* Determine file size. */
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -errno;
    }
    file_size = ftell(fp);
    if (file_size < 0) {
        fclose(fp);
        return -errno;
    }
    rewind(fp);

    /* Allocate buffer. */
    *out = (uint8_t *)malloc((size_t)file_size);
    if (!*out) {
        fclose(fp);
        return -ENOMEM;
    }

    nread = fread(*out, 1, (size_t)file_size, fp);
    if (nread != (size_t)file_size) {
        free(*out);
        *out = NULL;
        fclose(fp);
        return -EIO;
    }

    fclose(fp);
    *out_len = (size_t)file_size;
    return 0;
}

int write_binary_file(const char *path, const uint8_t *data, size_t len)
{
    FILE *fp;

    if (!data)
        return -EINVAL;

    if (path) {
        fp = fopen(path, "wb");
        if (!fp)
            return -errno;
    } else {
        fp = stdout;
    }

    if (len > 0 && fwrite(data, 1, len, fp) != len) {
        if (path)
            fclose(fp);
        return -EIO;
    }

    if (path)
        fclose(fp);
    else
        fflush(fp);

    return 0;
}

/* ======================================================================
 * Hex string parsing
 * ====================================================================== */

/**
 * hexval — Convert a single hex character to its numeric value (0-15),
 *          or -1 if the character is invalid.
 */
static int hexval(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

int hexstr_to_bytes(const char *hexstr, uint8_t **out, size_t *out_len)
{
    const char *p;
    size_t hex_len;
    size_t i;
    int hi, lo;

    if (!hexstr || !out || !out_len)
        return -EINVAL;

    *out     = NULL;
    *out_len = 0;

    /* Skip optional "0x" or "0X" prefix. */
    p = hexstr;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        p += 2;

    hex_len = strlen(p);
    if (hex_len == 0 || hex_len % 2 != 0)
        return -EINVAL;

    *out = (uint8_t *)malloc(hex_len / 2);
    if (!*out)
        return -ENOMEM;

    for (i = 0; i < hex_len / 2; i++) {
        hi = hexval(p[2 * i]);
        lo = hexval(p[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            free(*out);
            *out = NULL;
            return -EINVAL;
        }
        (*out)[i] = (uint8_t)((hi << 4) | lo);
    }

    *out_len = hex_len / 2;
    return 0;
}

/* ======================================================================
 * Key / IV loader (hex string or binary file)
 * ====================================================================== */

int load_key_or_iv(const char *src, int is_file,
                   uint8_t **out, size_t *out_len,
                   size_t expected_min, size_t expected_max)
{
    int ret;

    if (!src || !out || !out_len)
        return -EINVAL;

    *out     = NULL;
    *out_len = 0;

    if (is_file) {
        /* Load from file directly. */
        ret = read_binary_file(src, out, out_len);
        if (ret)
            return ret;
    } else {
        /* Try hex parsing first. */
        ret = hexstr_to_bytes(src, out, out_len);
        if (ret) {
            /* Not valid hex — try as a file path. */
            ret = read_binary_file(src, out, out_len);
            if (ret)
                return ret;
        }
    }

    /* Validate length if constraints were given. */
    if (expected_min > 0 && *out_len < expected_min) {
        free(*out);
        *out     = NULL;
        *out_len = 0;
        return -EINVAL;
    }
    if (expected_max > 0 && *out_len > expected_max) {
        free(*out);
        *out     = NULL;
        *out_len = 0;
        return -EINVAL;
    }

    return 0;
}
