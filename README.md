# PRIME FCE AES Application for i.MX943

A command-line tool and reusable C library for AES encryption and decryption
using the **PRIME** cryptographic hardware engine (its **FCE** AES block)
on NXP i.MX943 processors.

## Features

- **AES cipher modes**: ECB, CBC, CTR, GCM (128/192/256-bit keys)
- **PKCS#7 padding**: ECB and CBC automatically pad to the AES block size
  (16 bytes) on encrypt and strip on decrypt
- **Unified API**: init → encrypt/decrypt (×N) → free lifecycle
- **Explicit IV control**: IV is a parameter passed to encrypt/decrypt;
  random IV generation available via `fce_aes_generate_iv()`
- **Dual key input**: hexadecimal strings or binary files
- **Dual backend**: PRIME hardware engine (default) with transparent
  fallback to OpenSSL software crypto; force OpenSSL via `-s` flag or
  `FCE_AES_FLAG_FORCE_OPENSSL`
- **Cross-verification**: built-in self-test runs all four modes as
  round-trip + cross-verify against OpenSSL
- **Output format**: encrypted file embeds IV (and GCM tag) alongside
  ciphertext for self-describing storage

## Directory Structure

```
fce_aes_app/
  Makefile          — Build system
  README.md         — This file
  include/          — Public API headers
    fce_aes.h           Unified FCE AES API (recommended)
    fce_aes_session.h   Low-level PRIME session API (aes_session_*)
    fce_aes_cli.h       CLI argument parser
    fce_aes_format.h    On-disk file format (IV/tag layout)
    fce_aes_io.h        I/O utilities
    aes_openssl.h       OpenSSL software crypto backend
    fce_aes_selftest.h  Self-test runner
  src/              — Implementation files
    fce_aes_app.c       Main entry point
    fce_aes_session.c   PRIME FCE AES session API (low-level)
    fce_aes.c           Unified FCE AES API implementation
    fce_aes_cli.c       Command-line argument parsing (getopt)
    fce_aes_format.c    On-disk file format (IV/tag layout)
    fce_aes_io.c        File and hex-string I/O utilities
    aes_openssl.c       OpenSSL AES implementation (EVP API)
    fce_aes_selftest.c  Built-in test vectors and self-test runner
```

Dependencies flow one direction: `main -> {cli, io, openssl, api, fce_aes, selftest}`.
No circular dependencies between modules.

In addition to the CLI binary, the Makefile also builds a static library
`libfce_aes.a` containing the core crypto modules (fce_aes_session, fce_aes,
aes_openssl, fce_aes_format).  External projects link against this library
without pulling in CLI/IO/selftest code.

## Prerequisites

- **NXP ELE SE library** with PRIME support, built with `PLAT=prime`:

  ```bash
  cd <ele-src>
  make PLAT=prime
  ```

  This produces `libprime.so` in the ELE source tree.

- **ARM cross-compiler** (for target deployment):

  ```bash
  # Yocto SDK example
  source /opt/fsl-imx-wayland/6.x/environment-setup-aarch64-poky-linux
  ```

## Building

### Cross-compilation with Yocto SDK (recommended)

```bash
source /opt/fsl-imx-xwayland/6.18-whinlatter/environment-setup-armv8a-poky-linux

# OpenSSL-only build (portable, no PRIME hardware required)
make USE_PRIME=0

# Full build with PRIME hardware support
make USE_PRIME=1
```

### Cross-compilation with custom toolchain

```bash
make CROSS_COMPILE=aarch64-poky-linux- \
     SDKTARGETSYSROOT=/path/to/sysroots/aarch64-poky-linux
```

### Native build (host with PRIME device)

```bash
make
```

### Build only the static library

```bash
make libfce_aes.a
```

The resulting `libfce_aes.a` can be linked into other projects:
```makefile
# In the consumer's Makefile
CFLAGS  += -I/path/to/fce_aes_app/include
LDFLAGS += -L/path/to/fce_aes_app
LDLIBS  += -lfce_aes -lcrypto
```

### Install to a target rootfs

```bash
make DESTDIR=/path/to/rootfs install
```

## Usage

### Self-test (no arguments)

```bash
./fce_aes_app
```

Runs encrypt/decrypt round-trip tests for all four modes (ECB, CBC, CTR,
GCM) with built-in AES-256 test vectors, and cross-verifies the PRIME
hardware results against the OpenSSL software backend.

### Encrypt a file

```bash
# IV generated from /dev/urandom automatically
./fce_aes_app -e -m CBC \
    -k e2f7fef712ca2c685ad8e052925ab10587a4fcdf3feee3365249b3c2e51d79d7 \
    -i plaintext.bin -o ciphertext.bin
```

**Output file format (non-ECB modes):** The encrypted output file embeds the IV
(and for GCM, the authentication tag) together with the ciphertext:

| Mode | Layout |
|------|--------|
| ECB  | `[ciphertext]` |
| CBC  | `[16-byte IV][ciphertext]` |
| CTR  | `[16-byte IV][ciphertext]` |
| GCM  | `[12-byte IV][ciphertext][16-byte tag]` |

> **Note:** ECB and CBC use PKCS#7 padding.  The ciphertext written to
> the output file is padded to a multiple of 16 bytes and is therefore
> always larger than the original plaintext (by 1–16 bytes).

This means the IV (and GCM tag) travel with the encrypted data, so you only
need to supply the key when decrypting (see below).

### Decrypt a file

```bash
# IV is extracted from the input file
./fce_aes_app -d -m CBC \
    -k e2f7fef712ca2c685ad8e052925ab10587a4fcdf3feee3365249b3c2e51d79d7 \
    -i ciphertext.bin -o restored.bin
```

### GCM encryption (with authentication tag)

```bash
# IV auto-generated
./fce_aes_app -e -m GCM \
    -k <64-hex-chars> \
    -i plaintext.bin -o ciphertext.bin

# The authentication tag is printed to stdout and embedded in the
# output file.

# Decrypt (tag and IV extracted from input file):
./fce_aes_app -d -m GCM \
    -k <64-hex-chars> \
    -i ciphertext.bin -o restored.bin
```

### Cross-verification: PRIME ↔ OpenSSL

The built-in self-test (`./fce_aes_app` with no arguments) automatically
cross-verifies all four modes across both backends: it encrypts with
PRIME and decrypts with OpenSSL, encrypts with OpenSSL and decrypts with
PRIME, and directly compares ciphertexts and GCM tags.

For manual cross-verification, use the `-s` flag:

```bash
# ECB is deterministic (no IV)
./fce_aes_app    -e -m ECB -k <key> -i plaintext.bin -o hw_ecb.bin
./fce_aes_app -s -e -m ECB -k <key> -i plaintext.bin -o sw_ecb.bin
diff hw_ecb.bin sw_ecb.bin && echo "PRIME matches OpenSSL"
```

## CLI Options

| Option | Description |
|--------|-------------|
| `-e` | Encrypt (default) |
| `-d` | Decrypt |
| `-m <mode>` | AES mode: `ECB`, `CBC`, `CTR`, `GCM` (default: CBC) |
| `-i <file>` | Input data file (binary) |
| `-o <file>` | Output data file (binary; default: stdout) |
| `-k <hex>` | AES key as hex string (32/48/64 hex chars) |
| `-K <file>` | AES key from binary file (16/24/32 bytes) |
| `-s` | Use OpenSSL software crypto instead of PRIME hardware |
| `-q` | Quiet mode — suppress informational output |
| `-h` | Show help |

## C API Example

The recommended entry point is the **unified API** (`fce_aes.h`).

### Encrypt (with explicit IV)

```c
#include "fce_aes.h"

uint8_t key[32] = { ... };
uint8_t plaintext[] = "Hello, PRIME!";

/* 1. Init: create context (opens PRIME session or falls back to OpenSSL) */
struct fce_aes *ctx = fce_aes_init(FCE_AES_CBC, key, sizeof(key),
                                    NULL, 0);
if (!ctx) { /* handle error */ }

/* 2. Generate random IV */
uint8_t *iv;
size_t   iv_len;
fce_aes_generate_iv(FCE_AES_CBC, &iv, &iv_len);

/* 3. Encrypt (output is heap-allocated) */
uint8_t *ct;
size_t   ct_len;
int ret = fce_aes_encrypt(ctx, iv, iv_len,
                           plaintext, sizeof(plaintext),
                           &ct, &ct_len);

/* 4. Free buffers and context */
fce_aes_free_buf(iv);
fce_aes_free_buf(ct);
fce_aes_free(ctx);
```

### Decrypt

```c
/* Re-init with the same key */
struct fce_aes *ctx = fce_aes_init(FCE_AES_CBC, key, sizeof(key),
                                    NULL, 0);

/* Decrypt using the same IV */
uint8_t *pt;
size_t   pt_len;
fce_aes_decrypt(ctx, iv, iv_len, ct, ct_len, &pt, &pt_len);

fce_aes_free_buf(pt);
fce_aes_free(ctx);
```

### Repeated operations (same session)

```c
struct fce_aes *ctx = fce_aes_init(FCE_AES_CTR, key, sizeof(key),
                                    NULL, 0);

for (int i = 0; i < N; i++) {
    uint8_t *iv, *ct;
    size_t   iv_len, ct_len;

    fce_aes_generate_iv(FCE_AES_CTR, &iv, &iv_len);
    fce_aes_encrypt(ctx, iv, iv_len, frame[i], frame_len[i],
                    &ct, &ct_len);
    /* ... send/store ct, iv ... */
    fce_aes_free_buf(iv);
    fce_aes_free_buf(ct);
}

fce_aes_free(ctx);
```

### Force OpenSSL backend

```c
struct fce_aes *ctx = fce_aes_init_ex(FCE_AES_CBC, key, sizeof(key),
                                       NULL, 0,
                                       FCE_AES_FLAG_FORCE_OPENSSL);
```

### Low-level session API

For callers who need direct PRIME session control, the original
`aes_session_*` API is still available:

```c
#include "fce_aes_session.h"

struct aes_session sess = {0};
aes_session_open(&sess);
aes_session_load_key(&sess, key, sizeof(key));

/* ... many operations with struct aes_params ... */
aes_session_crypto(&sess, &params);

aes_session_close(&sess);
```

## Notes

- The PRIME engine requires 256 MiB of contiguous physical memory per
  session.  The SE library allocates this on `aes_session_open()`.
- Cache coherency is managed automatically using ARMv8 `dc cvac` / `dc civac`
  instructions.  No manual cache maintenance is needed by callers.
- GCM encryption produces a 16-byte authentication tag appended to the
  ciphertext in the output buffer.  The tag is embedded in the output
  file and automatically extracted on decrypt.
- IV is an explicit parameter in `fce_aes_encrypt()` / `fce_aes_decrypt()`.
  Call `fce_aes_generate_iv()` to obtain a random IV from `/dev/urandom`,
  or supply your own.
- GCM uses a built-in default AAD ("NXP-iMX9-AES-GCM", 16 bytes).
- Maximum input data size per operation: 1 GiB (limited by PRIME firmware
  shared-memory allocation).
- **PKCS#7 padding** (ECB and CBC):
  - Encrypt pads the plaintext to a multiple of 16 bytes using PKCS#7
    padding (always at least 1 byte; block-aligned data gets a full
    16-byte padding block).  The output file is therefore always larger
    than the input for ECB/CBC.
  - Decrypt automatically strips the padding.  On authentication failure
    (invalid padding) the decrypted data is still returned but the
    padding is not stripped — callers should check the plaintext length
    for the actual decrypted size.
- **OpenSSL backend** (`-s` or `FCE_AES_FLAG_FORCE_OPENSSL`):
  - ECB and CBC use PKCS#7 padding (same as the PRIME backend).
  - CTR mode uses a 16-byte counter block (IV).  When a 12-byte nonce is
    provided it is padded to 16 bytes as `[nonce || 0x00000001]` (NIST SP
    800-38A initial counter value = 1).
  - GCM authentication tag verification is performed by OpenSSL on
    decrypt; a mismatch returns an error.

### Migration from crypto_stream (removed)

If you were using `crypto_stream_encrypt()`, migrate to the unified API:

| Old API | New API |
|---------|---------|
| `crypto_stream_new(mode, key, key_len)` | `fce_aes_init(mode, key, key_len, aad, aad_len)` |
| `crypto_stream_encrypt(cs, data, len, &out, &olen)` | `fce_aes_encrypt(ctx, iv, iv_len, data, len, &out, &olen)` + `fce_aes_generate_iv()` |
| `crypto_stream_free(cs)` | `fce_aes_free(ctx)` |
| `crypto_stream_free_buf(buf)` | `fce_aes_free_buf(buf)` |
| `crypto_stream_iv_length(cs)` | `fce_aes_iv_length(ctx)` |
| `crypto_stream_tag_length(cs)` | `fce_aes_tag_length(ctx)` |

Key differences:
- IV is now **explicit** — generate it separately and pass to encrypt/decrypt.
- Output is `[ciphertext]` (or `[ciphertext][tag]` for GCM) without the
  IV prepended — manage IV storage yourself or prepend it as needed.
- Both **encrypt and decrypt** are supported (old crypto_stream was
  encrypt-only).

## License

SPDX-License-Identifier: BSD-3-Clause

Copyright 2026 NXP
