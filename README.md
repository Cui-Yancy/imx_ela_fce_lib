# FCE AES PRIME Application for i.MX943

A command-line tool and reusable C library for AES encryption and decryption
using the **PRIME** cryptographic hardware engine on NXP i.MX943 processors.

## Features

- **AES cipher modes**: ECB, CBC, CTR (128/192/256-bit keys)
- **AEAD mode**: GCM with authentication tag support
- **Two API tiers**:
  - One-shot `aes_operation()` for convenience
  - Session-based API (`aes_session_*`) for efficient repeated operations
- **Dual key input**: hexadecimal strings or binary files; IV auto-generated from /dev/urandom
- **Built-in self-test**: run with no arguments to verify all four modes

## Directory Structure

```
fce_aes_app/
  Makefile          — Build system
  README.md         — This file
  include/          — Public API headers
    fce_aes_api.h       Core PRIME AES API
    fce_aes_cli.h       CLI argument parser
    fce_aes_io.h        I/O utilities
    fce_aes_selftest.h  Self-test runner
  src/              — Implementation files
    fce_aes_app.c       Main entry point
    fce_aes_api.c       PRIME AES engine wrapper (core API)
    fce_aes_cli.c       Command-line argument parsing (getopt)
    fce_aes_io.c        File and hex-string I/O utilities
    fce_aes_selftest.c  Built-in test vectors and self-test runner
```

Dependencies flow one direction: `main → {cli, io, api, selftest}`.
No circular dependencies between modules.

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

### Native build (for host testing — requires PRIME device)

```bash
make
```

### Cross-compilation with Yocto SDK

```bash
make CROSS_COMPILE=aarch64-poky-linux- \
     SDKTARGETSYSROOT=/path/to/sysroots/aarch64-poky-linux
```

### Cross-compilation with custom toolchain

```bash
make CROSS_COMPILE=aarch64-linux-gnu- \
     SDKTARGETSYSROOT=/path/to/sysroot
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
GCM) with built-in AES-256 test vectors.

### Encrypt a file

```bash
# IV auto-generated from /dev/urandom
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
| CTR  | `[12-byte IV][ciphertext]` |
| GCM  | `[12-byte IV][ciphertext][16-byte tag]` |

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
# IV auto-generated from /dev/urandom
./fce_aes_app -e -m GCM \
    -k <64-hex-chars> \
    -i plaintext.bin -o ciphertext.bin

# The authentication tag is printed to stdout and also embedded in the
# output file.

# Decrypt (tag and IV extracted from input file):
./fce_aes_app -d -m GCM \
    -k <64-hex-chars> \
    -i ciphertext.bin -o restored.bin
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
| `-h` | Show help |

## C API Example

```c
#include "fce_aes_api.h"

/* One-shot encrypt */
uint8_t key[32] = { ... };
uint8_t iv[16]  = { ... };
uint8_t plaintext[] = "Hello, PRIME!";
uint8_t ciphertext[sizeof(plaintext)];

struct aes_params params = {
    .dir  = FCE_AES_ENCRYPT,
    .mode = FCE_AES_CBC,
    .key  = key, .key_len = sizeof(key),
    .iv   = iv,  .iv_len  = sizeof(iv),
    .input = plaintext, .input_len = sizeof(plaintext),
    .output = ciphertext, .output_len = sizeof(ciphertext),
};

int ret = aes_operation(&params);
```

For repeated operations, use the session-based API:

```c
struct aes_session sess = {0};
aes_session_open(&sess);
aes_session_load_key(&sess, key, sizeof(key));

/* ... many operations ... */
aes_session_crypto(&sess, &params1);
aes_session_crypto(&sess, &params2);

aes_session_close(&sess);
```

## Notes

- The PRIME engine requires 256 MiB of contiguous physical memory per
  session.  The SE library allocates this on `aes_session_open()`.
- Cache coherency is managed automatically using ARMv8 `dc cvac` / `dc civac`
  instructions.  No manual cache maintenance is needed by callers.
- GCM encryption produces a 16-byte authentication tag.  The tag is
  embedded in the output file and automatically extracted on decrypt.
- The IV (nonce) is automatically generated from `/dev/urandom` during
  encryption for CBC, CTR, and GCM modes.  The generated IV is printed
  to stdout and embedded in the output file.  During decryption the IV
  is extracted from the input file automatically, so only the key is
  required.
- GCM uses a built-in default AAD ("NXP-iMX9-AES-GCM", 16 bytes).
- Maximum input data size per operation: 256 KiB.

## License

SPDX-License-Identifier: BSD-3-Clause

Copyright 2026 NXP
