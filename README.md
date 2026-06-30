# FCE AES PRIME Application for i.MX943

A command-line tool and reusable C library for AES encryption and decryption
using the **PRIME** cryptographic hardware engine on NXP i.MX943 processors.

## Features

- **AES cipher modes**: ECB, CBC, CTR (128/192/256-bit keys)
- **AEAD mode**: GCM with authentication tag support
- **Two API tiers**:
  - One-shot `aes_operation()` for convenience
  - Session-based API (`aes_session_*`) for efficient repeated operations
- **Dual key/IV input**: hexadecimal strings or binary files
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
# With key as hex string
./fce_aes_app -e -m CBC \
    -k e2f7fef712ca2c685ad8e052925ab10587a4fcdf3feee3365249b3c2e51d79d7 \
    -v 415e631116f530d2cda8e0364dbf67fb \
    -i plaintext.bin -o ciphertext.bin

# Or with key from binary file
./fce_aes_app -e -m CTR \
    -K keyfile.bin -V iv.bin \
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
# IV is extracted from the input file (no -v / -V needed)
./fce_aes_app -d -m CBC \
    -k e2f7fef712ca2c685ad8e052925ab10587a4fcdf3feee3365249b3c2e51d79d7 \
    -i ciphertext.bin -o restored.bin

# Or override the embedded IV manually
./fce_aes_app -d -m CBC \
    -k e2f7fef712ca2c685ad8e052925ab10587a4fcdf3feee3365249b3c2e51d79d7 \
    -v 415e631116f530d2cda8e0364dbf67fb \
    -i ciphertext.bin -o restored.bin
```

### GCM encryption (with authentication tag)

```bash
./fce_aes_app -e -m GCM \
    -k <64-hex-chars> -v <24-hex-chars> \
    -i plaintext.bin -o ciphertext.bin

# The authentication tag is printed to stdout and also embedded in the
# output file.

# Decrypt (tag extracted from input file, no -v needed):
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
| `-v <hex>` | IV/nonce as hex string (CBC: 32 hex, CTR/GCM: 24 hex; optional for decrypt) |
| `-V <file>` | IV/nonce from binary file (optional for decrypt) |
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
- The IV (nonce) is embedded in the encrypted output file for CBC, CTR,
  and GCM modes.  During decryption the IV is automatically extracted
  from the input file, so you do not need to supply it via `-v`/`-V`
  unless you want to override the embedded value.
- **Encrypt and decrypt input parameters differ:** encryption always
  requires the IV (`-v`/`-V`) because it must be known before writing the
  output file.  Decryption reads the IV from the file and only needs the
  key (and AAD for GCM if custom AAD was used).
- Maximum input data size per operation: 256 KiB.

## License

SPDX-License-Identifier: BSD-3-Clause

Copyright 2026 NXP
