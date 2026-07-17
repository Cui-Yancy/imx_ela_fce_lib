# SPDX-License-Identifier: BSD-3-Clause
#
# Makefile for imx_ela_fce_lib — i.MX Security Library
#
# Provides:
#   libimx_security.a  — Static library with FCE AES + ELE RSA APIs
#   fce_aes_app        — CLI test tool for FCE AES encrypt/decrypt
#   ele_rsa_app        — CLI test tool for ELE RSA sign/verify
#
# Source layout:
#   include/            — Public API headers
#   include/internal/   — Internal/private headers
#   src/lib/            — Library implementation source files
#   src/app/            — CLI application source files
#
# Cross-compilation:
#
#   a) Yocto SDK (sourced environment):
#        source /opt/fsl-imx-xwayland/6.18-whinlatter/environment-setup-armv8a-poky-linux
#        make
#
#   b) Standalone cross toolchain:
#        make CROSS_COMPILE=aarch64-poky-linux- \
#             SDKTARGETSYSROOT=/path/to/sysroots/armv8a-poky-linux
#
# PRIME backend (NXP i.MX943 crypto hardware):
#
#   The ELE library (libprime) must be built first with PLAT=prime:
#     cd ../ele && make PLAT=prime
#
#   To build without PRIME (pure OpenSSL, portable to any Linux platform):
#     make USE_PRIME=0
#
# Variables
# ---------
# USE_PRIME         Build with PRIME hardware backend.  Set to 0 for a
#                   portable build that uses OpenSSL only.  Default: 1.
# CROSS_COMPILE     Toolchain prefix (e.g. aarch64-poky-linux-).
#                   Not needed when using a Yocto SDK environment.
# SDKTARGETSYSROOT  Yocto SDK sysroot path (set --sysroot for cross builds).
# ELE_DIR           Path to the NXP ELE SE library source tree.
#                   Default: ../imx-secure-enclave
# DESTDIR           Installation prefix for 'make install'.
# BINDIR            Binary installation directory (within DESTDIR).

USE_PRIME          ?= 1
CROSS_COMPILE      ?=
SDKTARGETSYSROOT   ?=
ELE_DIR            ?= ../imx-secure-enclave
DESTDIR            ?=
BINDIR             ?= /usr/bin

# Compiler: if CROSS_COMPILE was explicitly provided, compose from it.
# Otherwise respect the CC already in the environment (Yocto SDK) or
# default to "gcc" / "ar".
ifneq ($(CROSS_COMPILE),)
CC := $(CROSS_COMPILE)gcc
AR := $(CROSS_COMPILE)ar
endif
CC ?= gcc
AR ?= ar

# ------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------

LIB_TARGET := libimx_security.a
AES_TARGET := fce_aes_app
RSA_TARGET := ele_rsa_app

# Library sources (under src/lib/)
LIB_SRCS := src/lib/fce_aes.c \
            src/lib/fce_aes_session.c \
            src/lib/fce_aes_format.c \
            src/lib/aes_openssl.c \
            src/lib/ele_rsa.c \
            src/lib/imx_util.c
LIB_OBJS := $(LIB_SRCS:.c=.o)

# AES app sources (under src/app/)
AES_APP_SRCS := src/app/fce_aes_app.c \
                src/app/fce_aes_cli.c \
                src/app/fce_aes_selftest.c
AES_APP_OBJS := $(AES_APP_SRCS:.c=.o)

# RSA app sources (under src/app/)
RSA_APP_SRCS := src/app/ele_rsa_app.c
RSA_APP_OBJS := $(RSA_APP_SRCS:.c=.o)

# ------------------------------------------------------------------
# Compiler and linker flags
# ------------------------------------------------------------------

# Base CFLAGS: include paths for public and internal headers.
BASE_CFLAGS := -O2 -Wall -Werror -Iinclude

# Library CFLAGS: base + PRIME-specific (if enabled).
CFLAGS := $(BASE_CFLAGS)

# AES app CFLAGS: base + PRIME + app include path for fce_aes_cli.h.
AES_CFLAGS := $(BASE_CFLAGS) -Isrc/app

# RSA app CFLAGS: same as app (for consistency, though doesn't use PRIME).
RSA_CFLAGS := $(BASE_CFLAGS)

# Base link: OpenSSL crypto library (required for AES software backend).
LDLIBS  := -lcrypto -ldl

# PRIME-specific: include paths, library, and compile-time define.
ifeq ($(USE_PRIME),1)
CFLAGS     += -DUSE_PRIME \
              -I$(ELE_DIR)/include \
              -I$(ELE_DIR)/include/prime
AES_CFLAGS += -DUSE_PRIME
LDFLAGS    += -L$(ELE_DIR)
LDLIBS     += -lprime
endif

# When SDKTARGETSYSROOT is set, pass --sysroot so the compiler and linker
# find system headers and libraries under the sysroot.
ifneq ($(SDKTARGETSYSROOT),)
CFLAGS     += --sysroot=$(SDKTARGETSYSROOT)
AES_CFLAGS += --sysroot=$(SDKTARGETSYSROOT)
RSA_CFLAGS += --sysroot=$(SDKTARGETSYSROOT)
LDFLAGS    += --sysroot=$(SDKTARGETSYSROOT)
endif

# ------------------------------------------------------------------
# Rules
# ------------------------------------------------------------------

.PHONY: all clean install

all: $(LIB_TARGET) $(AES_TARGET) $(RSA_TARGET)

# Static library: archive all library objects.
$(LIB_TARGET): $(LIB_OBJS)
	@echo "Creating $@ ..."
	@$(AR) rcs $@ $^

# AES application: link app objects with the library.
$(AES_TARGET): $(AES_APP_OBJS) $(LIB_TARGET)
	@echo "Linking $@ ..."
	@$(CC) $(AES_CFLAGS) $(LDFLAGS) -o $@ $(AES_APP_OBJS) \
		-L. -limx_security $(LDLIBS)

# RSA application: link app object with the library (no OpenSSL needed).
$(RSA_TARGET): $(RSA_APP_OBJS) $(LIB_TARGET)
	@echo "Linking $@ ..."
	@$(CC) $(RSA_CFLAGS) $(LDFLAGS) -o $@ $(RSA_APP_OBJS) \
		-L. -limx_security -ldl

# Pattern rule: compile library sources.
src/lib/%.o: src/lib/%.c
	@echo "CC $@ ..."
	@$(CC) $(CFLAGS) -c -o $@ $<

# Pattern rule: compile AES app sources.
src/app/%.o: src/app/%.c
	@echo "CC $@ ..."
	@$(CC) $(AES_CFLAGS) -c -o $@ $<

clean:
	@echo "Cleaning ..."
	rm -f $(LIB_OBJS) $(AES_APP_OBJS) $(RSA_APP_OBJS)
	rm -f $(LIB_TARGET) $(AES_TARGET) $(RSA_TARGET)

install: $(AES_TARGET) $(RSA_TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(AES_TARGET) $(DESTDIR)$(BINDIR)/$(AES_TARGET)
	install -m 755 $(RSA_TARGET) $(DESTDIR)$(BINDIR)/$(RSA_TARGET)
