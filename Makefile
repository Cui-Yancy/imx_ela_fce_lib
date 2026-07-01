# SPDX-License-Identifier: BSD-3-Clause
#
# Makefile for fce_aes_app — i.MX943 FCE AES PRIME Application
#
# Source layout:
#   include/    — public header files (.h)
#   src/        — implementation files (.c)
#
# Cross-compilation (choose one):
#
#   a) Yocto SDK (sourced environment):
#        source /opt/fsl-imx-xwayland/6.18-whinlatter/environment-setup-armv8a-poky-linux
#        make
#
#   b) Standalone cross toolchain:
#        make CROSS_COMPILE=aarch64-poky-linux- \
#             SDKTARGETSYSROOT=/path/to/sysroots/armv8a-poky-linux
#
# The ELE library (libprime) must be built first with PLAT=prime:
#   cd ../ele && make PLAT=prime
#
# Variables
# ---------
# CROSS_COMPILE     Toolchain prefix (e.g. aarch64-poky-linux-).
#                   Not needed when using a Yocto SDK environment.
# SDKTARGETSYSROOT  Yocto SDK sysroot path (set --sysroot for cross builds).
# ELE_DIR           Path to the NXP ELE SE library source tree.
#                   Default: ../ele
# DESTDIR           Installation prefix for 'make install'.
# BINDIR            Binary installation directory (within DESTDIR).

CROSS_COMPILE      ?=
SDKTARGETSYSROOT   ?=
ELE_DIR            ?= ../ele
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

# Application name
TARGET := fce_aes_app

# Source files (under src/) and corresponding object files
SRCS := src/fce_aes_app.c \
        src/fce_aes_api.c \
        src/fce_aes_cli.c \
        src/fce_aes_format.c \
        src/fce_aes_io.c \
        src/fce_aes_selftest.c
OBJS := $(SRCS:.c=.o)

# ------------------------------------------------------------------
# Compiler and linker flags
# ------------------------------------------------------------------

# Include paths: local headers (include/), then PRIME API headers.
CFLAGS := -O2 -Wall -Werror \
          -Iinclude \
          -I$(ELE_DIR)/include \
          -I$(ELE_DIR)/include/prime

# Link against the PRIME shared library.
LDFLAGS := -L$(ELE_DIR)
LDLIBS  := -lprime

# When SDKTARGETSYSROOT is set, pass --sysroot so the compiler and linker
# find system headers and libraries under the sysroot.  The explicit
# -L$(ELE_DIR) above is a host path unaffected by --sysroot.
ifneq ($(SDKTARGETSYSROOT),)
CFLAGS  += --sysroot=$(SDKTARGETSYSROOT)
LDFLAGS += --sysroot=$(SDKTARGETSYSROOT)
endif

# ------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
