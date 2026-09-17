# Makefile for xdp_ipblock
# Requires: clang, llvm, libbpf-dev (or libbpf built from source)

CLANG   ?= clang
CC      ?= gcc
ARCH    ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Adjust these if libbpf is installed in a non-standard prefix
LIBBPF_INC ?=
LIBBPF_LIB ?=

CFLAGS_KERN := -O2 -g -Wall \
               -target bpf \
               -D__TARGET_ARCH_$(ARCH) \
               $(LIBBPF_INC)

CFLAGS_USER := -O2 -g -Wall \
               $(LIBBPF_INC)

LDFLAGS_USER := -lbpf -lelf -lz \
                $(LIBBPF_LIB)

.PHONY: all clean

all: xdp_ipblock_kern.o xdp_ipblock

# ---- kernel (BPF bytecode) ----
xdp_ipblock_kern.o: xdp_ipblock_kern.c
	$(CLANG) $(CFLAGS_KERN) -c $< -o $@

# ---- user-space loader ----
xdp_ipblock: xdp_ipblock_user.c
	$(CC) $(CFLAGS_USER) $< -o $@ $(LDFLAGS_USER)

clean:
	rm -f xdp_ipblock_kern.o xdp_ipblock
