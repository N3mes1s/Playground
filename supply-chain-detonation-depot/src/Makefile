# Build the supply-chain detonation BPF probe + static-musl loader.
# Same shape as ../../ebpf-core-firecracker-depot/src/Makefile (PR #19).

VMLINUX_H ?= vmlinux.h

CLANG ?= clang
CC    ?= gcc

BPF_CFLAGS = -O2 -g -Wall -Werror \
             -target bpf \
             -D__TARGET_ARCH_x86 \
             -I.

LOADER_CFLAGS  = -O2 -Wall -Wextra
LOADER_LDLIBS  = -lbpf -lelf -lz -lzstd -llzma -lbz2
LOADER_LDFLAGS = -static -no-pie

.PHONY: all clean

all: probe.bpf.o loader

probe.bpf.o: probe.bpf.c $(VMLINUX_H)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

loader: loader.c
	$(CC) $(LOADER_CFLAGS) $(LOADER_LDFLAGS) $< $(LOADER_LDLIBS) -o $@
	strip --strip-all $@

clean:
	rm -f probe.bpf.o loader
