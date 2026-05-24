# Build the BPF probe (probe.bpf.o) and the static-musl loader binary.
# Invoked inside infra/docker/ebpf-runner.Dockerfile's Alpine builder
# stage where clang, libbpf-static, libelf-static and zlib-static are
# all available.
#
# Inputs:
#   VMLINUX_H   path to a pre-generated vmlinux.h (from `bpftool btf
#               dump file <vmlinux> format c`). Defaults to ./vmlinux.h
#               which the Dockerfile generates before invoking make.
#
# Outputs:
#   probe.bpf.o   CO-RE eBPF object, loaded by the userspace loader
#   loader        static-musl ELF, runs as PID 1 inside the guest

VMLINUX_H ?= vmlinux.h

CLANG     ?= clang
CC        ?= gcc

# clang for BPF — -g keeps DWARF/BTF so libbpf can do CO-RE relocs.
BPF_CFLAGS = -O2 -g -Wall -Werror \
             -target bpf \
             -D__TARGET_ARCH_x86 \
             -I.

# Static-musl userspace. -lbpf needs -lelf -lz transitively.
LOADER_CFLAGS = -O2 -Wall -Wextra
LOADER_LDLIBS = -lbpf -lelf -lz
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
