# syntax=docker/dockerfile:1.7
#
# Cached runner image for the CO-RE eBPF experiment.
#
# Stages:
#   A  fetch + decompress a Linux kernel ELF with BTF
#   B  generate vmlinux.h from that kernel's BTF
#   C  cross-compile probe.bpf.o + static-musl loader against vmlinux.h
#   D  assemble the initrd cpio (init = loader, /probe.bpf.o)
#   E  final runtime image: firecracker + util-linux + (kernel, initrd, run script)
#
# Built via .depot/workflows/build-runner-image.yml and consumed by
# .depot/workflows/boot-single-kernel.yml.

# ----- Stage A: fetch a Linux kernel with BTF -------------------------
FROM ubuntu:24.04 AS kernel-fetch

ENV DEBIAN_FRONTEND=noninteractive

RUN sed -i 's|http://archive.ubuntu.com/ubuntu|http://mirror.facebook.net/ubuntu|g; s|http://security.ubuntu.com/ubuntu|http://mirror.facebook.net/ubuntu|g' \
        /etc/apt/sources.list /etc/apt/sources.list.d/*.sources 2>/dev/null || true \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates curl xz-utils zstd lz4 lzop dpkg binutils file \
 && rm -rf /var/lib/apt/lists/*

# Ubuntu 24.04 (noble) ships kernel 6.8 with CONFIG_DEBUG_INFO_BTF=y so
# /sys/kernel/btf/vmlinux exists in the running guest and libbpf can
# resolve CO-RE relocations.  Pull a specific 6.8.x build for
# reproducibility.
ARG KERNEL_DEB_URL=https://launchpad.net/ubuntu/+source/linux/6.8.0-83.83/+build/31195822/+files/linux-image-unsigned-6.8.0-83-generic_6.8.0-83.83_amd64.deb
RUN mkdir -p /work/deb \
 && curl -fsSL "$KERNEL_DEB_URL" -o /work/kernel.deb \
 && dpkg-deb -x /work/kernel.deb /work/deb \
 && ls -lh /work/deb/boot/vmlinuz* \
 && cp /work/deb/boot/vmlinuz-* /work/vmlinuz

# Decompress vmlinuz -> vmlinux ELF using the upstream extract-vmlinux
# script (works whether the inner image is gzipped, zstd, lz4, lzop).
RUN curl -fsSL https://raw.githubusercontent.com/torvalds/linux/v6.8/scripts/extract-vmlinux -o /usr/local/bin/extract-vmlinux \
 && chmod +x /usr/local/bin/extract-vmlinux \
 && extract-vmlinux /work/vmlinuz > /work/vmlinux \
 && file /work/vmlinux \
 && ls -lh /work/vmlinux

# ----- Stage B: generate vmlinux.h from the kernel's BTF --------------
FROM alpine:3.20 AS btf-dump

RUN apk add --no-cache bpftool file

COPY --from=kernel-fetch /work/vmlinux /tmp/vmlinux

# bpftool reads BTF straight from the ELF .BTF section. If the kernel
# was built without CONFIG_DEBUG_INFO_BTF this will fail loudly.
RUN bpftool btf dump file /tmp/vmlinux format c > /tmp/vmlinux.h \
 && wc -l /tmp/vmlinux.h \
 && head -5 /tmp/vmlinux.h

# ----- Stage C: cross-compile probe + loader --------------------------
FROM alpine:3.20 AS build

RUN apk add --no-cache \
        build-base clang lld llvm \
        libbpf-dev libbpf-static \
        elfutils-dev elfutils-static \
        zlib-dev zlib-static \
        linux-headers bpftool

WORKDIR /src
COPY src/ .
COPY --from=btf-dump /tmp/vmlinux.h ./vmlinux.h

RUN make -j$(nproc) all \
 && file probe.bpf.o loader \
 && ls -lh probe.bpf.o loader \
 && echo '--- loader is statically linked ---' \
 && (ldd loader 2>&1 || true) | head -5

# ----- Stage D: assemble initrd cpio ----------------------------------
FROM alpine:3.20 AS initrd-build

RUN apk add --no-cache cpio

COPY --from=build /src/loader      /initrd/init
COPY --from=build /src/probe.bpf.o /initrd/probe.bpf.o

# Linux's initrd handler invokes /init (the binary at the cpio root).
# We chmod +x defensively even though the build stage already strips
# and marks executable.
RUN chmod +x /initrd/init \
 && cd /initrd \
 && find . -print0 | cpio -o -H newc --null > /tmp/initrd.cpio \
 && ls -lh /tmp/initrd.cpio \
 && echo '--- initrd contents ---' \
 && cpio -tv < /tmp/initrd.cpio

# ----- Stage E: final runtime image -----------------------------------
FROM buildpack-deps:24.04-scm

ENV DEBIAN_FRONTEND=noninteractive
ARG FIRECRACKER_VERSION=v1.15.0

# Same defensive apt-mirror swap as the sibling unikraft experiment.
RUN sed -i 's|http://archive.ubuntu.com/ubuntu|http://mirror.facebook.net/ubuntu|g; s|http://security.ubuntu.com/ubuntu|http://mirror.facebook.net/ubuntu|g' \
        /etc/apt/sources.list /etc/apt/sources.list.d/*.sources 2>/dev/null || true \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates curl jq xz-utils tar gzip uuid-runtime file \
        util-linux bsdmainutils \
 && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://github.com/firecracker-microvm/firecracker/releases/download/${FIRECRACKER_VERSION}/firecracker-${FIRECRACKER_VERSION}-x86_64.tgz" -o /tmp/fc.tgz \
 && tar -xzf /tmp/fc.tgz -C /tmp \
 && install -m 0755 "/tmp/release-${FIRECRACKER_VERSION}-x86_64/firecracker-${FIRECRACKER_VERSION}-x86_64" /usr/local/bin/firecracker \
 && rm -rf /tmp/fc.tgz "/tmp/release-${FIRECRACKER_VERSION}-x86_64" \
 && firecracker --version

COPY --from=kernel-fetch /work/vmlinux       /opt/guest/vmlinux
COPY --from=initrd-build /tmp/initrd.cpio    /opt/guest/initrd.cpio
COPY scripts/run_linux_guest.sh              /opt/run_linux_guest.sh

RUN chmod +x /opt/run_linux_guest.sh \
 && file /opt/guest/vmlinux \
 && ls -lh /opt/guest/vmlinux /opt/guest/initrd.cpio /opt/run_linux_guest.sh

WORKDIR /opt
