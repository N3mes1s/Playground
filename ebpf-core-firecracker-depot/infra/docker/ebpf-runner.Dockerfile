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
        ca-certificates curl xz-utils zstd lz4 lzop binutils file dpkg \
        linux-image-virtual \
 && rm -rf /var/lib/apt/lists/*

# Three Linux kernels with CONFIG_DEBUG_INFO_BTF=y so /sys/kernel/btf/
# vmlinux exists in the guest and libbpf can resolve CO-RE relocations
# at load time:
#
#   6.8  — Ubuntu noble's stock kernel (from apt linux-image-virtual)
#   6.1  — kernel.ubuntu.com mainline build of vanilla v6.1.0
#   5.15 — kernel.ubuntu.com mainline build of vanilla v5.15.0
#
# Three different upstream layouts of struct task_struct => CO-RE
# field-offset relocations actually have to do work.
#
# These mainline URLs are pinned to specific point releases (the
# date-stamped filename is the artefact ID); they don't move.

ARG KERNEL_6_1_URL=http://kernel.ubuntu.com/mainline/v6.1/amd64/linux-image-unsigned-6.1.0-060100-generic_6.1.0-060100.202303090726_amd64.deb
ARG KERNEL_5_15_URL=http://kernel.ubuntu.com/mainline/v5.15/amd64/linux-image-unsigned-5.15.0-051500-generic_5.15.0-051500.202110312130_amd64.deb

RUN mkdir -p /work \
 && cp /boot/vmlinuz-*-generic /work/vmlinuz-6.8 \
 && curl -fsSL "$KERNEL_6_1_URL"  -o /work/k61.deb \
 && curl -fsSL "$KERNEL_5_15_URL" -o /work/k515.deb \
 && dpkg-deb -x /work/k61.deb  /work/k61 \
 && dpkg-deb -x /work/k515.deb /work/k515 \
 && cp /work/k61/boot/vmlinuz-*-generic  /work/vmlinuz-6.1 \
 && cp /work/k515/boot/vmlinuz-*-generic /work/vmlinuz-5.15 \
 && rm -rf /work/k61 /work/k515 /work/*.deb \
 && ls -lh /work/vmlinuz-*

# Decompress each vmlinuz -> vmlinux ELF. extract-vmlinux handles
# gzip / zstd / lz4 / lzop / xz wrappers.
RUN curl -fsSL https://raw.githubusercontent.com/torvalds/linux/v6.8/scripts/extract-vmlinux -o /usr/local/bin/extract-vmlinux \
 && chmod +x /usr/local/bin/extract-vmlinux \
 && for v in 5.15 6.1 6.8; do \
      extract-vmlinux /work/vmlinuz-$v > /work/vmlinux-$v; \
      file /work/vmlinux-$v; \
    done \
 && ls -lh /work/vmlinux-*

# ----- Stage B: generate vmlinux.h from the kernel's BTF --------------
FROM alpine:3.20 AS btf-dump

RUN apk add --no-cache bpftool file

# Generate vmlinux.h from the NEWEST kernel (6.8). That's the BTF
# headers the probe will be compiled against. CO-RE relocations at
# load time will rewrite field offsets when the probe runs against
# the older 6.1 / 5.15 guest kernels.
COPY --from=kernel-fetch /work/vmlinux-6.8 /tmp/vmlinux

# bpftool reads BTF straight from the ELF .BTF section. If the kernel
# was built without CONFIG_DEBUG_INFO_BTF this will fail loudly.
RUN bpftool btf dump file /tmp/vmlinux format c > /tmp/vmlinux.h \
 && wc -l /tmp/vmlinux.h \
 && head -5 /tmp/vmlinux.h

# ----- Stage C: cross-compile probe + loader --------------------------
FROM alpine:3.20 AS build

# Alpine bundles static .a archives inside the -dev packages
# (libbpf-dev ships /usr/lib/libbpf.a, elfutils-dev ships libelf.a).
# libelf.a calls into zstd/xz/bz2 for compressed-ELF-section support,
# so all three need static counterparts too.
RUN apk add --no-cache \
        build-base clang lld llvm \
        libbpf-dev \
        elfutils-dev \
        zlib-dev zlib-static \
        zstd-static xz-static bzip2-static \
        linux-headers bpftool \
        argp-standalone

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

# Stage 1 expects /opt/guest/vmlinux (the 6.8 default).
# Stage 2 picks one of the per-version files under /opt/guest/.
COPY --from=kernel-fetch /work/vmlinux-5.15  /opt/guest/vmlinux-5.15
COPY --from=kernel-fetch /work/vmlinux-6.1   /opt/guest/vmlinux-6.1
COPY --from=kernel-fetch /work/vmlinux-6.8   /opt/guest/vmlinux-6.8
COPY --from=initrd-build /tmp/initrd.cpio    /opt/guest/initrd.cpio
COPY scripts/run_linux_guest.sh              /opt/run_linux_guest.sh

# /opt/guest/vmlinux is a symlink to 6.8 so the Stage 1 workflow that
# hardcoded the path keeps working.
RUN ln -s vmlinux-6.8 /opt/guest/vmlinux \
 && chmod +x /opt/run_linux_guest.sh \
 && for v in 5.15 6.1 6.8; do file /opt/guest/vmlinux-$v; done \
 && ls -lh /opt/guest/ /opt/run_linux_guest.sh

WORKDIR /opt
