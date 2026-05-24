# syntax=docker/dockerfile:1.7
#
# LVH-backed runner image.
#
# Replaces the hand-rolled kernel-fetch in ebpf-runner.Dockerfile
# (apt-install linux-image-virtual + curl+dpkg-deb pinned launchpad
# debs + extract-vmlinux) with Cilium's little-vm-helper kernel
# catalog at quay.io/lvh-images/complexity-test:<ver>-<timestamp>.
#
# Why bother:
#   - LVH is the canonical "matrix BPF tests across kernel versions
#     in CI" tooling — Cilium use it in their own production CI.
#   - The images are pre-built with the BPF subsystems Cilium needs
#     (BTF, all the verifier knobs, debug info). We don't have to
#     trust an Ubuntu kernel's config or fish vmlinux out of vmlinuz.
#   - Bumping to a new kernel == bump one tag string.
#
# Tags pinned to the timestamp Cilium's tests-datapath-verifier.yaml
# uses on `main`. Renovate-bot rotates them upstream; bump here by
# copy-pasting whatever cilium/cilium currently uses.

# ----- LVH kernel "source" images ------------------------------------
FROM quay.io/lvh-images/complexity-test:5.15-20260310.122539 AS lvh-5.15
FROM quay.io/lvh-images/complexity-test:6.1-20260310.122539  AS lvh-6.1
FROM quay.io/lvh-images/complexity-test:6.6-20260310.122539  AS lvh-6.6
FROM quay.io/lvh-images/complexity-test:6.12-20260310.122539 AS lvh-6.12

# ----- Stage A: extract one vmlinux per kernel -----------------------
FROM ubuntu:24.04 AS kernel-collect

ENV DEBIAN_FRONTEND=noninteractive

RUN sed -i 's|http://archive.ubuntu.com/ubuntu|http://mirror.facebook.net/ubuntu|g; s|http://security.ubuntu.com/ubuntu|http://mirror.facebook.net/ubuntu|g' \
        /etc/apt/sources.list /etc/apt/sources.list.d/*.sources 2>/dev/null || true \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates curl xz-utils zstd lz4 lzop binutils file \
 && rm -rf /var/lib/apt/lists/*

# Diagnostic: dump the full root of the smallest LVH image so we
# can find where the bootable kernel actually lives in this image
# family. (First pass assumed /boot/ which doesn't exist; this
# unblocks figuring out the real path.)
COPY --from=lvh-5.15  / /tmp/k-5.15/

# extract-vmlinux is the canonical kernel.org script that strips
# the bootloader wrapper from a compressed bzImage. It groks gzip,
# zstd, lz4, lzop, xz.
RUN curl -fsSL https://raw.githubusercontent.com/torvalds/linux/v6.8/scripts/extract-vmlinux -o /usr/local/bin/extract-vmlinux \
 && chmod +x /usr/local/bin/extract-vmlinux

RUN echo '=== top-level dirs of LVH 5.15 image ===' && \
    ls -la /tmp/k-5.15/ && \
    echo '=== any file with "vmlin" in name ===' && \
    find /tmp/k-5.15 -maxdepth 6 -iname '*vmlin*' 2>/dev/null | head -30 && \
    echo '=== any large ELF (likely kernel) ===' && \
    find /tmp/k-5.15 -maxdepth 6 -type f -size +1M 2>/dev/null | head -30 && \
    echo '=== /data dirs ===' && \
    find /tmp/k-5.15 -maxdepth 3 -type d 2>/dev/null | head -40 && \
    false # fail intentionally so we get the logs

# ----- Stage B: generate vmlinux.h (from 6.12, newest of the matrix) -
FROM alpine:3.20 AS btf-dump

RUN apk add --no-cache bpftool file

COPY --from=kernel-collect /work/vmlinux-6.12 /tmp/vmlinux

RUN bpftool btf dump file /tmp/vmlinux format c > /tmp/vmlinux.h \
 && wc -l /tmp/vmlinux.h \
 && head -5 /tmp/vmlinux.h

# ----- Stage C: build probe + static-musl loader ---------------------
FROM alpine:3.20 AS build

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
 && ls -lh probe.bpf.o loader

# ----- Stage D: initrd cpio ------------------------------------------
FROM alpine:3.20 AS initrd-build

RUN apk add --no-cache cpio

COPY --from=build /src/loader      /initrd/init
COPY --from=build /src/probe.bpf.o /initrd/probe.bpf.o

RUN chmod +x /initrd/init \
 && cd /initrd \
 && find . -print0 | cpio -o -H newc --null > /tmp/initrd.cpio \
 && ls -lh /tmp/initrd.cpio

# ----- Stage E: final runtime image ----------------------------------
FROM buildpack-deps:24.04-scm

ENV DEBIAN_FRONTEND=noninteractive
ARG FIRECRACKER_VERSION=v1.15.0

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

COPY --from=kernel-collect /work/vmlinux-5.15 /opt/guest/vmlinux-5.15
COPY --from=kernel-collect /work/vmlinux-6.1  /opt/guest/vmlinux-6.1
COPY --from=kernel-collect /work/vmlinux-6.6  /opt/guest/vmlinux-6.6
COPY --from=kernel-collect /work/vmlinux-6.12 /opt/guest/vmlinux-6.12
COPY --from=initrd-build   /tmp/initrd.cpio  /opt/guest/initrd.cpio
COPY scripts/run_linux_guest.sh              /opt/run_linux_guest.sh

RUN chmod +x /opt/run_linux_guest.sh \
 && for v in 5.15 6.1 6.6 6.12; do file /opt/guest/vmlinux-$v; done \
 && ls -lh /opt/guest/ /opt/run_linux_guest.sh

WORKDIR /opt
