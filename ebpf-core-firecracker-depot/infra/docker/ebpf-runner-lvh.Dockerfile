# syntax=docker/dockerfile:1.7
#
# LVH-backed runner image.
#
# Replaces the hand-rolled kernel-fetch in ebpf-runner.Dockerfile
# (apt-install linux-image-virtual + curl+dpkg-deb pinned launchpad
# debs + extract-vmlinux) with Cilium's little-vm-helper CLI.
#
# `lvh kernels pull <tag>` downloads kernel artefacts from
# quay.io/lvh-images/kernel-images:<tag> and extracts them as
#   ./<tag>/boot/vmlinux-X.Y.Z   (ELF, ready for Firecracker)
#   ./<tag>/boot/vmlinuz-X.Y.Z   (compressed bzImage)
#   ./<tag>/boot/btf-X.Y.Z       (raw BTF data)
#   plus System.map, config, lib/modules/...
#
# IMPORTANT: do NOT confuse `quay.io/lvh-images/kernel-images`
# (raw kernel files, what we want) with the similar-named
# `quay.io/lvh-images/complexity-test:<ver>` images (entire qcow2
# VM disks for lvh's run command — different beast entirely; the
# qcow2s contain `/data/images/*.qcow2.zst`, not /boot/vmlinux).

# ----- Stage A: build the lvh CLI -----------------------------------
# Need go >= 1.25.7 for lvh; alpine 3.20 ships 1.22, so pin the image.
FROM golang:1.25-alpine AS lvh-cli
RUN apk add --no-cache git make build-base
RUN go install github.com/cilium/little-vm-helper/cmd/lvh@latest \
 && /go/bin/lvh --help 2>&1 | head -3

# ----- Stage B: pull kernels via lvh CLI -----------------------------
FROM alpine:3.20 AS kernel-collect

RUN apk add --no-cache ca-certificates curl file

COPY --from=lvh-cli /go/bin/lvh /usr/local/bin/lvh

# Pin to "-main" tags, which the LVH project rebuilds nightly. Bump
# to a timestamp pin once you've picked a version known to work with
# your probe (e.g. 6.6-20251015.123456).
WORKDIR /work
RUN lvh kernels pull 5.15-main \
 && lvh kernels pull 6.1-main \
 && lvh kernels pull 6.6-main \
 && lvh kernels pull 6.12-main \
 && ls -la /work/

# Each tag dir has /boot/vmlinux-X.Y.Z and /boot/vmlinuz-X.Y.Z.
# Take the uncompressed vmlinux ELF (Firecracker boots it directly).
RUN for v in 5.15 6.1 6.6 6.12; do \
      cp /work/$v-main/boot/vmlinux-* /work/vmlinux-$v; \
      file /work/vmlinux-$v; \
    done \
 && ls -lh /work/vmlinux-*

# ----- Stage C: generate vmlinux.h from the newest kernel ------------
FROM alpine:3.20 AS btf-dump

RUN apk add --no-cache bpftool file

COPY --from=kernel-collect /work/vmlinux-6.12 /tmp/vmlinux

RUN bpftool btf dump file /tmp/vmlinux format c > /tmp/vmlinux.h \
 && wc -l /tmp/vmlinux.h \
 && head -5 /tmp/vmlinux.h

# ----- Stage D: build probe + static-musl loader ---------------------
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

# ----- Stage E: initrd cpio ------------------------------------------
FROM alpine:3.20 AS initrd-build

RUN apk add --no-cache cpio

COPY --from=build /src/loader      /initrd/init
COPY --from=build /src/probe.bpf.o /initrd/probe.bpf.o

RUN chmod +x /initrd/init \
 && cd /initrd \
 && find . -print0 | cpio -o -H newc --null > /tmp/initrd.cpio \
 && ls -lh /tmp/initrd.cpio

# ----- Stage F: final runtime image ----------------------------------
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
