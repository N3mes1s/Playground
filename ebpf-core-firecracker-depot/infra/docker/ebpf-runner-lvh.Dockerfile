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

# Use lvh CLI to pull kernels — it knows the registry URL convention
# and handles whatever extraction is needed to surface vmlinuz/vmlinux
# files. The complexity-test:<ver> images we tried directly are qcow2
# VM disks, not raw kernel artefacts.

# ----- Stage A: install lvh CLI + pull kernels -----------------------
FROM golang:1.23-alpine AS lvh-cli
RUN apk add --no-cache git make build-base
RUN go install github.com/cilium/little-vm-helper/cmd/lvh@latest

FROM alpine:3.20 AS kernel-collect

RUN apk add --no-cache ca-certificates curl file bash

COPY --from=lvh-cli /go/bin/lvh /usr/local/bin/lvh

# Probe what `lvh kernels pull` actually does with one version, then
# dump the resulting tree so we know how to wire it for real.
RUN lvh kernels --help 2>&1 | head -40 \
 && echo '--- pull help ---' \
 && lvh kernels pull --help 2>&1 | head -40

RUN lvh kernels pull 6.6-main 2>&1 | head -60 \
 && echo '--- pulled tree ---' \
 && find / -maxdepth 5 -iname '*vmlin*' 2>/dev/null | head -20 \
 && echo '--- ~/.config/lvh ---' \
 && find ~/.config -maxdepth 6 -type f 2>/dev/null | head -20 \
 && false # diagnostic: fail to surface the layout

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
