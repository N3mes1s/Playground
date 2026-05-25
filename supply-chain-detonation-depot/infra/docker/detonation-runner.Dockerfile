# syntax=docker/dockerfile:1.7
#
# Cached runner image for supply-chain-detonation-depot.
#
# Stages:
#   A  install lvh + pull a kernel ELF              (same as PR #19)
#   B  generate vmlinux.h from the kernel BTF       (same as PR #19)
#   C  cross-compile probe + static-musl loader    (same as PR #19)
#   D  build initrd cpio — but this one is a full
#      Alpine rootfs with node + npm so the loader
#      can fork+exec npm install                    (new for this PR)
#   E  final runtime image with firecracker         (same as PR #19)
#
# Built via .depot/workflows/build-runner-image.yml and consumed by
# .depot/workflows/detonate-one.yml.

# ----- Stage A: Ubuntu linux-image-virtual --------------------------
# LVH `kernel-images` 6.6-main was tried first but doesn't ship the
# virtio_net driver — the guest's virtio-mmio NIC doesn't enumerate
# and `ip link set eth0 up` fails with "Cannot find device". Ubuntu's
# linux-image-virtual package is explicitly built for VM guests and
# includes the full virtio stack.
FROM ubuntu:24.04 AS kernel-collect

ENV DEBIAN_FRONTEND=noninteractive

RUN sed -i 's|http://archive.ubuntu.com/ubuntu|http://mirror.facebook.net/ubuntu|g; s|http://security.ubuntu.com/ubuntu|http://mirror.facebook.net/ubuntu|g' \
        /etc/apt/sources.list /etc/apt/sources.list.d/*.sources 2>/dev/null || true \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates curl xz-utils zstd lz4 lzop binutils file \
        linux-image-virtual \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /work \
 && cp /boot/vmlinuz-*-generic /work/vmlinuz \
 && file /work/vmlinuz

RUN curl -fsSL https://raw.githubusercontent.com/torvalds/linux/v6.8/scripts/extract-vmlinux -o /usr/local/bin/extract-vmlinux \
 && chmod +x /usr/local/bin/extract-vmlinux \
 && extract-vmlinux /work/vmlinuz > /work/vmlinux \
 && file /work/vmlinux \
 && ls -lh /work/vmlinux

# ----- Stage B: vmlinux.h from BTF ----------------------------------
FROM alpine:3.20 AS btf-dump
RUN apk add --no-cache bpftool file
COPY --from=kernel-collect /work/vmlinux /tmp/vmlinux
RUN bpftool btf dump file /tmp/vmlinux format c > /tmp/vmlinux.h \
 && wc -l /tmp/vmlinux.h

# ----- Stage C: probe + static-musl loader --------------------------
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

# ----- Stage D: Alpine-based initrd with node + npm ------------------
# Unlike PR #19's minimal cpio (just /init + /probe.bpf.o), this initrd
# needs to host a real `npm` subprocess. Build a full Alpine root via
# `apk --root` into /rootfs, then cpio it.
FROM alpine:3.20 AS rootfs-build

RUN apk add --no-cache cpio

# Bootstrap an Alpine chroot at /rootfs with what's needed to run npm:
#   alpine-base       — /etc/{passwd,group,hosts,os-release}, /sbin/init
#                       (overridden by our /init), basic file layout
#   busybox           — coreutils equivalents (ls, sh, mkdir, cat, ...)
#   musl              — /lib/ld-musl-x86_64.so.1 dynamic linker
#   libc6-compat      — glibc compatibility shim (some npm postinstall
#                       scripts assume glibc)
#   ca-certificates   — for HTTPS to registry.npmjs.org
#   nodejs npm        — the actual install tooling
RUN mkdir -p /rootfs/etc/apk \
 && cp /etc/apk/repositories /rootfs/etc/apk/repositories \
 && cp -r /etc/apk/keys      /rootfs/etc/apk/keys \
 && apk add --no-cache --root /rootfs --initdb \
        alpine-base busybox musl libc6-compat ca-certificates \
        iproute2 \
        nodejs npm \
 && du -sh /rootfs \
 && ls -l /rootfs/sbin/ip /rootfs/bin/busybox 2>&1 | head

# Drop our PID-1 loader and probe object on top of the Alpine root.
COPY --from=build /src/loader      /rootfs/init
COPY --from=build /src/probe.bpf.o /rootfs/probe.bpf.o
RUN chmod +x /rootfs/init

# Static DNS so the guest can resolve registry.npmjs.org via the
# host-side NAT'd tap interface. /etc/resolv.conf in the initrd is
# read by glibc/musl name resolution at runtime.
RUN printf 'nameserver 8.8.8.8\nnameserver 1.1.1.1\n' > /rootfs/etc/resolv.conf \
 && cat /rootfs/etc/resolv.conf

# Package as a cpio newc archive. ~60-80 MiB initrd for this set of
# packages; the FC guest sized at 1 GiB has plenty of headroom.
RUN cd /rootfs \
 && find . -print0 | cpio -o -H newc --null > /tmp/initrd.cpio \
 && ls -lh /tmp/initrd.cpio \
 && echo '--- initrd contents (first 30) ---' \
 && cpio -tv < /tmp/initrd.cpio | head -30

# ----- Stage E: final runtime image ---------------------------------
FROM buildpack-deps:24.04-scm

ENV DEBIAN_FRONTEND=noninteractive
ARG FIRECRACKER_VERSION=v1.15.0

RUN sed -i 's|http://archive.ubuntu.com/ubuntu|http://mirror.facebook.net/ubuntu|g; s|http://security.ubuntu.com/ubuntu|http://mirror.facebook.net/ubuntu|g' \
        /etc/apt/sources.list /etc/apt/sources.list.d/*.sources 2>/dev/null || true \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates curl jq xz-utils tar gzip uuid-runtime file \
        util-linux bsdmainutils \
        iproute2 iptables \
        python3 \
 && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://github.com/firecracker-microvm/firecracker/releases/download/${FIRECRACKER_VERSION}/firecracker-${FIRECRACKER_VERSION}-x86_64.tgz" -o /tmp/fc.tgz \
 && tar -xzf /tmp/fc.tgz -C /tmp \
 && install -m 0755 "/tmp/release-${FIRECRACKER_VERSION}-x86_64/firecracker-${FIRECRACKER_VERSION}-x86_64" /usr/local/bin/firecracker \
 && rm -rf /tmp/fc.tgz "/tmp/release-${FIRECRACKER_VERSION}-x86_64" \
 && firecracker --version

COPY --from=kernel-collect /work/vmlinux       /opt/guest/vmlinux
COPY --from=rootfs-build  /tmp/initrd.cpio    /opt/guest/initrd.cpio
COPY scripts/run_detonation.sh                /opt/run_detonation.sh
COPY scripts/detonate_one.sh                  /opt/detonate_one.sh
COPY scripts/diff_fingerprint.py              /opt/diff_fingerprint.py
COPY scripts/lockfile_diff.py                  /opt/lockfile_diff.py
COPY scripts/dns_proxy.py                      /opt/dns_proxy.py
COPY scripts/dns_log_to_json.py                /opt/dns_log_to_json.py
COPY baselines/                                /opt/baselines/
COPY lockfile-fixtures/                        /opt/lockfile-fixtures/

RUN chmod +x /opt/run_detonation.sh /opt/detonate_one.sh \
              /opt/diff_fingerprint.py /opt/lockfile_diff.py \
              /opt/dns_proxy.py /opt/dns_log_to_json.py \
 && file /opt/guest/vmlinux \
 && ls -lh /opt/guest/ /opt/run_detonation.sh /opt/detonate_one.sh \
           /opt/diff_fingerprint.py /opt/lockfile_diff.py \
           /opt/dns_proxy.py /opt/dns_log_to_json.py \
 && ls -lh /opt/baselines/ /opt/lockfile-fixtures/

WORKDIR /opt
