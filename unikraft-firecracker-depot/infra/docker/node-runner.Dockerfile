# syntax=docker/dockerfile:1.7
#
# Cached runner image for Stage 2: Unikraft Node runtime + a CPIO rootfs
# containing detonate.js + node_modules/lodash, all baked in for
# fast detonation runs on Depot CI.
#
# Layout inside the image:
#   /opt/unikraft/node            — extracted Unikraft Node FC unikernel
#   /opt/unikraft/rootfs.cpio     — initrd with detonate.js + lodash
#   /opt/run_node_unikernel.sh    — boot + JSON parser
#   /usr/local/bin/firecracker    — FC v1.15.0
#
# Build context: unikraft-firecracker-depot/ (.dockerignore restricts
# to infra/, scripts/, rootfs/).

# ----- Stage A: pull the Unikraft Node runtime via kraft --------------
FROM buildpack-deps:24.04-scm AS uk-pull

ENV DEBIAN_FRONTEND=noninteractive

RUN sed -i 's|http://archive.ubuntu.com/ubuntu|http://mirror.facebook.net/ubuntu|g; s|http://security.ubuntu.com/ubuntu|http://mirror.facebook.net/ubuntu|g' \
        /etc/apt/sources.list /etc/apt/sources.list.d/*.sources 2>/dev/null || true \
 && apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl file \
 && rm -rf /var/lib/apt/lists/*

RUN curl -sSf https://get.kraftkit.sh | sh -s -- -y \
 && kraft version

# The Unikraft Node catalog publishes images as unikraft.org/node:<version>
# (not under library/ or runtime/). Try a few known LTS versions in order.
RUN ( kraft pkg pull --plat fc --arch x86_64 unikraft.org/node:22 \
   || kraft pkg pull --plat fc --arch x86_64 unikraft.org/node:21 \
   || kraft pkg pull --plat fc --arch x86_64 unikraft.org/node:20 \
   || kraft pkg pull --plat fc --arch x86_64 unikraft.org/node:18 ) \
 && mkdir -p /tmp/uk-extract \
 && for blob in $(find /root/.local/share/kraftkit -type f); do \
      ft="$(file -b "$blob" 2>/dev/null || true)"; \
      case "$ft" in *"tar archive"*) tar -xf "$blob" -C /tmp/uk-extract 2>/dev/null || true ;; esac; \
    done \
 && echo '--- extracted tree ---' \
 && find /tmp/uk-extract -type f -printf '%s\t%p\n' | sort -rn | head -20 \
 && cp /tmp/uk-extract/unikraft/bin/kernel /tmp/node-kernel \
 && file /tmp/node-kernel

# ----- Stage B: stage application files + npm install lodash ----------
FROM node:22-bookworm AS rootfs-stage

WORKDIR /rootfs-staging
COPY rootfs/detonate.js .
RUN npm init -y >/dev/null \
 && npm install --omit=dev --no-audit --no-fund --no-progress lodash@4 \
 && ls -lh node_modules/lodash/package.json detonate.js

# ----- Stage C: build the initrd CPIO archive -------------------------
FROM ubuntu:24.04 AS cpio-build

ENV DEBIAN_FRONTEND=noninteractive

RUN sed -i 's|http://archive.ubuntu.com/ubuntu|http://mirror.facebook.net/ubuntu|g; s|http://security.ubuntu.com/ubuntu|http://mirror.facebook.net/ubuntu|g' \
        /etc/apt/sources.list /etc/apt/sources.list.d/*.sources 2>/dev/null || true \
 && apt-get update \
 && apt-get install -y --no-install-recommends cpio \
 && rm -rf /var/lib/apt/lists/*

COPY --from=rootfs-stage /rootfs-staging /tmp/rootfs

# Unikraft expects a plain CPIO newc archive as the initrd.
RUN cd /tmp/rootfs \
 && find . -print0 | cpio -o -H newc --null > /tmp/rootfs.cpio \
 && ls -lh /tmp/rootfs.cpio \
 && cpio -tv < /tmp/rootfs.cpio | head -10

# ----- Stage D: final runtime image -----------------------------------
FROM buildpack-deps:24.04-scm

ENV DEBIAN_FRONTEND=noninteractive
ARG FIRECRACKER_VERSION=v1.15.0

RUN sed -i 's|http://archive.ubuntu.com/ubuntu|http://mirror.facebook.net/ubuntu|g; s|http://security.ubuntu.com/ubuntu|http://mirror.facebook.net/ubuntu|g' \
        /etc/apt/sources.list /etc/apt/sources.list.d/*.sources 2>/dev/null || true \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates curl jq xz-utils tar gzip uuid-runtime file binutils \
        util-linux bsdmainutils \
 && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://github.com/firecracker-microvm/firecracker/releases/download/${FIRECRACKER_VERSION}/firecracker-${FIRECRACKER_VERSION}-x86_64.tgz" -o /tmp/fc.tgz \
 && tar -xzf /tmp/fc.tgz -C /tmp \
 && install -m 0755 "/tmp/release-${FIRECRACKER_VERSION}-x86_64/firecracker-${FIRECRACKER_VERSION}-x86_64" /usr/local/bin/firecracker \
 && rm -rf /tmp/fc.tgz "/tmp/release-${FIRECRACKER_VERSION}-x86_64" \
 && firecracker --version

COPY --from=uk-pull   /tmp/node-kernel  /opt/unikraft/node
COPY --from=cpio-build /tmp/rootfs.cpio /opt/unikraft/rootfs.cpio
COPY scripts/run_node_unikernel.sh /opt/run_node_unikernel.sh

RUN chmod +x /opt/run_node_unikernel.sh \
 && file /opt/unikraft/node \
 && ls -lh /opt/unikraft/node /opt/unikraft/rootfs.cpio

WORKDIR /opt
