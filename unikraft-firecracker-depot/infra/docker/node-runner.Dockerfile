# syntax=docker/dockerfile:1.7
#
# Cached runner image for Stage 2: Unikraft Node unikernel + a CPIO
# initrd assembled per the official unikraft/catalog node/21 recipe
# (https://github.com/unikraft/catalog/blob/main/library/node/21/Dockerfile),
# extended with our detonate.js + node_modules/lodash.
#
# The Unikraft Node unikernel ships ONLY the kernel — the actual `node`
# binary, its musl/libgcc/libstdc++ runtime, CA certs, and timezone
# data must all be provided by the rootfs. See the failure
# "[libukcpio] /./usr/bin/node: Failed to load content" if the rootfs
# is missing the node binary or its libs.
#
# Final image layout:
#   /opt/unikraft/node            — kernel (110 MB ELF64)
#   /opt/unikraft/rootfs.cpio     — initrd with /usr/bin/node + libs + /usr/src/detonate.js
#   /opt/run_node_unikernel.sh    — boot + JSON-marker parser
#   /usr/local/bin/firecracker

# ----- Stage A: kraft-pull the Unikraft Node FC kernel ----------------
FROM buildpack-deps:24.04-scm AS uk-pull

ENV DEBIAN_FRONTEND=noninteractive

RUN sed -i 's|http://archive.ubuntu.com/ubuntu|http://mirror.facebook.net/ubuntu|g; s|http://security.ubuntu.com/ubuntu|http://mirror.facebook.net/ubuntu|g' \
        /etc/apt/sources.list /etc/apt/sources.list.d/*.sources 2>/dev/null || true \
 && apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl file \
 && rm -rf /var/lib/apt/lists/*

RUN curl -sSf https://get.kraftkit.sh | sh -s -- -y && kraft version

# node:22 doesn't exist; :21 is the highest published as of 2026-05.
RUN ( kraft pkg pull --plat fc --arch x86_64 unikraft.org/node:21 \
   || kraft pkg pull --plat fc --arch x86_64 unikraft.org/node:20 \
   || kraft pkg pull --plat fc --arch x86_64 unikraft.org/node:18 ) \
 && mkdir -p /tmp/uk-extract \
 && for blob in $(find /root/.local/share/kraftkit -type f); do \
      ft="$(file -b "$blob" 2>/dev/null || true)"; \
      case "$ft" in *"tar archive"*) tar -xf "$blob" -C /tmp/uk-extract 2>/dev/null || true ;; esac; \
    done \
 && cp /tmp/uk-extract/unikraft/bin/kernel /tmp/node-kernel \
 && file /tmp/node-kernel

# ----- Stage B: source the Linux Node binary + libs from alpine -------
FROM node:21-alpine AS node-src

# ----- Stage C: npm install lodash next to detonate.js ----------------
FROM node:21-alpine AS app-build
WORKDIR /staging/usr/src
COPY rootfs/detonate.js .
RUN npm init -y >/dev/null \
 && npm install --omit=dev --no-audit --no-fund --no-progress lodash@4 \
 && ls -lh detonate.js node_modules/lodash/package.json

# ----- Stage D: assemble the rootfs tree + cpio it --------------------
FROM alpine:3 AS rootfs-build
RUN apk add --no-cache cpio ca-certificates tzdata \
 && update-ca-certificates

RUN mkdir -p /staging/etc/ssl/certs \
              /staging/usr/bin \
              /staging/usr/lib \
              /staging/lib \
              /staging/usr/share/zoneinfo/Etc \
              /staging/usr/src \
              /staging/tmp

# Node binary + minimal musl runtime (mirrors the catalog Dockerfile)
COPY --from=node-src /usr/local/bin/node          /staging/usr/bin/node
COPY --from=node-src /lib/ld-musl-x86_64.so.1     /staging/lib/ld-musl-x86_64.so.1
COPY --from=node-src /usr/lib/libgcc_s.so.1       /staging/usr/lib/libgcc_s.so.1
COPY --from=node-src /usr/lib/libstdc++.so.6      /staging/usr/lib/libstdc++.so.6

# CA certs + UTC timezone (Node refuses TLS without certs)
RUN cp /usr/share/zoneinfo/Etc/UTC /staging/usr/share/zoneinfo/Etc/UTC \
 && ln -sf ../usr/share/zoneinfo/Etc/UTC /staging/etc/localtime \
 && echo "Etc/UTC" > /staging/etc/timezone \
 && cp /etc/ssl/certs/ca-certificates.crt /staging/etc/ssl/certs/ca-certificates.crt

# App: detonate.js + node_modules/lodash
COPY --from=app-build /staging/usr/src/detonate.js     /staging/usr/src/detonate.js
COPY --from=app-build /staging/usr/src/node_modules    /staging/usr/src/node_modules

RUN cd /staging \
 && find . -print0 | cpio -o -H newc --null > /tmp/rootfs.cpio \
 && ls -lh /tmp/rootfs.cpio \
 && echo "--- rootfs.cpio top-level entries ---" \
 && cpio -tv < /tmp/rootfs.cpio | head -25

# ----- Stage E: final runtime image -----------------------------------
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

COPY --from=uk-pull      /tmp/node-kernel  /opt/unikraft/node
COPY --from=rootfs-build /tmp/rootfs.cpio  /opt/unikraft/rootfs.cpio
COPY scripts/run_node_unikernel.sh /opt/run_node_unikernel.sh

RUN chmod +x /opt/run_node_unikernel.sh \
 && file /opt/unikraft/node \
 && ls -lh /opt/unikraft/node /opt/unikraft/rootfs.cpio

WORKDIR /opt
