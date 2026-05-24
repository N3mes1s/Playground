# syntax=docker/dockerfile:1.7
#
# CI base image for the unikraft-firecracker-depot experiment.
#
# Provides:
#   - firecracker v1.15.0
#   - kraft (KraftKit) CLI
#   - docker CLI (static binary)
#   - depot CLI
#   - iproute2, iptables, dnsmasq-base (kept for future tap-networked stages)
#
# archive.ubuntu.com is Cloudflare-blocked from Depot runners
# (HTTP 1010), so we point apt at mirror.facebook.net before
# installing anything.

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN sed -i 's|http://archive.ubuntu.com/ubuntu|http://mirror.facebook.net/ubuntu|g; s|http://security.ubuntu.com/ubuntu|http://mirror.facebook.net/ubuntu|g' \
        /etc/apt/sources.list /etc/apt/sources.list.d/*.sources 2>/dev/null || true \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        jq \
        xz-utils \
        tar \
        gzip \
        zstd \
        lz4 \
        lzop \
        iproute2 \
        iptables \
        dnsmasq-base \
        uuid-runtime \
 && rm -rf /var/lib/apt/lists/*

# Firecracker
ARG FIRECRACKER_VERSION=v1.15.0
RUN set -eux; \
    arch="$(uname -m)"; \
    url="https://github.com/firecracker-microvm/firecracker/releases/download/${FIRECRACKER_VERSION}/firecracker-${FIRECRACKER_VERSION}-${arch}.tgz"; \
    curl -fsSL "$url" -o /tmp/fc.tgz; \
    tar -xzf /tmp/fc.tgz -C /tmp; \
    install -m 0755 "/tmp/release-${FIRECRACKER_VERSION}-${arch}/firecracker-${FIRECRACKER_VERSION}-${arch}" /usr/local/bin/firecracker; \
    install -m 0755 "/tmp/release-${FIRECRACKER_VERSION}-${arch}/jailer-${FIRECRACKER_VERSION}-${arch}"     /usr/local/bin/jailer; \
    rm -rf /tmp/fc.tgz /tmp/release-${FIRECRACKER_VERSION}-${arch}; \
    firecracker --version

# Docker CLI (static)
ARG DOCKER_VERSION=27.3.1
RUN set -eux; \
    curl -fsSL "https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_VERSION}.tgz" -o /tmp/docker.tgz; \
    tar -xzf /tmp/docker.tgz -C /tmp; \
    install -m 0755 /tmp/docker/docker /usr/local/bin/docker; \
    rm -rf /tmp/docker /tmp/docker.tgz; \
    docker --version

# KraftKit (kraft) CLI
RUN set -eux; \
    curl -sSf https://get.kraftkit.sh | sh -s -- -y; \
    kraft version || true

# Depot CLI
RUN set -eux; \
    curl -L https://depot.dev/install-cli.sh | sh; \
    /root/.depot/bin/depot --version; \
    ln -s /root/.depot/bin/depot /usr/local/bin/depot

WORKDIR /workspace
