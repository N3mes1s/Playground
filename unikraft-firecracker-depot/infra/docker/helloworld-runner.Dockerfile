# syntax=docker/dockerfile:1.7
#
# Cached runner image for the Unikraft helloworld experiment.
# Bakes in:
#   - firecracker v1.15.0
#   - util-linux (for `script` — needed to allocate a PTY for FC stdout)
#   - the Unikraft helloworld unikernel ELF at /opt/unikraft/helloworld
#   - the boot script at /opt/run_unikernel.sh
#
# Build context: the experiment root (unikraft-firecracker-depot/).
# Built via `depot build --save --save-tag helloworld-runner-latest`
# and consumed by .depot/workflows/run-stage1-cached.yml via
# `container: image: registry.depot.dev/<PROJECT_ID>:helloworld-runner-latest`.
#
# archive.ubuntu.com is Cloudflare-blocked from Depot egress, so the
# apt sources are rewritten to mirror.facebook.net before apt-get.

# ----- Stage 1: pull the Unikraft helloworld kernel via kraft ---------
FROM buildpack-deps:24.04-scm AS uk-pull

ENV DEBIAN_FRONTEND=noninteractive

RUN sed -i 's|http://archive.ubuntu.com/ubuntu|http://mirror.facebook.net/ubuntu|g; s|http://security.ubuntu.com/ubuntu|http://mirror.facebook.net/ubuntu|g' \
        /etc/apt/sources.list /etc/apt/sources.list.d/*.sources 2>/dev/null || true \
 && apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl file \
 && rm -rf /var/lib/apt/lists/*

RUN curl -sSf https://get.kraftkit.sh | sh -s -- -y \
 && kraft version

RUN kraft pkg pull --plat fc --arch x86_64 unikraft.org/helloworld:latest \
 && mkdir -p /tmp/uk-extract \
 && for blob in $(find /root/.local/share/kraftkit -type f); do \
      ft="$(file -b "$blob" 2>/dev/null || true)"; \
      case "$ft" in *"tar archive"*) tar -xf "$blob" -C /tmp/uk-extract 2>/dev/null || true ;; esac; \
    done \
 && cp /tmp/uk-extract/unikraft/bin/kernel /tmp/uk-kernel \
 && file /tmp/uk-kernel

# ----- Stage 2: final runtime image -----------------------------------
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

# Bake the unikernel kernel and the boot script into the image.
COPY --from=uk-pull /tmp/uk-kernel /opt/unikraft/helloworld
COPY scripts/run_unikernel.sh /opt/run_unikernel.sh
RUN chmod +x /opt/run_unikernel.sh \
 && file /opt/unikraft/helloworld \
 && ls -lh /opt/unikraft/helloworld /opt/run_unikernel.sh

WORKDIR /opt
