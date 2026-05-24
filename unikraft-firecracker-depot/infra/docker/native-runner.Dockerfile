# syntax=docker/dockerfile:1.7
#
# Cached runner image for the aegis-probe native Unikraft unikernel.
#
# Unlike the bin-compat path (helloworld-runner.Dockerfile pulls
# prebuilt unikernels from unikraft.org), this Dockerfile *builds*
# the unikernel from sources via `kraft build`, linking main.c
# directly into the unikernel ELF. No rootfs needed at boot.
#
# Final image layout:
#   /opt/unikraft/aegis-probe       — the built unikernel ELF
#   /opt/run_unikernel.sh           — same FC-REST boot script as Stage 1
#   /usr/local/bin/firecracker
#
# Built via build-native-unikernel.yml; consumed by run-native-cached.yml.

# ----- Stage A: kraft build the unikernel ------------------------------
FROM buildpack-deps:24.04-scm AS uk-build

ENV DEBIAN_FRONTEND=noninteractive

# kraft build needs a real C toolchain plus kconfig dependencies. The
# kraftkit installer prints these as "recommended"; without them the
# build silently produces incomplete artifacts.
RUN sed -i 's|http://archive.ubuntu.com/ubuntu|http://mirror.facebook.net/ubuntu|g; s|http://security.ubuntu.com/ubuntu|http://mirror.facebook.net/ubuntu|g' \
        /etc/apt/sources.list /etc/apt/sources.list.d/*.sources 2>/dev/null || true \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates curl jq file \
        build-essential \
        bison flex libncurses-dev \
        unzip uuid-runtime socat \
        gcc-x86-64-linux-gnu \
 && rm -rf /var/lib/apt/lists/*

RUN curl -sSf https://get.kraftkit.sh | sh -s -- -y && kraft version

WORKDIR /app
COPY apps/aegis-probe/ ./

# `kraft build` resolves the Kraftfile, clones unikraft@stable into
# workdir/unikraft, generates a defconfig, and runs make. Output ELF
# lands at workdir/build/<name>_<plat>-<arch>.
#
# --no-update keeps the build hermetic; --no-cache forces a clean
# build (depot-build-push caches Docker layers, so we still get
# caching across runs without kraft's own per-build cache).
RUN kraft build --plat fc --arch x86_64 --no-update 2>&1 | tail -200 \
 && echo "--- build output tree ---" \
 && find workdir/build -maxdepth 2 -type f -printf '%s\t%p\n' 2>/dev/null | sort -rn | head -20 \
 && echo "--- candidate unikernel ELFs ---" \
 && find workdir/build -maxdepth 2 -type f \( -name 'aegis-probe*' -o -name '*_fc-x86_64*' \) | head -10

# Find the built unikernel — kraft names it deterministically but the
# exact path can vary by version. Prefer non-debug variants.
RUN bin="" \
 && for cand in \
      workdir/build/aegis-probe_fc-x86_64 \
      workdir/build/aegis-probe_firecracker-x86_64 \
      workdir/build/aegis-probe_kvm-x86_64; do \
      [[ -f "$cand" ]] && bin="$cand" && break; \
    done; \
    if [[ -z "$bin" ]]; then \
      bin="$(find workdir/build -maxdepth 2 -type f \
              \( -name 'aegis-probe*' -o -name '*_fc-x86_64*' \) \
              ! -name '*.dbg' ! -name '*.o' ! -name '*.gz' \
              | head -1)"; \
    fi; \
    if [[ -z "$bin" ]]; then \
      echo "ERROR: kraft build did not produce a unikernel binary" >&2; \
      find workdir/build -maxdepth 3 -type f >&2 | head -50; \
      exit 1; \
    fi; \
    cp "$bin" /tmp/aegis-probe \
 && file /tmp/aegis-probe \
 && ls -lh /tmp/aegis-probe

# ----- Stage B: final runtime image -----------------------------------
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

COPY --from=uk-build /tmp/aegis-probe /opt/unikraft/aegis-probe
COPY scripts/run_unikernel.sh        /opt/run_unikernel.sh

RUN chmod +x /opt/run_unikernel.sh \
 && file /opt/unikraft/aegis-probe \
 && ls -lh /opt/unikraft/aegis-probe /opt/run_unikernel.sh

WORKDIR /opt
