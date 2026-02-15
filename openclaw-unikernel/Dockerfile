# OpenClaw Unikernel — Build Container
#
# Builds the unikernel binary in a Rust nightly container.
# The output is a raw binary suitable for QEMU or bare-metal boot.
#
# Build:  docker build -t openclaw-unikernel .
# Extract: docker cp $(docker create openclaw-unikernel):/out/openclaw-unikernel .
# Run:    qemu-system-x86_64 -kernel openclaw-unikernel -m 128M -serial stdio -display none

FROM rust:latest AS builder

# Install nightly toolchain with required components
RUN rustup toolchain install nightly --component rust-src,llvm-tools
RUN rustup default nightly

WORKDIR /build

# Copy source
COPY Cargo.toml Cargo.lock* rust-toolchain.toml linker.ld ./
COPY .cargo/ .cargo/
COPY src/ src/

# Build the unikernel
RUN cargo build --release --target x86_64-unknown-none \
    -Zbuild-std=core,alloc,compiler_builtins \
    -Zbuild-std-features=compiler-builtins-mem

# Extract binary
FROM scratch AS output
COPY --from=builder /build/target/x86_64-unknown-none/release/openclaw-unikernel /out/openclaw-unikernel
