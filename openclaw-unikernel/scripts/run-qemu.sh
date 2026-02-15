#!/bin/bash
# Run the OpenClaw unikernel in QEMU
#
# Usage: ./scripts/run-qemu.sh [path-to-binary]
#
# The binary is passed as the first argument by `cargo run`.

set -e

BINARY="${1:-target/x86_64-unknown-none/release/openclaw-unikernel}"

if [ ! -f "$BINARY" ]; then
    echo "Error: Binary not found at $BINARY"
    echo "Build first with: cargo build --release"
    exit 1
fi

echo "Starting OpenClaw Unikernel in QEMU..."
echo "  Binary: $BINARY"
echo "  Memory: 128M"
echo "  Network: User-mode (SLIRP)"
echo "  Serial: stdio"
echo ""
echo "Press Ctrl-A X to exit QEMU"
echo ""

exec qemu-system-x86_64 \
    -kernel "$BINARY" \
    -m 128M \
    -serial stdio \
    -display none \
    -no-reboot \
    -cpu qemu64 \
    -smp 1 \
    -netdev user,id=net0,hostfwd=tcp::3000-:3000 \
    -device virtio-net-pci,netdev=net0 \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04
