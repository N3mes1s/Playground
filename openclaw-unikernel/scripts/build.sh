#!/bin/bash
# Build the OpenClaw unikernel
#
# Usage:
#   ./scripts/build.sh          # Release build
#   ./scripts/build.sh debug    # Debug build
#   ./scripts/build.sh size     # Report binary size

set -e

MODE="${1:-release}"
TARGET="x86_64-unknown-none"

case "$MODE" in
    release)
        echo "Building OpenClaw Unikernel (release)..."
        cargo build --release --target "$TARGET" \
            -Zbuild-std=core,alloc,compiler_builtins \
            -Zbuild-std-features=compiler-builtins-mem

        BINARY="target/$TARGET/release/openclaw-unikernel"
        if [ -f "$BINARY" ]; then
            SIZE=$(stat -f%z "$BINARY" 2>/dev/null || stat -c%s "$BINARY" 2>/dev/null)
            echo ""
            echo "Build successful!"
            echo "  Binary: $BINARY"
            echo "  Size:   $(echo "scale=2; $SIZE / 1048576" | bc) MiB ($SIZE bytes)"
        fi
        ;;

    debug)
        echo "Building OpenClaw Unikernel (debug)..."
        cargo build --target "$TARGET" \
            -Zbuild-std=core,alloc,compiler_builtins \
            -Zbuild-std-features=compiler-builtins-mem
        echo "Build successful!"
        ;;

    size)
        BINARY="target/$TARGET/release/openclaw-unikernel"
        if [ -f "$BINARY" ]; then
            echo "Binary size analysis:"
            size "$BINARY" 2>/dev/null || true
            echo ""
            echo "Section sizes:"
            objdump -h "$BINARY" 2>/dev/null | grep -E '^\s+[0-9]' || true
        else
            echo "Release binary not found. Build first with: ./scripts/build.sh"
        fi
        ;;

    *)
        echo "Usage: $0 [release|debug|size]"
        exit 1
        ;;
esac
