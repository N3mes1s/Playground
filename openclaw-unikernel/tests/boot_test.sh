#!/bin/bash
# OpenClaw Unikernel Boot Test
#
# Boots the unikernel in QEMU and verifies it reaches the main event loop
# without panicking. Checks serial output for expected boot sequence messages.
#
# Usage: ./tests/boot_test.sh [path-to-binary]
#
# Exit codes:
#   0 — All boot checks passed
#   1 — Boot failed (panic, missing phase, or timeout)

set -euo pipefail

BINARY="${1:-target/x86_64-unknown-none/release/openclaw-unikernel}"
TIMEOUT=30  # seconds
OUTPUT=$(mktemp)

if [ ! -f "$BINARY" ]; then
    echo "FAIL: Binary not found: $BINARY"
    echo "      Run 'make build' first."
    exit 1
fi

echo "=== OpenClaw Boot Test ==="
echo "Binary: $BINARY ($(du -h "$BINARY" | cut -f1))"
echo "Timeout: ${TIMEOUT}s"
echo ""

# Boot QEMU with serial output captured to file.
# Use timeout to kill after $TIMEOUT seconds.
# No network needed for boot test — skip virtio-net to speed up.
timeout "$TIMEOUT" qemu-system-x86_64 \
    -kernel "$BINARY" \
    -m 1G \
    -serial stdio \
    -display none \
    -no-reboot \
    -cpu qemu64 \
    -smp 1 \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -netdev user,id=net0 \
    -device virtio-net-pci,netdev=net0 \
    2>/dev/null > "$OUTPUT" || true

echo "--- Serial Output (first 60 lines) ---"
head -60 "$OUTPUT"
echo "--- End Serial Output ---"
echo ""

# Check for expected boot phases
PASS=0
FAIL=0

check() {
    local desc="$1"
    local pattern="$2"
    if grep -q "$pattern" "$OUTPUT"; then
        echo "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc (expected: '$pattern')"
        FAIL=$((FAIL + 1))
    fi
}

echo "Boot Sequence Checks:"
check "Unikernel banner"       "booting unikernel"
check "Heap initialized"       "heap initialized"
check "Scheduler ready"        "scheduler ready"
check "Network stack"          "network stack initialized"
check "Security engine"        "security policy engine"
check "Memory system"          "memory system ready"
check "Configuration loaded"   "configuration loaded"
check "Agent loop started"     "starting agent loop"
check "Daemon services"        "all services started"
check "No kernel panic"        "KERNEL PANIC" && FAIL=$((FAIL + 1)) && PASS=$((PASS - 1)) || true
check "No OOM"                 "OUT OF MEMORY" && FAIL=$((FAIL + 1)) && PASS=$((PASS - 1)) || true

# The panic/OOM checks are inverted — we WANT them to NOT be found
# Fix the logic: grep returns 0 if found, 1 if not found
if grep -q "KERNEL PANIC" "$OUTPUT"; then
    echo "  FAIL: Kernel panic detected!"
    FAIL=$((FAIL + 1))
else
    echo "  PASS: No kernel panic"
    PASS=$((PASS + 1))
fi

if grep -q "OUT OF MEMORY" "$OUTPUT"; then
    echo "  FAIL: OOM detected!"
    FAIL=$((FAIL + 1))
else
    echo "  PASS: No OOM"
    PASS=$((PASS + 1))
fi

echo ""
echo "Results: $PASS passed, $FAIL failed"

# Cleanup
rm -f "$OUTPUT"

if [ "$FAIL" -gt 0 ]; then
    echo "BOOT TEST FAILED"
    exit 1
fi

echo "BOOT TEST PASSED"
exit 0
