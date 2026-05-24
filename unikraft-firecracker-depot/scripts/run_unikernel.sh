#!/usr/bin/env bash
# Boot a Unikraft unikernel under Firecracker via its REST API.
# Stage 1: no rootfs, no networking. Expects the unikernel to
# self-halt after printing its banner.
#
# Usage: run_unikernel.sh <kernel-path> [grep-pattern]
#   grep-pattern defaults to "Hello world"
#   WAIT_ITERS env var controls poll timeout (default 300 == 30s)
#
# Firecracker wires the guest's ttyS0 to its own stdout. When FC is
# launched from a script with stdout redirected to a regular file,
# guest output is often dropped or buffered (see firecracker-microvm
# /firecracker#2729). We work around this by allocating a PTY for FC
# via util-linux `script`, and we point FC's own structured logs at a
# separate file via --log-path so the captured stdout is purely the
# guest serial console.

set -euo pipefail

kernel="${1:?missing kernel path}"
pattern="${2:-Hello world}"
wait_iters="${WAIT_ITERS:-300}"
# Unikraft boot args use the "<app_name> -- <app_args>" convention.
# Linux-style args like "console=ttyS0" silently break Unikraft boot.
boot_args="${BOOT_ARGS:-kernel -- }"
mem_mib="${MEM_MIB:-64}"

if [[ ! -f "$kernel" ]]; then
  echo "ERROR: kernel not found at $kernel" >&2
  exit 2
fi

sock="$(mktemp -u /tmp/fc-XXXXXX.sock)"
serial_log="$(mktemp -t fc-serial-XXXXXX)"
fc_log="$(mktemp -t fc-internal-XXXXXX)"
: > "$serial_log"
: > "$fc_log"

cleanup() {
  if [[ -n "${fc_pid:-}" ]] && kill -0 "$fc_pid" 2>/dev/null; then
    kill "$fc_pid" 2>/dev/null || true
    wait "$fc_pid" 2>/dev/null || true
  fi
  if [[ -n "${script_pid:-}" ]] && kill -0 "$script_pid" 2>/dev/null; then
    kill "$script_pid" 2>/dev/null || true
    wait "$script_pid" 2>/dev/null || true
  fi
  rm -f "$sock"
}
trap cleanup EXIT

# Launch firecracker under `script` so it sees a PTY for stdout.
# --log-path routes FC's own slog away from stdout, leaving the PTY
# for guest serial only.
if command -v script >/dev/null; then
  script -qfec "firecracker --api-sock '$sock' --log-path '$fc_log' --level Info" \
    "$serial_log" </dev/null >/dev/null 2>&1 &
  script_pid=$!
  # Find firecracker's actual pid via the api-sock for cleanup
  for _ in $(seq 1 50); do
    fc_pid="$(pgrep -P "$script_pid" firecracker 2>/dev/null | head -1 || true)"
    [[ -n "$fc_pid" ]] && break
    sleep 0.1
  done
else
  echo "WARN: util-linux 'script' not available; falling back to direct stdout redirect" >&2
  firecracker --api-sock "$sock" --log-path "$fc_log" --level Info \
    </dev/null >"$serial_log" 2>&1 &
  fc_pid=$!
fi

# Wait up to 5s for the API socket to appear
for _ in $(seq 1 50); do
  [[ -S "$sock" ]] && break
  sleep 0.1
done
if [[ ! -S "$sock" ]]; then
  echo "ERROR: firecracker did not create $sock" >&2
  echo "--- fc internal log ---" >&2
  cat "$fc_log" >&2 || true
  echo "--- captured stdout (PTY) ---" >&2
  cat "$serial_log" >&2 || true
  exit 3
fi

# Send /machine-config BEFORE /boot-source — that's the order kraft uses
# and the order Unikraft-on-FC expects.
curl -fsS --unix-socket "$sock" -X PUT \
  'http://localhost/machine-config' \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --argjson m "$mem_mib" '{vcpu_count:1, mem_size_mib:$m, smt:false}')"

curl -fsS --unix-socket "$sock" -X PUT \
  'http://localhost/boot-source' \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg k "$kernel" --arg b "$boot_args" '{kernel_image_path:$k, boot_args:$b}')"

t0=$(date +%s%N)
curl -fsS --unix-socket "$sock" -X PUT \
  'http://localhost/actions' \
  -H 'Content-Type: application/json' \
  -d '{"action_type":"InstanceStart"}'

# Wait for the banner to land on the captured serial log
for _ in $(seq 1 "$wait_iters"); do
  if grep -qF "$pattern" "$serial_log" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
t1=$(date +%s%N)

echo "--- guest serial (firecracker stdout via PTY) ---"
cat "$serial_log" || true
echo "--- firecracker internal log ---"
cat "$fc_log" || true
echo "---"
echo "elapsed_ms=$(( (t1 - t0) / 1000000 ))"
echo "serial_log_bytes=$(stat -c%s "$serial_log" 2>/dev/null || echo 0)"

if ! grep -qF "$pattern" "$serial_log"; then
  echo "ERROR: unikernel did not print expected pattern '$pattern' within ${wait_iters} deciseconds" >&2
  echo "--- kernel info ---" >&2
  file "$kernel" >&2 || true
  exit 1
fi

echo "OK: matched pattern '$pattern'"
