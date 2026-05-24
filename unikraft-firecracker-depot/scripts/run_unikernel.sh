#!/usr/bin/env bash
# Boot a Unikraft unikernel under Firecracker via its REST API.
# Stage 1: no rootfs, no networking. Expects the unikernel to
# self-halt after printing its banner.
#
# Usage: run_unikernel.sh <kernel-path> [grep-pattern]
#   grep-pattern defaults to "hello" (case-insensitive)

set -euo pipefail

kernel="${1:?missing kernel path}"
pattern="${2:-hello}"

if [[ ! -f "$kernel" ]]; then
  echo "ERROR: kernel not found at $kernel" >&2
  exit 2
fi

sock="$(mktemp -u /tmp/fc-XXXXXX.sock)"
log="$(mktemp -t fc-log-XXXXXX)"

cleanup() {
  if [[ -n "${fc_pid:-}" ]] && kill -0 "$fc_pid" 2>/dev/null; then
    kill "$fc_pid" 2>/dev/null || true
    wait "$fc_pid" 2>/dev/null || true
  fi
  rm -f "$sock" "$log"
}
trap cleanup EXIT

firecracker --api-sock "$sock" >"$log" 2>&1 &
fc_pid=$!

# Wait up to 5s for the API socket to appear
for _ in $(seq 1 50); do
  [[ -S "$sock" ]] && break
  sleep 0.1
done
if [[ ! -S "$sock" ]]; then
  echo "ERROR: firecracker did not create $sock" >&2
  cat "$log" >&2
  exit 3
fi

curl -fsS --unix-socket "$sock" -X PUT \
  'http://localhost/boot-source' \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg k "$kernel" '{kernel_image_path:$k, boot_args:"console=ttyS0 reboot=k panic=1"}')"

curl -fsS --unix-socket "$sock" -X PUT \
  'http://localhost/machine-config' \
  -H 'Content-Type: application/json' \
  -d '{"vcpu_count":1,"mem_size_mib":64,"smt":false}'

t0=$(date +%s%N)
curl -fsS --unix-socket "$sock" -X PUT \
  'http://localhost/actions' \
  -H 'Content-Type: application/json' \
  -d '{"action_type":"InstanceStart"}'

# Wait for the banner to land on the serial log (or 5s, whichever first)
for _ in $(seq 1 50); do
  if grep -qi "$pattern" "$log" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
t1=$(date +%s%N)

echo "--- firecracker stdout/stderr ---"
cat "$log"
echo "---"
echo "elapsed_ms=$(( (t1 - t0) / 1000000 ))"

if ! grep -qi "$pattern" "$log"; then
  echo "ERROR: unikernel did not print expected pattern '$pattern'" >&2
  exit 1
fi

echo "OK: matched pattern '$pattern'"
