#!/usr/bin/env bash
# Boot the detonation guest under Firecracker. Adapted from PR #19's
# run_linux_guest.sh — same PTY trick, same --log-path split for FC's
# own slog, different marker pattern and a way to pass the target
# package via the kernel cmdline.
#
# Usage: run_detonation.sh <kernel> <initrd> [package-spec]
#   package-spec defaults to lodash@4.17.21 (Stage 1 acceptance)
#   WAIT_ITERS env var = poll timeout in 0.1s units (default 1200 == 120s)

set -euo pipefail

kernel="${1:?missing kernel path}"
initrd="${2:?missing initrd path}"
package="${3:-lodash@4.17.21}"
wait_iters="${WAIT_ITERS:-1200}"
mem_mib="${MEM_MIB:-1024}"

# Linux init-args separator: everything after " -- " on the kernel
# cmdline is passed to /init as argv. Our loader scans cmdline for
# `pkg=...` after the separator.
boot_args="${BOOT_ARGS:-console=ttyS0 reboot=k panic=1 root=/dev/ram0 rw pci=off -- pkg=${package}}"

for f in "$kernel" "$initrd"; do
  if [[ ! -f "$f" ]]; then
    echo "ERROR: required file not found: $f" >&2
    exit 2
  fi
done

sock="$(mktemp -u /tmp/fc-XXXXXX.sock)"
serial_log="$(mktemp -t fc-serial-XXXXXX)"
fc_log="$(mktemp -t fc-internal-XXXXXX)"
: > "$serial_log"
: > "$fc_log"

cleanup() {
  for pid in "${fc_pid:-}" "${script_pid:-}"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  rm -f "$sock"
}
trap cleanup EXIT

# PTY-wrap FC so guest serial isn't dropped (firecracker#2729).
script -qfec "firecracker --api-sock '$sock' --log-path '$fc_log' --level Info" \
  "$serial_log" </dev/null >/dev/null 2>&1 &
script_pid=$!

for _ in $(seq 1 50); do
  fc_pid="$(pgrep -P "$script_pid" firecracker 2>/dev/null | head -1 || true)"
  [[ -n "$fc_pid" ]] && break
  sleep 0.1
done

for _ in $(seq 1 50); do
  [[ -S "$sock" ]] && break
  sleep 0.1
done
if [[ ! -S "$sock" ]]; then
  echo "ERROR: firecracker did not create $sock" >&2
  cat "$fc_log" >&2 || true
  exit 3
fi

curl -fsS --unix-socket "$sock" -X PUT 'http://localhost/machine-config' \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --argjson m "$mem_mib" '{vcpu_count:1, mem_size_mib:$m, smt:false}')"

curl -fsS --unix-socket "$sock" -X PUT 'http://localhost/boot-source' \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg k "$kernel" --arg i "$initrd" --arg b "$boot_args" \
        '{kernel_image_path:$k, initrd_path:$i, boot_args:$b}')"

# FC needs a virtio-net device for the guest to do DNS / TCP. Stage 1
# uses host-side bridged networking via a TAP device — but Depot's
# job container has no network policy that lets the guest reach
# registry.npmjs.org. Defer real network setup to Stage 2; for now
# the npm install will fail with ENETUNREACH and we'll see that in
# the fingerprint (which is useful — it proves the BPF probe captures
# the connect attempts).

t0=$(date +%s%N)
curl -fsS --unix-socket "$sock" -X PUT 'http://localhost/actions' \
  -H 'Content-Type: application/json' \
  -d '{"action_type":"InstanceStart"}'

for _ in $(seq 1 "$wait_iters"); do
  if grep -qF 'DETONATION_END' "$serial_log" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
t1=$(date +%s%N)

echo "--- guest serial ---"
cat "$serial_log" 2>/dev/null || true
echo "--- firecracker internal log (tail) ---"
tail -30 "$fc_log" 2>/dev/null || true
echo "---"
echo "elapsed_ms=$(( (t1 - t0) / 1000000 ))"

json="$(awk '/DETONATION_BEGIN/{p=1; next} /DETONATION_END/{p=0} p' "$serial_log" | tr -d '\r' | tr -d '\n')"

if [[ -z "$json" ]]; then
  echo "ERROR: no DETONATION_BEGIN/END markers in serial output" >&2
  exit 1
fi

echo "=== fingerprint ==="
echo "$json" | jq . 2>/dev/null || echo "$json"

# Stage 1 success criterion: JSON is parseable and present. Verdict
# logic (compare to baseline) is Stage 2 work — implemented in
# scripts/diff_fingerprint.sh.
exit_status="$(echo "$json" | jq -r '.exit_status // -999' 2>/dev/null || echo -999)"
echo "exit_status_in_json=$exit_status"
exit 0
