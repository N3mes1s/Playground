#!/usr/bin/env bash
# Boot the Unikraft Node runtime under Firecracker with a CPIO initrd
# that contains detonate.js + node_modules/lodash. Wait for the
# DETONATE_JSON_BEGIN/END markers in the serial console, extract the
# JSON, return the verdict.
#
# Usage: run_node_unikernel.sh <kernel> <initrd>
#
# Env knobs:
#   BOOT_ARGS   default: "runtime/node -- node /detonate.js"
#   MEM_MIB     default: 256
#   WAIT_ITERS  default: 900 (== 90 s) — Node startup is much slower
#               than helloworld
#
# Same FC-on-CI workarounds as Stage 1 apply:
#   - util-linux `script` allocates a PTY so guest serial isn't dropped
#   - FC's own slog goes to --log-path, leaving the PTY for guest output

set -euo pipefail

kernel="${1:?missing kernel path}"
initrd="${2:?missing initrd path}"
# boot_args matches the form kraft produces for node:21 (confirmed via the
# multi-image smoke run): "kernel" as the app name, full path to the node
# binary inside the rootfs, full path to the script.
boot_args="${BOOT_ARGS:-kernel -- /usr/bin/node /usr/src/detonate.js}"
mem_mib="${MEM_MIB:-256}"
wait_iters="${WAIT_ITERS:-900}"

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

t0=$(date +%s%N)
curl -fsS --unix-socket "$sock" -X PUT 'http://localhost/actions' \
  -H 'Content-Type: application/json' \
  -d '{"action_type":"InstanceStart"}'

# Wait for the JSON-end marker
for _ in $(seq 1 "$wait_iters"); do
  if grep -qF 'DETONATE_JSON_END' "$serial_log" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
t1=$(date +%s%N)

echo "--- guest serial ---"
cat "$serial_log"
echo "--- firecracker internal log (tail) ---"
tail -30 "$fc_log" 2>/dev/null || true
echo "---"
echo "elapsed_ms=$(( (t1 - t0) / 1000000 ))"
echo "serial_log_bytes=$(stat -c%s "$serial_log" 2>/dev/null || echo 0)"

# Extract JSON between markers (strip CR from PTY output)
json="$(awk '/DETONATE_JSON_BEGIN/{p=1; next} /DETONATE_JSON_END/{p=0} p' "$serial_log" | tr -d '\r')"

if [[ -z "$json" ]]; then
  echo "ERROR: no DETONATE_JSON_BEGIN/END markers found in serial output" >&2
  exit 1
fi

echo "=== detonate result ==="
echo "$json" | jq .

verdict="$(echo "$json" | jq -r '.verdict')"
case "$verdict" in
  OK)   echo "VERDICT: OK";   exit 0 ;;
  FAIL) echo "VERDICT: FAIL"; exit 1 ;;
  *)    echo "VERDICT: unknown ($verdict)"; exit 2 ;;
esac
