#!/usr/bin/env bash
# Boot a Linux kernel + initrd under Firecracker via its REST API.
# Adapted from PR #18's run_unikernel.sh (Unikraft); same PTY trick
# for guest serial, same FC --log-path split. Differences:
#   - Linux-style boot_args (console=ttyS0 reboot=k panic=1)
#   - initrd_path is required, not optional
#   - mem_size_mib defaults to 512 (libbpf + maps + ringbuf)
#
# Usage: run_linux_guest.sh <kernel> <initrd> [grep-pattern]
#   grep-pattern defaults to "BPF_RESULT_END" (loader emits it)
#   WAIT_ITERS env var controls poll timeout in 0.1s units (default 600 == 60s)

set -euo pipefail

kernel="${1:?missing kernel path}"
initrd="${2:?missing initrd path}"
pattern="${3:-BPF_RESULT_END}"
wait_iters="${WAIT_ITERS:-600}"
boot_args="${BOOT_ARGS:-console=ttyS0 reboot=k panic=1 root=/dev/ram0 rw}"
mem_mib="${MEM_MIB:-512}"

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

# Wrap firecracker under `script` so it gets a PTY — guest serial is
# dropped otherwise (firecracker-microvm/firecracker#2729).
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

for _ in $(seq 1 "$wait_iters"); do
  if grep -qF "$pattern" "$serial_log" 2>/dev/null; then
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
echo "serial_log_bytes=$(stat -c%s "$serial_log" 2>/dev/null || echo 0)"

# Extract the JSON between BPF_RESULT_BEGIN/END markers (strip CR from PTY).
json="$(awk '/BPF_RESULT_BEGIN/{p=1; next} /BPF_RESULT_END/{p=0} p' "$serial_log" | tr -d '\r')"

if [[ -z "$json" ]]; then
  echo "ERROR: no BPF_RESULT markers in serial output" >&2
  exit 1
fi

echo "=== bpf result ==="
echo "$json" | jq . 2>/dev/null || echo "$json"

verdict="$(echo "$json" | jq -r '.verdict' 2>/dev/null || echo unknown)"
case "$verdict" in
  OK)   echo "VERDICT: OK";   exit 0 ;;
  FAIL) echo "VERDICT: FAIL"; exit 1 ;;
  *)    echo "VERDICT: unknown ($verdict)"; exit 2 ;;
esac
