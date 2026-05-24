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

# Per-instance unique names so concurrent jobs on the same runner
# don't stomp each other's tap / iptables rules.
inst_id="${INST_ID:-$$}"
tap_dev="tap-fc${inst_id}"
guest_ip="172.16.${inst_id:0:1}.2"
host_ip="172.16.${inst_id:0:1}.1"
guest_mac="02:FC:00:00:00:$(printf '%02x' $((inst_id % 256)))"

# Linux init-args separator: everything after " -- " on the kernel
# cmdline is passed to /init as argv. Our loader scans cmdline for
# `pkg=...` after the separator. The `ip=` arg before the separator
# is parsed by the kernel itself — autoconfigure eth0 with our
# static address before /init runs.
boot_args="${BOOT_ARGS:-console=ttyS0 reboot=k panic=1 root=/dev/ram0 rw pci=off ip=${guest_ip}::${host_ip}:255.255.255.0::eth0:off -- pkg=${package}}"

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
  # Best-effort tap teardown; container is ephemeral but be tidy
  ip link del "$tap_dev" 2>/dev/null || true
}
trap cleanup EXIT

# Set up TAP for the guest + NAT through the container's egress.
egress="$(ip route show default 2>/dev/null | awk '{print $5}' | head -1)"
[[ -z "$egress" ]] && egress=eth0

echo "--- network setup: tap=$tap_dev host=$host_ip guest=$guest_ip egress=$egress ---"
ip link del "$tap_dev" 2>/dev/null || true
ip tuntap add "$tap_dev" mode tap
ip addr add "${host_ip}/24" dev "$tap_dev"
ip link set "$tap_dev" up

# Enable forwarding + NAT. Some container fs's symlink /proc/sys to
# a read-only mount — fall back to sysctl if that's the case.
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null \
  || sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

iptables -t nat -A POSTROUTING -o "$egress" -j MASQUERADE 2>/dev/null || true
iptables -A FORWARD -i "$tap_dev" -o "$egress" -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -i "$egress" -o "$tap_dev" \
    -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
ip route show
ip addr show "$tap_dev" || true

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

# Wire up the virtio-net device backed by our tap. FC will expose it
# as `eth0` inside the guest; the kernel's `ip=` boot arg statically
# configures it before /init runs.
curl -fsS --unix-socket "$sock" -X PUT 'http://localhost/network-interfaces/eth0' \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg t "$tap_dev" --arg m "$guest_mac" \
        '{iface_id:"eth0", host_dev_name:$t, guest_mac:$m}')"

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
