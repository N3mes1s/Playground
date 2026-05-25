#!/usr/bin/env bash
# Detonate + verify one package, write structured result files.
# Safe to invoke concurrently with distinct INST_ID values.
#
# Usage: detonate_one.sh <package-spec> <inst_id>
#
# Writes (to $MATRIX_DIR, default /tmp/matrix):
#   <slug>.log           full stdout/stderr from run_detonation.sh
#   <slug>.fp.json       captured fingerprint (absent if no markers)
#   <slug>.status        one of PASS, DIFF, NEW, FAIL
#   <slug>.duration_ms   wall-clock ms for the detonation
#   <slug>.note          short human-readable explanation
#   <slug>.diff.json     baseline diff (only if a diff was computed)
#
# Always exits 0 — the aggregator decides overall pass/fail by
# reading .status files. This keeps `xargs -P` from aborting the
# whole batch when one package fails.

set -uo pipefail

spec="${1:?missing spec}"
inst_id="${2:?missing inst_id}"

matrix_dir="${MATRIX_DIR:-/tmp/matrix}"
kernel="${KERNEL:-/opt/guest/vmlinux}"
initrd="${INITRD:-/opt/guest/initrd.cpio}"
baselines_dir="${BASELINES_DIR:-/opt/baselines}"
detonator="${DETONATOR:-/opt/run_detonation.sh}"
differ="${DIFFER:-/opt/diff_fingerprint.py}"

mkdir -p "$matrix_dir"
slug="$(echo "$spec" | tr '/@:' '___')"
log="$matrix_dir/$slug.log"
fp="$matrix_dir/$slug.fp.json"
status_file="$matrix_dir/$slug.status"
note_file="$matrix_dir/$slug.note"
dur_file="$matrix_dir/$slug.duration_ms"

record() {
  echo "$1" > "$status_file"
  echo "${2:-}" > "$note_file"
}

t0=$(date +%s)
INST_ID="$inst_id" bash "$detonator" "$kernel" "$initrd" "$spec" \
  > "$log" 2>&1 || true
t1=$(date +%s)
echo $(( (t1 - t0) * 1000 )) > "$dur_file"

awk '/DETONATION_BEGIN/{p=1;next} /DETONATION_END/{exit} p' "$log" \
  | tr -d '\r' > "$fp.raw" || true

# Extract the DNS map (emitted between DNS_MAP_BEGIN/END markers
# after the fingerprint) so we can do hostname-based baselining.
dns_map="$matrix_dir/$slug.dns.json"
awk '/DNS_MAP_BEGIN/{p=1;next} /DNS_MAP_END/{exit} p' "$log" \
  | tr -d '\r' > "$dns_map" || true
[[ -s "$dns_map" ]] || echo '{}' > "$dns_map"

if [[ ! -s "$fp.raw" ]]; then
  record FAIL "no DETONATION markers"
  exit 0
fi

if ! jq '. + { verdict: (if .exit_status == 0 then "OK" else "FAIL" end) }' \
       "$fp.raw" > "$fp" 2>/dev/null; then
  record FAIL "fingerprint not valid JSON"
  exit 0
fi

exit_status=$(jq -r '.exit_status' "$fp")
if [[ "$exit_status" != "0" ]]; then
  record FAIL "npm exit=$exit_status"
  exit 0
fi

baseline="$baselines_dir/${spec}.json"
if [[ ! -f "$baseline" ]]; then
  record NEW "no baseline — commit one after review"
  exit 0
fi

if python3 "$differ" --dns-map "$dns_map" "$fp" "$baseline" \
     > "$matrix_dir/$slug.diff.json"; then
  record PASS ""
else
  ue=$(jq -r '.unknown_execve_targets | length' "$matrix_dir/$slug.diff.json")
  uc=$(jq -r '.unknown_connect_peers | length' "$matrix_dir/$slug.diff.json")
  uo=$(jq -r '.unknown_openat_writes // [] | length' "$matrix_dir/$slug.diff.json" 2>/dev/null || echo 0)
  record DIFF "unknown execve=$ue connect=$uc openat=$uo"
fi

exit 0
