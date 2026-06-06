#!/usr/bin/env bash
# carve benchmark — data collection.
#
# For a corpus of real Rust projects, capture everything the verifier needs to
# measure noise reduction and check for false clears, WITHOUT re-running cargo
# during analysis (so results are reproducible from the saved JSON):
#   - audit.json      : `cargo audit --json` (the version-match baseline)
#   - triage.vex.json : `carve triage --vex` (carve's per-finding verdicts)
#   - meta.json       : `cargo metadata --locked` (the independent ground-truth
#                       resolve graph the verifier re-derives presence/runtime from)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
DATA="$HERE/data"
C="${CARVE_BIN:-$HERE/../target/release/carve}"
DB="${ADVISORY_DB:-/tmp/advisory-db}"
AUDIT="$(command -v cargo-audit || echo "$HOME/.cargo/bin/cargo-audit")"
WORK="${BENCH_WORK:-/tmp/carve-bench-corpus}"
rm -rf "$DATA"; mkdir -p "$DATA" "$WORK"

[ -d "$DB" ] || git clone --depth 1 https://github.com/rustsec/advisory-db.git "$DB" >/dev/null 2>&1

# name|git-url|ref   (ref empty = default branch). Older tags pin vulnerable deps
# so the 2026/older advisories actually fire; current mains add clean-tree cases.
repos=(
  "gitui-v0.22.1|https://github.com/gitui-org/gitui.git|v0.22.1"
  "delta-0.13.0|https://github.com/dandavison/delta.git|0.13.0"
  "starship-v1.10.3|https://github.com/starship/starship.git|v1.10.3"
  "mdbook-v0.4.21|https://github.com/rust-lang/mdBook.git|v0.4.21"
  "zoxide-v0.8.3|https://github.com/ajeetdsouza/zoxide.git|v0.8.3"
  "delta|https://github.com/dandavison/delta.git|"
  "bandwhich|https://github.com/imsnif/bandwhich.git|"
)

for entry in "${repos[@]}"; do
  IFS='|' read -r name url ref <<<"$entry"
  echo "=== $name ==="
  dir="$WORK/$name"; out="$DATA/$name"; mkdir -p "$out"; rm -rf "$dir"
  if [ -n "$ref" ]; then
    git clone --depth 1 --branch "$ref" "$url" "$dir" >/dev/null 2>&1 || { echo "  clone FAIL"; continue; }
  else
    git clone --depth 1 "$url" "$dir" >/dev/null 2>&1 || { echo "  clone FAIL"; continue; }
  fi
  [ -f "$dir/Cargo.lock" ] || { echo "  no Cargo.lock — skip"; continue; }
  ( cd "$dir" && cargo fetch --locked >/dev/null 2>&1 ) || echo "  fetch warn (continuing)"
  ( cd "$dir" && git checkout -- Cargo.lock 2>/dev/null )
  "$AUDIT" audit --db "$DB" -n -f "$dir/Cargo.lock" --json > "$out/audit.json" 2>/dev/null
  ( cd "$dir" && git checkout -- Cargo.lock 2>/dev/null )
  "$C" triage "$out/audit.json" --manifest-path "$dir/Cargo.toml" --vex > "$out/triage.vex.json" 2>"$out/triage.err"
  ( cd "$dir" && git checkout -- Cargo.lock 2>/dev/null )
  ( cd "$dir" && cargo metadata --format-version 1 --locked > "$out/meta.json" 2>/dev/null )
  n=$(python3 -c "import json;d=json.load(open('$out/audit.json'));print(d['vulnerabilities']['count']+sum(len(x) for x in d.get('warnings',{}).values()))" 2>/dev/null || echo "?")
  echo "  findings=$n  vex=$(wc -c < "$out/triage.vex.json" 2>/dev/null)B"
done
echo "RUN_DONE"
