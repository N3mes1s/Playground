#!/usr/bin/env bash
#
# End-to-end carve demo on a real GitHub project (BurntSushi/aho-corasick),
# proving the three claims:
#   1. DFUG     — extract what dependency code the product actually uses.
#   2. carve    — vendor + agent-slice down to ONLY that code, still compiling,
#                 changing NO project source (only adding the vendored part).
#   3. impact   — show whether a dependency update touches the code we use.
#
# Requires: cargo (online), and carve built in ../ (cargo build --manifest-path ../Cargo.toml).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CARVE="$HERE/../target/debug/carve"
WORK="${WORK:-/tmp/carve-demo}"
PROJECT="$WORK/aho-corasick"

echo "==> building carve"
cargo build --manifest-path "$HERE/../Cargo.toml" -q

echo "==> cloning a real project"
rm -rf "$PROJECT"; mkdir -p "$WORK"
git clone --depth 1 https://github.com/BurntSushi/aho-corasick.git "$PROJECT"

echo "==> baseline build (also populates the registry source cache carve reads)"
( cd "$PROJECT" && cargo build -q )

MAN="$PROJECT/Cargo.toml"

echo; echo "### 1. Dependency Functional Usage Graph"
"$CARVE" analyze --manifest-path "$MAN"

echo; echo "### 2a. Vendor all direct deps verbatim + wire the reversible patch"
"$CARVE" vendor-all --manifest-path "$MAN" --apply

echo; echo "### 2b. Rebuild against the vendored copy — NOTE: only Cargo.toml changed"
( cd "$PROJECT" && git --no-pager diff --stat && cargo build -q && echo "build OK against vendored deps" )

echo; echo "### 2c. Agent slices the vendored crate to only what we need (verify-gated)"
"$CARVE" slice memchr --manifest-path "$MAN"
( cd "$PROJECT" && cargo build -q && echo "build OK against SLICED deps" )
"$CARVE" verify --manifest-path "$MAN"

echo; echo "### 3. Would a dependency update touch us?"
"$CARVE" impact memchr --to 2.6.0 --manifest-path "$MAN"

echo; echo "### (reverse it — fully lossless)"
"$CARVE" restore memchr --manifest-path "$MAN"
( cd "$PROJECT" && cargo build -q && echo "build OK back on upstream dep" )

echo; echo "done."
