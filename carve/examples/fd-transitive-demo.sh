#!/usr/bin/env bash
#
# Deep transitive demo on a complex real project (sharkdp/fd): vendor the WHOLE
# dependency closure (dependencies of dependencies) and rebuild from it.
#
# Optional: set ANTHROPIC_API_KEY to also exercise the LLM-driven slicer.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CARVE="$HERE/../target/debug/carve"
WORK="${WORK:-/tmp/carve-fd-demo}"
PROJECT="$WORK/fd"

echo "==> building carve"
cargo build --manifest-path "$HERE/../Cargo.toml" -q

echo "==> cloning fd (a deep dependency tree: regex/ignore/clap/rustix/…)"
rm -rf "$PROJECT"; mkdir -p "$WORK"
git clone --depth 1 https://github.com/sharkdp/fd.git "$PROJECT"

echo "==> baseline build (populates the registry source cache carve reads)"
( cd "$PROJECT" && cargo build -q )

MAN="$PROJECT/Cargo.toml"

echo; echo "### Deep DFUG — usage graph across the WHOLE closure (deps of deps)"
"$CARVE" analyze --manifest-path "$MAN" --transitive

echo; echo "### Vendor the ENTIRE transitive closure verbatim + reversible patches"
"$CARVE" vendor-all --manifest-path "$MAN" --transitive --apply

echo; echo "### Rebuild fd from the vendored closure — only Cargo.toml changed"
( cd "$PROJECT" && git --no-pager diff --stat && cargo build -q && echo "build OK from vendored closure" )

echo; echo "### Provenance check + the binary runs"
"$CARVE" verify --manifest-path "$MAN" | tail -1
"$PROJECT/target/debug/fd" --version

if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
  echo; echo "### (optional) LLM agent plans a slice of a vendored crate"
  "$CARVE" llm-check
  "$CARVE" slice memchr --manifest-path "$MAN" --llm || true
fi

echo; echo "done."
