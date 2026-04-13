#!/usr/bin/env bash
# Run cargo-tarpaulin and generate a coverage report.
# Mirrors the commented-out steps in .github/workflows/ci.yaml.
#
# Usage:
#   ./scripts/coverage.sh            # generates lcov + HTML report
#   ./scripts/coverage.sh --xml      # also emit Cobertura XML (for CI upload)
#
# Output:
#   coverage/lcov.info               - LCOV data (usable by IDE plugins)
#   coverage/html/                   - browsable HTML report
#   coverage/cobertura.xml           - XML report (only with --xml flag)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$REPO_ROOT/coverage"
TIMEOUT=200

cd "$REPO_ROOT"

# Install cargo-tarpaulin if not already present
if ! cargo tarpaulin --version &>/dev/null 2>&1; then
    echo "Installing cargo-tarpaulin..."
    cargo install cargo-tarpaulin
fi

mkdir -p "$OUT_DIR"

# Build the tarpaulin command, matching the CI flags
CMD=(
    cargo tarpaulin
    --package libmwemu
    --no-default-features
    --timeout "$TIMEOUT"
    --out Lcov
    --out Html
    --output-dir "$OUT_DIR"
)

# Append XML output if requested
if [[ "${1:-}" == "--xml" ]]; then
    CMD+=(--out Xml)
fi

echo "Running: ${CMD[*]}"
"${CMD[@]}"

echo ""
echo "Coverage report written to $OUT_DIR/"
echo "  HTML : $OUT_DIR/html/index.html"
echo "  LCOV : $OUT_DIR/lcov.info"
if [[ "${1:-}" == "--xml" ]]; then
    echo "  XML  : $OUT_DIR/cobertura.xml"
fi
