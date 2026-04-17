#!/usr/bin/env bash
# Token Flamegraph — Zero-install runner
#
# Analyze your current Claude Code session without installing anything:
#   bash <(curl -sL https://raw.githubusercontent.com/N3mes1s/Playground/claude/token-flamegraph-visualization-W0RbW/token-flamegraph/run.sh)
#
# With arguments:
#   bash <(curl -sL .../run.sh) --demo
#   bash <(curl -sL .../run.sh) --optimize
#   bash <(curl -sL .../run.sh) --install   # permanent install
set -euo pipefail

if [ "${1:-}" = "--install" ]; then
    TMP="$(mktemp -d)"
    git clone --depth 1 https://github.com/N3mes1s/Playground.git "$TMP/src" 2>/dev/null
    bash "$TMP/src/token-flamegraph/install.sh"
    rm -rf "$TMP"
    exit 0
fi

# Ephemeral run — download to /tmp, run, clean up
TOOL_DIR="/tmp/token-flamegraph-$$"
trap 'rm -rf "$TOOL_DIR"' EXIT

git clone --depth 1 https://github.com/N3mes1s/Playground.git "$TOOL_DIR/src" 2>/dev/null
cd "$TOOL_DIR/src/token-flamegraph"

case "${1:-}" in
    --demo)      python3 cli.py --demo ;;
    --optimize)  python3 optimizer.py ;;
    --html)      python3 cli.py --html "${2:-/tmp/flamegraph.html}" && echo "  HTML: ${2:-/tmp/flamegraph.html}" ;;
    --compare)   python3 compare.py snapshot && python3 compare.py diff ;;
    *)           python3 cli.py --self ;;
esac
