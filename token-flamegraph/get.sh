#!/usr/bin/env bash
# Token Flamegraph — Quick Install
# Run in any Claude Code session:
#   bash <(curl -sL flmgrph.sh)
# Or:
#   curl -sL https://raw.githubusercontent.com/N3mes1s/Playground/main/token-flamegraph/install.sh | bash
set -euo pipefail
TMP="$(mktemp -d)"
git clone --depth 1 https://github.com/N3mes1s/Playground.git "$TMP/src" 2>/dev/null
bash "$TMP/src/token-flamegraph/install.sh"
rm -rf "$TMP"
