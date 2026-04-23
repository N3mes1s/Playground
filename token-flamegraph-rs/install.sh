#!/usr/bin/env bash
set -euo pipefail

# Token Flamegraph — Installer
#
# One-liner:
#   bash <(curl -sL https://raw.githubusercontent.com/N3mes1s/Playground/main/token-flamegraph-rs/install.sh)
#
# What it does:
#   1. Downloads or builds the token-flamegraph binary
#   2. Installs to ~/.local/bin/
#   3. Installs /flamegraph skill to ~/.claude/skills/
#   4. Adds Stop hook for auto-optimization to ~/.claude/settings.json

BIN_DIR="${HOME}/.local/bin"
SKILL_DIR="${HOME}/.claude/skills/flamegraph"
SETTINGS="${HOME}/.claude/settings.json"
BINARY_NAME="token-flamegraph"

# Uninstall mode
if [ "${1:-}" = "--uninstall" ]; then
    echo "  Uninstalling token-flamegraph..."
    rm -f "${BIN_DIR}/${BINARY_NAME}"
    rm -rf "${SKILL_DIR}"
    if [ -f "$SETTINGS" ]; then
        python3 -c "
import json
with open('$SETTINGS') as f:
    d = json.load(f)
stops = d.get('hooks', {}).get('Stop', [])
d['hooks']['Stop'] = [h for h in stops if not any('token-flamegraph' in hook.get('command', '') for hook in h.get('hooks', []))]
if not d['hooks']['Stop']:
    del d['hooks']['Stop']
if not d.get('hooks'):
    del d['hooks']
with open('$SETTINGS', 'w') as f:
    json.dump(d, f, indent=2)
    f.write('\n')
" 2>/dev/null && echo "  ✓ Stop hook removed" || echo "  ⚠ Could not update settings.json"
    fi
    echo "  ✓ Binary removed"
    echo "  ✓ Skill removed"
    echo "  ✅ Uninstalled. .claude/rules/token-optimization.md left in place (safe to delete)."
    exit 0
fi

echo "  Installing token-flamegraph..."

# 1. Get the binary
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
mkdir -p "$BIN_DIR"

if [ -f "${SCRIPT_DIR}/target/release/${BINARY_NAME}" ]; then
    cp "${SCRIPT_DIR}/target/release/${BINARY_NAME}" "${BIN_DIR}/${BINARY_NAME}"
elif [ -f "${SCRIPT_DIR}/target/x86_64-unknown-linux-musl/release/${BINARY_NAME}" ]; then
    cp "${SCRIPT_DIR}/target/x86_64-unknown-linux-musl/release/${BINARY_NAME}" "${BIN_DIR}/${BINARY_NAME}"
elif command -v cargo >/dev/null 2>&1 && [ -f "${SCRIPT_DIR}/Cargo.toml" ]; then
    echo "  Building from source..."
    cd "$SCRIPT_DIR" && cargo build --release 2>/dev/null
    cp "target/release/${BINARY_NAME}" "${BIN_DIR}/${BINARY_NAME}"
else
    echo "  Error: No pre-built binary found and cargo not available."
    echo "  Build from source: cd token-flamegraph-rs && cargo build --release"
    exit 1
fi
chmod +x "${BIN_DIR}/${BINARY_NAME}"
echo "  ✓ Binary installed: ${BIN_DIR}/${BINARY_NAME} ($(du -h "${BIN_DIR}/${BINARY_NAME}" | cut -f1))"

# 2. Install /flamegraph skill
mkdir -p "$SKILL_DIR"
cat > "${SKILL_DIR}/SKILL.md" << 'SKILL'
---
name: flamegraph
description: Analyze token usage for Claude Code sessions. Generates flamegraph visualizations, efficiency scores, optimization rules, and session comparisons.
argument-hint: [command] [args...]
allowed-tools: Bash Read Grep Glob
---

# Token Flamegraph Toolkit

Analyze Claude Code session token usage: $ARGUMENTS

## Commands

| Command | What it does |
|---------|-------------|
| `/flamegraph` | Full terminal dashboard for current session |
| `/flamegraph demo` | Demo with sample data |
| `/flamegraph optimize` | Generate optimization rules to .claude/rules/ |
| `/flamegraph html [file]` | Interactive HTML flamegraph |
| `/flamegraph snapshot` | Save metrics baseline |
| `/flamegraph diff` | Compare against baseline |

## Implementation

| Argument | Command |
|----------|---------|
| (none) | `token-flamegraph --self` |
| `demo` | `token-flamegraph --demo` |
| `optimize` | `token-flamegraph --optimize` |
| `html` | `token-flamegraph --html $ARGUMENTS[1]` |
| `snapshot` | `token-flamegraph --snapshot` |
| `diff` | `token-flamegraph --diff` |
SKILL
echo "  ✓ Skill installed: /flamegraph"

# 3. Add Stop hook for auto-optimization
if [ -f "$SETTINGS" ]; then
    if python3 -c "
import json, sys
d = json.load(open('$SETTINGS'))
hooks = d.get('hooks', {}).get('Stop', [])
for h in hooks:
    for hook in h.get('hooks', []):
        if 'token-flamegraph' in hook.get('command', ''):
            sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
        echo "  ✓ Stop hook already configured"
    else
        python3 -c "
import json
with open('$SETTINGS') as f:
    d = json.load(f)
d.setdefault('hooks', {}).setdefault('Stop', []).append({
    'hooks': [{
        'type': 'command',
        'command': '${BIN_DIR}/${BINARY_NAME} --hook',
        'timeout': 30,
        'statusMessage': 'Analyzing token patterns...'
    }]
})
with open('$SETTINGS', 'w') as f:
    json.dump(d, f, indent=2)
    f.write('\n')
"
        echo "  ✓ Stop hook added for auto-optimization"
    fi
else
    mkdir -p "$(dirname "$SETTINGS")"
    cat > "$SETTINGS" << SETTINGS
{
  "hooks": {
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "${BIN_DIR}/${BINARY_NAME} --hook",
            "timeout": 30,
            "statusMessage": "Analyzing token patterns..."
          }
        ]
      }
    ]
  }
}
SETTINGS
    echo "  ✓ Settings created with Stop hook"
fi

if [[ ":$PATH:" != *":${BIN_DIR}:"* ]]; then
    echo ""
    echo "  ⚠ Add to your shell profile: export PATH=\"\${HOME}/.local/bin:\${PATH}\""
fi

echo ""
echo "  ✅ Installation complete! (841KB static binary)"
echo ""
echo "  Usage:"
echo "    token-flamegraph --self      Dashboard for current session"
echo "    token-flamegraph --demo      Demo with sample data"
echo "    token-flamegraph --optimize  Generate .claude/rules/ optimization rules"
echo "    token-flamegraph --html out.html  Interactive HTML flamegraph"
echo "    /flamegraph                  Skill in Claude Code"
echo ""
echo "  Auto-optimization runs after each turn via Stop hook."
