#!/usr/bin/env bash
set -euo pipefail

# Token Flamegraph Toolkit — Installer
#
# One-liner:
#   curl -sL https://raw.githubusercontent.com/N3mes1s/Playground/claude/token-flamegraph-visualization-W0RbW/token-flamegraph/install.sh | bash
#
# Or from a local clone:
#   bash token-flamegraph/install.sh
#
# What it does:
#   1. Copies toolkit to ~/.claude/tools/token-flamegraph/
#   2. Creates `flamegraph` CLI wrapper in ~/.local/bin/
#   3. Installs /flamegraph skill to ~/.claude/skills/
#   4. Adds Stop hook for auto-optimization to ~/.claude/settings.json
#   5. Zero pip dependencies — pure Python + openssl

INSTALL_DIR="${HOME}/.claude/tools/token-flamegraph"
BIN_DIR="${HOME}/.local/bin"
SKILL_DIR="${HOME}/.claude/skills/flamegraph"
SETTINGS="${HOME}/.claude/settings.json"

# Find source directory (script location or current dir)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
if [ -f "${SCRIPT_DIR}/cli.py" ]; then
    SRC_DIR="${SCRIPT_DIR}"
elif [ -f "token-flamegraph/cli.py" ]; then
    SRC_DIR="$(pwd)/token-flamegraph"
else
    # Download from git
    echo "  Downloading token-flamegraph toolkit..."
    TMP="$(mktemp -d)"
    git clone --depth 1 -b claude/token-flamegraph-visualization-W0RbW \
        https://github.com/N3mes1s/Playground.git "$TMP/repo" 2>/dev/null
    SRC_DIR="$TMP/repo/token-flamegraph"
fi

echo "  Installing token-flamegraph toolkit..."

# 1. Copy core modules
mkdir -p "$INSTALL_DIR"
CORE_FILES="parser.py flamegraph.py terminal.py render.py optimizer.py compare.py cli.py demo.py auto_optimize.py budget.py messages.py"
for f in $CORE_FILES; do
    if [ -f "${SRC_DIR}/${f}" ]; then
        cp "${SRC_DIR}/${f}" "${INSTALL_DIR}/${f}"
    fi
done
echo "  ✓ Toolkit installed to ${INSTALL_DIR}"

# 2. Create CLI wrapper
mkdir -p "$BIN_DIR"
cat > "${BIN_DIR}/flamegraph" << 'WRAPPER'
#!/usr/bin/env bash
exec python3 "${HOME}/.claude/tools/token-flamegraph/cli.py" "$@"
WRAPPER
chmod +x "${BIN_DIR}/flamegraph"

cat > "${BIN_DIR}/token-optimize" << 'WRAPPER'
#!/usr/bin/env bash
exec python3 "${HOME}/.claude/tools/token-flamegraph/optimizer.py" "$@"
WRAPPER
chmod +x "${BIN_DIR}/token-optimize"

# Ensure ~/.local/bin is in PATH
if [[ ":$PATH:" != *":${BIN_DIR}:"* ]]; then
    echo "  ⚠ Add to your shell profile: export PATH=\"\${HOME}/.local/bin:\${PATH}\""
fi
echo "  ✓ CLI wrappers: flamegraph, token-optimize"

# 3. Install /flamegraph skill
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
| `/flamegraph optimize` | Generate CLAUDE.md optimization rules |
| `/flamegraph html [file]` | Interactive HTML flamegraph |
| `/flamegraph snapshot` | Save metrics baseline |
| `/flamegraph diff` | Compare against baseline |

## Implementation

```bash
cd ~/.claude/tools/token-flamegraph
```

| Argument | Command |
|----------|---------|
| (none), `dashboard` | `python3 cli.py --self` |
| `demo` | `python3 cli.py --demo` |
| `optimize` | `python3 optimizer.py` |
| `html` | `python3 cli.py --html $ARGUMENTS[1]` |
| `snapshot` | `python3 compare.py snapshot` |
| `diff` | `python3 compare.py diff` |
SKILL
echo "  ✓ Skill installed: /flamegraph"

# 4. Add Stop hook for auto-optimization
if [ -f "$SETTINGS" ]; then
    # Check if hook already exists
    if python3 -c "
import json, sys
d = json.load(open('$SETTINGS'))
hooks = d.get('hooks', {}).get('Stop', [])
for h in hooks:
    for hook in h.get('hooks', []):
        if 'auto_optimize' in hook.get('command', ''):
            sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
        echo "  ✓ Stop hook already configured"
    else
        # Merge hook into existing settings
        python3 -c "
import json
with open('$SETTINGS') as f:
    d = json.load(f)
d.setdefault('hooks', {}).setdefault('Stop', []).append({
    'hooks': [{
        'type': 'command',
        'command': 'python3 ${INSTALL_DIR}/auto_optimize.py',
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
    # Create new settings file
    mkdir -p "$(dirname "$SETTINGS")"
    cat > "$SETTINGS" << SETTINGS
{
  "hooks": {
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python3 ${INSTALL_DIR}/auto_optimize.py",
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

echo ""
echo "  ✅ Installation complete!"
echo ""
echo "  Usage:"
echo "    flamegraph --self     Terminal dashboard for current session"
echo "    flamegraph --demo     Demo with sample data"
echo "    token-optimize        Generate CLAUDE.md rules"
echo "    /flamegraph           Skill in Claude Code"
echo ""
echo "  The Stop hook will auto-update CLAUDE.md with optimization"
echo "  rules after each turn (rate-limited to every 5 minutes)."
