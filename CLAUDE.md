# Token Optimization Rules

# Auto-generated and continuously updated by auto_optimize.py hook.
# Last updated: 2026-04-17 20:51:47

## [HIGH] Use Edit instead of Read+Write
# Saves ~15% — 6 occurrences of Read immediately followed by Write
When modifying existing files, always use Edit (not Read+Write). Edit sends only the changed lines, saving ~60% of output tokens per file modification.

## [HIGH] Large Write calls dominate output
# Saves ~20% — Write sizes: [19085, 16578, 16171, 12352, 11848]
For files over 50 lines, prefer Edit over Write. If creating a new large file, consider splitting into smaller logical files to reduce per-call token cost.

## [MED] Batch sequential Bash commands
# Saves ~10% — Bash streaks: [3, 6, 8, 5, 3, 3, 3, 4, 3, 11, 8, 3, 5, 3, 3, 5, 4, 5, 5, 8, 36, 4, 20, 4, 36, 15, 17, 3, 11, 22, 9, 41, 103, 5, 3]
Chain independent Bash commands with && in a single call. Run truly independent commands as parallel tool calls. Each separate Bash call costs a full context round-trip.

## [LOW] 42 duplicate file reads
# Saves ~5% — Duplicates: {'/home/user/Playground/token-flamegraph/flamegraph.py': 10, '/home/user/Playground/token-flamegraph/parser.py': 9, '/home/user/Playground/token-flamegraph/this-session.html': 2, '/home/user/Playground/token-flamegraph/cli.py': 3, '/home/user/Playground/token-flamegraph/optimizer.py': 2}
Before reading a file, check if you've already read it in this conversation. Store key information from reads in your response text so you don't need to re-read.

## [LOW] 15 full file reads without limit
# Saves ~8% — Full reads: ['/tmp/token-flamegraph-demo.html', '/home/user/Playground/token-flamegraph/parser.py', '/home/user/Playground/token-flamegraph/this-session.html', '/home/user/Playground/token-flamegraph/cli.py', '/home/user/Playground/token-flamegraph/optimizer.py']
Use the limit and offset parameters when reading files. Read only the section you need, not the entire file.

## [LOW] 28 grep/rg calls via Bash
# Saves ~3% — Commands: ['git commit -m "$(cat <<\'EOF\'\nAdd efficiency scores', 'ls -la /root/.claude/ | grep -i cred && echo "---"', 'env | grep -i -E "ANTHROPIC|CLAUDE|API_KEY" 2>/dev']
Never use `grep` or `rg` via Bash. Always use the Grep tool — it's optimized for permissions and returns structured results with less token overhead.

## [LOW] 32 find/ls calls via Bash
# Saves ~3% — Commands: ['ls /home/user/Playground/', 'cd /home/user/Playground && git add token-flamegra', 'cd /home/user/Playground && git add token-flamegra']
Never use `find` or `ls` via Bash for file discovery. Use the Glob tool with patterns like '**/*.py' — it's faster and costs fewer tokens.
