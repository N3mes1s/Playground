#!/usr/bin/env python3
"""
Auto-optimization hook — runs after each turn to detect new waste
patterns and update CLAUDE.md if rules have changed.

Usage as Stop hook:
  python3 /home/user/Playground/token-flamegraph/auto_optimize.py

Behavior:
- Finds the current session JSONL
- Runs the optimizer on it
- Compares new rules against existing CLAUDE.md
- If rules changed (new patterns or worse numbers), updates CLAUDE.md
- Prints a one-line summary if anything changed
- Runs in <2s to avoid slowing down the session
"""

import json
import os
import sys
import time
from pathlib import Path

CLAUDE_MD = Path("/home/user/Playground/CLAUDE.md")
LAST_RUN = Path("/tmp/.auto_optimize_last")
MIN_INTERVAL_SECS = 300  # don't run more than once per 5 minutes


def find_session_jsonl() -> Path | None:
    """Find the current session's JSONL file."""
    claude_dir = Path.home() / ".claude" / "projects"
    if not claude_dir.exists():
        return None
    candidates = []
    for jsonl in claude_dir.rglob("*.jsonl"):
        candidates.append((jsonl.stat().st_mtime, jsonl))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return candidates[0][1]


def should_run() -> bool:
    """Rate-limit: skip if we ran recently."""
    if not LAST_RUN.exists():
        return True
    try:
        last = float(LAST_RUN.read_text().strip())
        return (time.time() - last) > MIN_INTERVAL_SECS
    except (ValueError, OSError):
        return True


def run_optimizer(jsonl_path: Path):
    """Run the optimizer and return Rule objects."""
    sys.path.insert(0, str(Path(__file__).parent))
    from optimizer import analyze_session
    return analyze_session(str(jsonl_path))


def format_claude_md(rules) -> str:
    """Format Rule dataclass list as CLAUDE.md content."""
    severity_map = {1: "HIGH", 2: "MED", 3: "LOW"}
    lines = [
        "# Token Optimization Rules",
        "",
        "# Auto-generated and continuously updated by auto_optimize.py hook.",
        f"# Last updated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
    ]
    for rule in rules:
        sev = severity_map.get(rule.priority, "LOW")
        lines.append(f"## [{sev}] {rule.title}")
        lines.append(f"# Saves ~{rule.estimated_savings_pct:.0f}% — {rule.evidence}")
        lines.append(rule.claude_md_directive)
        lines.append("")
    return "\n".join(lines)


def rules_changed(old_content: str, new_rules) -> bool:
    """Check if rules have meaningfully changed."""
    old_titles = set()
    for line in old_content.split("\n"):
        if line.startswith("## ["):
            old_titles.add(line.split("] ", 1)[-1] if "] " in line else line)
    new_titles = {r.title for r in new_rules}
    return old_titles != new_titles


def main():
    if not should_run():
        return

    jsonl = find_session_jsonl()
    if not jsonl:
        return

    try:
        rules = run_optimizer(jsonl)
    except Exception:
        return

    if not rules:
        return

    LAST_RUN.write_text(str(time.time()))

    old_content = CLAUDE_MD.read_text() if CLAUDE_MD.exists() else ""

    if rules_changed(old_content, rules):
        new_content = format_claude_md(rules)
        CLAUDE_MD.write_text(new_content)
        count = len(rules)
        top = rules[0].title if rules else ""
        print(f"📊 CLAUDE.md updated: {count} rules (top: {top})")


if __name__ == "__main__":
    main()
