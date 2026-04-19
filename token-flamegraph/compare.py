#!/usr/bin/env python3
"""
Compare two sessions or snapshot a session for later comparison.

Usage:
    python compare.py snapshot                    # Save current session as baseline
    python compare.py diff                        # Compare current session vs baseline
    python compare.py diff session_a.jsonl session_b.jsonl  # Compare two files
"""

import json
import sys
from pathlib import Path
from parser import parse_session
from flamegraph import session_to_viz

SNAPSHOT_FILE = Path(__file__).parent / ".baseline.json"


def snapshot_session(path: str):
    """Save session stats as a baseline for later comparison."""
    session = parse_session(path)
    viz = session_to_viz(session)

    baseline = {
        "path": path,
        "model": viz.model,
        "total_output": viz.total_output,
        "total_input": viz.total_input,
        "total_thinking": viz.total_thinking,
        "total_text": viz.total_text,
        "total_tool": viz.total_tool,
        "total_cache": viz.total_cache,
        "num_tool_calls": viz.num_tool_calls,
        "num_turns": len(viz.turns),
        "categories": viz.tool_category_tokens,
        "top_tools": viz.top_tools[:10],
    }
    SNAPSHOT_FILE.write_text(json.dumps(baseline, indent=2))
    print(f"  📸 Baseline saved ({viz.total_output:,} output tokens, {viz.num_tool_calls} tools)")


def diff_sessions(path_a: str = None, path_b: str = None):
    """Compare two sessions and show token deltas."""
    if path_a and path_b:
        a = _stats_from_file(path_a)
        b = _stats_from_file(path_b)
        label_a, label_b = "Session A", "Session B"
    elif SNAPSHOT_FILE.exists():
        a = json.loads(SNAPSHOT_FILE.read_text())
        if path_a:
            b = _stats_from_file(path_a)
        else:
            b = _stats_from_file(_find_current_session())
        label_a, label_b = "Baseline", "Current"
    else:
        print("  No baseline found. Run: python compare.py snapshot", file=sys.stderr)
        sys.exit(1)

    # Print comparison
    print(f"\n  {'Metric':<24s} {label_a:>12s} {label_b:>12s} {'Delta':>10s} {'%':>7s}")
    print(f"  {'─' * 70}")

    metrics = [
        ("Output tokens", "total_output"),
        ("Thinking tokens", "total_thinking"),
        ("Text tokens", "total_text"),
        ("Tool tokens", "total_tool"),
        ("Input tokens", "total_input"),
        ("Cache hits", "total_cache"),
        ("Tool calls", "num_tool_calls"),
        ("Turns", "num_turns"),
    ]

    for label, key in metrics:
        va = a.get(key, 0)
        vb = b.get(key, 0)
        delta = vb - va
        pct = (delta / va * 100) if va > 0 else 0
        arrow = "↓" if delta < 0 else "↑" if delta > 0 else "="
        color = "\033[92m" if delta < 0 else "\033[91m" if delta > 0 else "\033[0m"
        reset = "\033[0m"
        print(f"  {label:<24s} {va:>12,} {vb:>12,} {color}{arrow}{abs(delta):>8,}{reset} {color}{pct:>+6.1f}%{reset}")

    # Category breakdown
    cat_a = a.get("categories", {})
    cat_b = b.get("categories", {})
    all_cats = set(list(cat_a.keys()) + list(cat_b.keys()))
    if all_cats:
        print(f"\n  {'Tool Category':<24s} {label_a:>12s} {label_b:>12s} {'Delta':>10s}")
        print(f"  {'─' * 60}")
        cat_names = {"read": "File reads", "write": "File writes", "bash": "Shell", "search": "Search", "agent": "Sub-agents"}
        for cat in sorted(all_cats):
            va = cat_a.get(cat, 0)
            vb = cat_b.get(cat, 0)
            delta = vb - va
            color = "\033[92m" if delta < 0 else "\033[91m" if delta > 0 else "\033[0m"
            reset = "\033[0m"
            name = cat_names.get(cat, cat)
            print(f"  {name:<24s} {va:>12,} {vb:>12,} {color}{delta:>+10,}{reset}")

    print()


def _stats_from_file(path: str) -> dict:
    session = parse_session(path)
    viz = session_to_viz(session)
    return {
        "path": path,
        "model": viz.model,
        "total_output": viz.total_output,
        "total_input": viz.total_input,
        "total_thinking": viz.total_thinking,
        "total_text": viz.total_text,
        "total_tool": viz.total_tool,
        "total_cache": viz.total_cache,
        "num_tool_calls": viz.num_tool_calls,
        "num_turns": len(viz.turns),
        "categories": viz.tool_category_tokens,
        "top_tools": viz.top_tools[:10],
    }


def _find_current_session() -> str:
    for base in [Path.home() / ".claude" / "projects"]:
        if base.exists():
            files = sorted(
                [f for f in base.rglob("*.jsonl") if "subagents" not in str(f)],
                key=lambda p: p.stat().st_mtime, reverse=True
            )
            if files:
                return str(files[0])
    print("No session found", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]

    if not args:
        print("Usage: python compare.py snapshot | diff [file_a] [file_b]")
        sys.exit(1)

    cmd = args[0]

    if cmd == "snapshot":
        path = args[1] if len(args) > 1 else _find_current_session()
        snapshot_session(path)
    elif cmd == "diff":
        if len(args) >= 3:
            diff_sessions(args[1], args[2])
        elif len(args) == 2:
            diff_sessions(args[1])
        else:
            diff_sessions()
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
