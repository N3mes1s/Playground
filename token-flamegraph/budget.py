#!/usr/bin/env python3
"""
Real-time token budget monitor for Claude Code sessions.

Can be used as:
1. A stop-hook: runs after each turn, warns if budget thresholds are exceeded
2. A standalone monitor: watches a session file and prints live stats
3. A library: import and query programmatically

Key optimizations it detects and suggests:
- Context growing too fast (suggest summarization)
- Too many Write calls (suggest Edit)
- Sub-agents doing too many tool calls (suggest constraining)
- Cache miss spikes (suggest reordering)
- Tool call storms (suggest batching)
"""

import json
import sys
import time
from pathlib import Path
from dataclasses import dataclass


@dataclass
class BudgetAlert:
    severity: str  # "info", "warn", "critical"
    message: str
    suggestion: str
    tokens_at_stake: int = 0


def analyze_session_file(path: str) -> list[BudgetAlert]:
    """Analyze a session JSONL and return actionable alerts."""
    p = Path(path)
    if not p.exists():
        return []

    lines = p.read_text().strip().split("\n")
    records = [json.loads(l) for l in lines if l.strip()]

    alerts = []
    assistant_msgs = []
    total_output = 0
    total_write_tokens = 0
    total_tools = 0
    max_input = 0
    prev_input = 0
    cache_misses = 0
    cache_hits = 0
    turn_tool_counts = []
    current_turn_tools = 0

    for rec in records:
        if rec.get("type") != "assistant":
            if rec.get("type") == "user":
                if current_turn_tools > 0:
                    turn_tool_counts.append(current_turn_tools)
                    current_turn_tools = 0
            continue

        msg = rec.get("message", {})
        if not isinstance(msg, dict):
            continue

        usage = msg.get("usage", {})
        out = usage.get("output_tokens", 0)
        inp = (
            usage.get("input_tokens", 0)
            + usage.get("cache_read_input_tokens", 0)
            + usage.get("cache_creation_input_tokens", 0)
        )
        cache_r = usage.get("cache_read_input_tokens", 0)
        cache_w = usage.get("cache_creation_input_tokens", 0)

        total_output += out
        if inp > max_input:
            if prev_input > 0:
                growth = inp - prev_input
                if cache_r < inp * 0.5:
                    cache_misses += 1
                else:
                    cache_hits += 1
            prev_input = inp
            max_input = inp

        content = msg.get("content", [])
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    name = block.get("name", "")
                    total_tools += 1
                    current_turn_tools += 1

                    if name == "Write":
                        inp_data = block.get("input", {})
                        content_str = json.dumps(inp_data)
                        total_write_tokens += len(content_str) // 4

    # Flush last turn
    if current_turn_tools > 0:
        turn_tool_counts.append(current_turn_tools)

    # --- Generate alerts ---

    # 1. Context size warning
    if max_input > 80_000:
        alerts.append(BudgetAlert(
            severity="critical" if max_input > 150_000 else "warn",
            message=f"Context reached {max_input:,} tokens",
            suggestion="Consider starting a new session or asking for a summary to reduce context",
            tokens_at_stake=max_input,
        ))

    # 2. Write-heavy session
    if total_write_tokens > total_output * 0.5 and total_write_tokens > 5000:
        alerts.append(BudgetAlert(
            severity="warn",
            message=f"Write tool consumed ~{total_write_tokens:,} tokens ({total_write_tokens * 100 // max(total_output, 1)}% of output)",
            suggestion="Use Edit for modifications instead of Write (sends only the diff, not full file)",
            tokens_at_stake=total_write_tokens // 3,
        ))

    # 3. Tool call storms
    storm_turns = [c for c in turn_tool_counts if c > 10]
    if storm_turns:
        avg_storm = sum(storm_turns) // len(storm_turns)
        alerts.append(BudgetAlert(
            severity="warn",
            message=f"{len(storm_turns)} turn(s) with 10+ tool calls (avg {avg_storm})",
            suggestion="Batch independent tool calls in parallel, or auto-approve trusted tools to reduce round-trips",
            tokens_at_stake=max_input * len(storm_turns),
        ))

    # 4. Cache miss rate
    total_cache_events = cache_hits + cache_misses
    if total_cache_events > 3 and cache_misses / total_cache_events > 0.3:
        alerts.append(BudgetAlert(
            severity="warn",
            message=f"Cache miss rate: {cache_misses}/{total_cache_events} ({cache_misses * 100 // total_cache_events}%)",
            suggestion="Large context changes between turns are invalidating cache. Avoid inserting large blocks mid-conversation",
            tokens_at_stake=max_input * cache_misses,
        ))

    # 5. Overall budget check
    total_cost = max_input + total_output  # rough proxy
    if total_cost > 200_000:
        alerts.append(BudgetAlert(
            severity="info",
            message=f"Session total: ~{total_cost:,} tokens (in+out)",
            suggestion=f"Output: {total_output:,} | Context: {max_input:,} | Tools: {total_tools}",
        ))

    return alerts


def format_alerts(alerts: list[BudgetAlert], oneliner: bool = False) -> str:
    """Format alerts for terminal display.

    oneliner=True produces a single line suitable for stop-hook output:
      ⚠ ctx=110K write=79% tools=12 | Use Edit not Write, context growing fast
    """
    if not alerts:
        return "✅ budget ok" if oneliner else ""

    if oneliner:
        worst = sorted(alerts, key=lambda x: {"critical": 0, "warn": 1, "info": 2}[x.severity])
        icon = "🔴" if worst[0].severity == "critical" else "⚠"
        tips = [a.message.split(" ")[0:4] for a in worst[:3]]
        tips_str = "; ".join(" ".join(t) for t in tips)
        return f"{icon} {tips_str}"

    icons = {"critical": "🔴", "warn": "🟡", "info": "🔵"}
    lines = []

    for a in sorted(alerts, key=lambda x: {"critical": 0, "warn": 1, "info": 2}[x.severity]):
        icon = icons[a.severity]
        lines.append(f"  {icon} {a.message}")
        lines.append(f"     → {a.suggestion}")
        if a.tokens_at_stake > 0:
            lines.append(f"     ({a.tokens_at_stake:,} tokens at stake)")
        lines.append("")

    return "\n".join(lines)


def monitor(path: str, interval: float = 5.0):
    """Watch a session file and print live budget alerts."""
    last_size = 0
    print(f"Monitoring: {path}")
    print(f"Checking every {interval}s...\n")

    while True:
        try:
            p = Path(path)
            if p.exists():
                size = p.stat().st_size
                if size != last_size:
                    last_size = size
                    alerts = analyze_session_file(path)
                    if alerts:
                        print(f"\033[2m--- {time.strftime('%H:%M:%S')} ---\033[0m")
                        print(format_alerts(alerts))
            time.sleep(interval)
        except KeyboardInterrupt:
            break


# Hook mode: run once and exit with status
if __name__ == "__main__":
    args = sys.argv[1:]
    flags = [a for a in args if a.startswith("--")]
    positional = [a for a in args if not a.startswith("--")]

    if positional:
        path = positional[0]
    else:
        # Auto-find current session
        claude_dir = Path("/root/.claude/projects")
        if not claude_dir.exists():
            claude_dir = Path.home() / ".claude" / "projects"
        jsonl_files = sorted(
            [f for f in claude_dir.rglob("*.jsonl") if "subagents" not in str(f)],
            key=lambda p: p.stat().st_mtime, reverse=True
        )
        if not jsonl_files:
            print("No session found", file=sys.stderr)
            sys.exit(1)
        path = str(jsonl_files[0])

    if "--watch" in flags:
        monitor(path)
    elif "--hook" in flags:
        # One-liner mode for stop-hooks
        alerts = analyze_session_file(path)
        print(format_alerts(alerts, oneliner=True))
    else:
        alerts = analyze_session_file(path)
        if alerts:
            print(format_alerts(alerts))
        else:
            print("  ✅ No budget concerns detected")
