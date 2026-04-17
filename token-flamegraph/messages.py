#!/usr/bin/env python3
"""
Inter-session message passing for Claude Code sessions.

Sessions can communicate through several channels:
1. Filesystem mailbox (fastest, simplest)
2. Git branch (durable, cross-machine)
3. CLAUDE.md directives (picked up automatically by new sessions)
4. Session JSONL reading (read-only, observing other sessions)

This module implements channel #1: a filesystem-based mailbox.
"""

import json
import time
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional

# Mailbox location — shared between all sessions on same project
MAILBOX_DIR = Path("/root/.claude/projects/-home-user-Playground/.mailbox")


@dataclass
class Message:
    """A message between sessions."""
    from_session: str
    to_session: str  # "*" for broadcast
    timestamp: float
    topic: str  # e.g., "token_report", "optimization_rule", "alert"
    payload: dict
    read: bool = False


def send(to: str, topic: str, payload: dict, from_session: str = ""):
    """Send a message to another session (or '*' for broadcast)."""
    import os
    if not from_session:
        from_session = os.environ.get("CLAUDE_CODE_SESSION_ID", "unknown")

    MAILBOX_DIR.mkdir(parents=True, exist_ok=True)

    msg = Message(
        from_session=from_session,
        to_session=to,
        timestamp=time.time(),
        topic=topic,
        payload=payload,
    )

    # File per message: timestamp_from_topic.json
    ts = int(msg.timestamp * 1000)
    filename = f"{ts}_{from_session[:8]}_{topic}.json"
    (MAILBOX_DIR / filename).write_text(json.dumps(asdict(msg), indent=2))
    return filename


def recv(session_id: str = "", topics: list[str] = None, unread_only: bool = True) -> list[Message]:
    """Receive messages for this session."""
    import os
    if not session_id:
        session_id = os.environ.get("CLAUDE_CODE_SESSION_ID", "unknown")

    if not MAILBOX_DIR.exists():
        return []

    messages = []
    for f in sorted(MAILBOX_DIR.glob("*.json")):
        try:
            data = json.loads(f.read_text())
            msg = Message(**data)

            # Filter: addressed to us or broadcast
            if msg.to_session not in (session_id, "*"):
                continue

            # Filter: topic
            if topics and msg.topic not in topics:
                continue

            # Filter: unread
            if unread_only and msg.read:
                continue

            messages.append(msg)
        except (json.JSONDecodeError, TypeError):
            continue

    return messages


def mark_read(msg: Message):
    """Mark a message as read."""
    for f in MAILBOX_DIR.glob("*.json"):
        try:
            data = json.loads(f.read_text())
            if data.get("timestamp") == msg.timestamp and data.get("from_session") == msg.from_session:
                data["read"] = True
                f.write_text(json.dumps(data, indent=2))
                break
        except (json.JSONDecodeError, TypeError):
            continue


def list_sessions() -> list[dict]:
    """List all sessions that have sent or received messages."""
    if not MAILBOX_DIR.exists():
        return []
    sessions = set()
    for f in MAILBOX_DIR.glob("*.json"):
        try:
            data = json.loads(f.read_text())
            sessions.add(data.get("from_session", ""))
            if data.get("to_session") != "*":
                sessions.add(data.get("to_session", ""))
        except (json.JSONDecodeError, TypeError):
            continue
    return sorted(s for s in sessions if s)


def broadcast_token_report(session_path: str = None):
    """Analyze current session and broadcast the report to all sessions."""
    import os
    from parser import parse_session
    from flamegraph import session_to_viz

    if not session_path:
        # Auto-find
        claude_dir = Path("/root/.claude/projects")
        jsonl_files = sorted(
            [f for f in claude_dir.rglob("*.jsonl") if "subagents" not in str(f)],
            key=lambda p: p.stat().st_mtime, reverse=True
        )
        if not jsonl_files:
            return
        session_path = str(jsonl_files[0])

    session = parse_session(session_path)
    viz = session_to_viz(session)

    report = {
        "model": viz.model,
        "total_output": viz.total_output,
        "total_input": viz.total_input,
        "total_thinking": viz.total_thinking,
        "total_cache": viz.total_cache,
        "cache_rate": round(viz.total_cache / max(viz.total_input, 1) * 100, 1),
        "num_tools": viz.num_tool_calls,
        "num_turns": len(viz.turns),
        "top_tools": viz.top_tools[:5],
        "categories": viz.tool_category_tokens,
        "avg_score": round(
            sum(t.efficiency_score for t in viz.turns if t.output_tokens > 0)
            / max(sum(1 for t in viz.turns if t.output_tokens > 0), 1),
            1
        ),
    }

    filename = send("*", "token_report", report)
    print(f"Broadcast token report: {filename}")
    return report


def broadcast_optimization_rules(session_path: str = None):
    """Run optimizer and broadcast rules to all sessions."""
    from optimizer import analyze_session as analyze_rules

    if not session_path:
        claude_dir = Path("/root/.claude/projects")
        jsonl_files = sorted(
            [f for f in claude_dir.rglob("*.jsonl") if "subagents" not in str(f)],
            key=lambda p: p.stat().st_mtime, reverse=True
        )
        if not jsonl_files:
            return
        session_path = str(jsonl_files[0])

    rules = analyze_rules(session_path)
    payload = {
        "rules": [
            {"title": r.title, "directive": r.claude_md_directive, "priority": r.priority}
            for r in rules
        ]
    }

    filename = send("*", "optimization_rules", payload)
    print(f"Broadcast {len(rules)} rules: {filename}")
    return rules


def check_inbox():
    """Check and display any pending messages for this session."""
    messages = recv(unread_only=True)
    if not messages:
        print("  📭 No new messages")
        return

    print(f"  📬 {len(messages)} new message(s):\n")
    for msg in messages:
        ts = time.strftime("%H:%M:%S", time.localtime(msg.timestamp))
        print(f"  [{ts}] from={msg.from_session[:12]} topic={msg.topic}")

        if msg.topic == "token_report":
            p = msg.payload
            print(f"    Output: {p.get('total_output', 0):,} | Score: {p.get('avg_score', 0)} | Tools: {p.get('num_tools', 0)}")

        elif msg.topic == "optimization_rules":
            rules = msg.payload.get("rules", [])
            for r in rules[:3]:
                prio = {1: "🔴", 2: "🟡", 3: "🔵"}.get(r.get("priority", 3), "•")
                print(f"    {prio} {r.get('title', '')}")

        elif msg.topic == "alert":
            print(f"    ⚠ {msg.payload.get('message', '')}")

        print()


if __name__ == "__main__":
    import sys
    args = [a for a in sys.argv[1:] if not a.startswith("--")]

    if not args:
        print("Usage: python messages.py send|recv|report|rules|inbox")
        sys.exit(1)

    cmd = args[0]
    if cmd == "inbox":
        check_inbox()
    elif cmd == "report":
        broadcast_token_report()
    elif cmd == "rules":
        broadcast_optimization_rules()
    elif cmd == "send":
        if len(args) < 4:
            print("Usage: python messages.py send <to_session|*> <topic> <json_payload>")
            sys.exit(1)
        payload = json.loads(args[3]) if len(args) > 3 else {}
        send(args[1], args[2], payload)
        print("Sent.")
    elif cmd == "recv":
        messages = recv(unread_only="--all" not in sys.argv)
        for m in messages:
            print(json.dumps(asdict(m), indent=2))
    else:
        print(f"Unknown: {cmd}")
