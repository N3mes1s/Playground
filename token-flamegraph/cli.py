#!/usr/bin/env python3
"""
Token Flamegraph - Visualize how a coding agent spends its token budget.

Usage:
    python cli.py session.jsonl                       # Terminal dashboard
    python cli.py session.jsonl --html -o report.html # HTML report
    python cli.py --demo                              # Demo with sample data
    python cli.py --self                              # Visualize current session
    python cli.py --teleport SESSION_ID               # Analyze remote session
"""

import argparse
import glob
import os
import shutil
import sys
import webbrowser
import tempfile
from pathlib import Path

from parser import parse_session
from demo import generate_demo_session


def _fetch_teleport_session(session_id: str):
    """Use claude-teleport-analyzer to export a remote session, then parse it."""
    import subprocess
    import tempfile

    # Find the teleport analyzer binary
    candidates = [
        "claude-teleport-analyzer",
        "/tmp/claude-teleport-analyzer/target/release/claude-teleport-analyzer",
        "/home/user/claude-teleport-analyzer/target/debug/claude-teleport-analyzer",
        "/home/user/claude-teleport-analyzer/target/release/claude-teleport-analyzer",
    ]
    binary = None
    for c in candidates:
        if os.path.isfile(c) or shutil.which(c):
            binary = c
            break

    if not binary:
        print("claude-teleport-analyzer not found. Install from:", file=sys.stderr)
        print("  https://github.com/N3mes1s/claude-teleport-analyzer", file=sys.stderr)
        sys.exit(1)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        export_path = f.name

    print(f"Exporting remote session {session_id}...")
    result = subprocess.run(
        [binary, "export", session_id, "--output", export_path],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"Export failed: {result.stderr}", file=sys.stderr)
        sys.exit(1)

    print(f"Parsing exported session...")
    return parse_session(export_path)


def _find_current_session() -> str:
    """Find the JSONL file for the current Claude Code session."""
    claude_dir = Path.home() / ".claude" / "projects"
    if not claude_dir.exists():
        # Try /root
        claude_dir = Path("/root/.claude/projects")
    if not claude_dir.exists():
        print("Could not find Claude Code session directory", file=sys.stderr)
        sys.exit(1)

    # Find the most recent .jsonl file
    jsonl_files = sorted(claude_dir.rglob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    # Filter out subagent files
    jsonl_files = [f for f in jsonl_files if "subagents" not in str(f)]
    if not jsonl_files:
        print("No session files found", file=sys.stderr)
        sys.exit(1)

    return str(jsonl_files[0])


def main():
    ap = argparse.ArgumentParser(
        description="Token Flamegraph - Visualize agent token usage"
    )
    ap.add_argument("input", nargs="?", help="Session JSON/JSONL file")
    ap.add_argument("-o", "--output", help="Output file path")
    ap.add_argument("--title", default="Token Flamegraph", help="Chart title")
    ap.add_argument("--demo", action="store_true", help="Generate demo visualization")
    ap.add_argument("--html", action="store_true", help="Output HTML instead of terminal")
    ap.add_argument("--self", dest="self_session", action="store_true",
                    help="Visualize the current/most recent Claude Code session")
    ap.add_argument("--open", action="store_true", help="Open HTML in browser")
    ap.add_argument("--teleport", metavar="SESSION_ID",
                    help="Export & analyze a remote session via claude-teleport-analyzer")

    args = ap.parse_args()

    # Determine input
    if args.teleport:
        session = _fetch_teleport_session(args.teleport)
        if args.title == "Token Flamegraph":
            args.title = f"Remote: {args.teleport[:30]}"
    elif args.demo:
        session = generate_demo_session()
    elif args.self_session:
        path = _find_current_session()
        session = parse_session(path)
        if args.title == "Token Flamegraph":
            args.title = f"Session: {Path(path).stem[:20]}"
    elif args.input:
        session = parse_session(args.input)
    else:
        ap.print_help()
        sys.exit(1)

    if args.html:
        from render import render_html
        html_content = render_html(session, title=args.title)
        if args.output:
            out_path = Path(args.output)
            out_path.write_text(html_content)
            print(f"Written to {out_path}")
            if args.open:
                webbrowser.open(f"file://{out_path.resolve()}")
        else:
            with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w") as f:
                f.write(html_content)
                print(f"Written to {f.name}")
                if args.open:
                    webbrowser.open(f"file://{f.name}")
    else:
        # Terminal output (default)
        from terminal import render_terminal
        output = render_terminal(session, title=args.title)
        if args.output:
            # Strip ANSI codes for file output
            import re
            clean = re.sub(r'\033\[[0-9;]*m', '', output)
            Path(args.output).write_text(clean)
            print(f"Written to {args.output}")
        else:
            print(output)


if __name__ == "__main__":
    main()
