#!/usr/bin/env python3
"""
CLI entry point for the Recursive LM Security Auditor.

Supports scanning local directories or cloning a GitHub repository for analysis.

Usage:
    # Scan a local directory
    python cli.py /path/to/source

    # Scan a GitHub repo
    python cli.py https://github.com/OWASP/DVSA

    # Scan with a specific model
    python cli.py https://github.com/OWASP/DVSA --model openrouter/x-ai/grok-4

    # Use a cheaper sub-model for recursive calls
    python cli.py ./my-app --sub-model openrouter/openai/gpt-4.1-mini

    # Save report to a file
    python cli.py ./my-app -o report.md
"""

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from scanner import run_audit


def clone_repo(repo_url: str, target_dir: str, branch: str | None = None) -> Path:
    """Clone a git repository to target_dir. Returns the clone path."""
    cmd = ["git", "clone", "--depth", "1"]
    if branch:
        cmd += ["--branch", branch]
    cmd += [repo_url, target_dir]

    print(f"Cloning {repo_url} ...")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"git clone failed: {result.stderr}", file=sys.stderr)
        sys.exit(1)

    return Path(target_dir)


def is_git_url(target: str) -> bool:
    """Check if a string looks like a git repository URL."""
    return (
        target.startswith("https://github.com/")
        or target.startswith("git@")
        or target.startswith("https://gitlab.com/")
        or target.startswith("https://bitbucket.org/")
        or target.endswith(".git")
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Recursive LM Security Auditor - Scan codebases for security vulnerabilities using DSPy RLM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/local/project
  %(prog)s https://github.com/OWASP/DVSA
  %(prog)s https://github.com/org/repo --branch develop
  %(prog)s ./my-app --model openrouter/x-ai/grok-4 -o report.md
        """,
    )

    parser.add_argument(
        "target",
        help="Local path or GitHub/Git URL of the repository to scan",
    )
    parser.add_argument(
        "--model",
        default="openrouter/moonshotai/kimi-k2.5",
        help="Primary LM model identifier (default: openrouter/moonshotai/kimi-k2.5)",
    )
    parser.add_argument(
        "--sub-model",
        default=None,
        help="Model for recursive sub-queries (defaults to same as --model)",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=16000,
        help="Max tokens per LM call (default: 16000)",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=35,
        help="Maximum REPL iterations for the RLM (default: 35)",
    )
    parser.add_argument(
        "--branch",
        default=None,
        help="Git branch to clone (default: default branch)",
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Write the report to a file instead of stdout",
    )
    parser.add_argument(
        "--reasoning-effort",
        default=None,
        choices=["low", "medium", "high", "xhigh"],
        help="Reasoning effort level for supported models (e.g. xhigh for GPT-5.x)",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Disable verbose RLM logging",
    )

    args = parser.parse_args()
    tmp_dir = None

    try:
        if is_git_url(args.target):
            tmp_dir = tempfile.mkdtemp(prefix="rlm-audit-")
            source_path = clone_repo(args.target, tmp_dir, branch=args.branch)
        else:
            source_path = Path(args.target).resolve()
            if not source_path.is_dir():
                print(f"Error: {source_path} is not a directory", file=sys.stderr)
                sys.exit(1)

        print(f"Scanning: {source_path}")
        print(f"Model:    {args.model}")
        if args.sub_model:
            print(f"Sub-model: {args.sub_model}")
        if args.reasoning_effort:
            print(f"Reasoning: {args.reasoning_effort}")
        print(f"Max iterations: {args.max_iterations}")
        print()

        report = run_audit(
            source_path=source_path,
            model=args.model,
            sub_model=args.sub_model,
            max_tokens=args.max_tokens,
            max_iterations=args.max_iterations,
            verbose=not args.quiet,
            reasoning_effort=args.reasoning_effort,
        )

        if args.output:
            out = Path(args.output)
            out.write_text(report)
            print(f"\nReport written to {out}")
        else:
            print("\n" + "=" * 80)
            print("SECURITY AUDIT REPORT")
            print("=" * 80 + "\n")
            print(report)

    finally:
        if tmp_dir and Path(tmp_dir).exists():
            shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
