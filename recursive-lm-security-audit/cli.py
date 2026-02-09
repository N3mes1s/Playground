#!/usr/bin/env python3
"""
CLI entry point for the Recursive LM Security Auditor.

Supports scanning local directories or cloning a GitHub repository for analysis.
Automatically uses parallel scanning for large codebases.

Usage:
    # Scan a local directory
    python cli.py /path/to/source

    # Scan a GitHub repo
    python cli.py https://github.com/OWASP/DVSA

    # Scan a large repo in parallel (auto-detected, or force with --parallel)
    python cli.py https://github.com/n8n-io/n8n --parallel --workers 3

    # Scan with a specific model
    python cli.py https://github.com/OWASP/DVSA --model openrouter/x-ai/grok-4

    # Use a cheaper sub-model for recursive calls
    python cli.py ./my-app --sub-model openrouter/openai/gpt-4.1-mini

    # Save report to a file
    python cli.py ./my-app -o report.md

    # Scan AND validate (deep-think about each finding)
    python cli.py ./my-app --validate -o report.md

    # Validate an existing report against source code
    python cli.py --validate-report raw-report.md --source ./my-app -o validated.md
"""

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from scanner import run_audit, load_source_tree, _configure_deno_tls
from parallel_scanner import run_parallel_audit, _tree_size, _tree_file_count, MAX_CHUNK_CHARS
from validator import validate_report


# Auto-parallel threshold: repos above this size get parallel scanning
AUTO_PARALLEL_CHARS = 2_000_000  # ~2MB of source


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
  %(prog)s https://github.com/n8n-io/n8n --parallel --workers 3
  %(prog)s https://github.com/org/repo --branch develop
  %(prog)s ./my-app --model openrouter/x-ai/grok-4 -o report.md
  %(prog)s ./my-app --validate -o validated-report.md
  %(prog)s --validate-report raw.md --source ./my-app -o validated.md
        """,
    )

    parser.add_argument(
        "target",
        nargs="?",
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

    # Parallel scanning options
    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Force parallel scanning mode (auto-detected for large repos)",
    )
    parser.add_argument(
        "--no-parallel",
        action="store_true",
        help="Force single-scan mode even for large repos",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=3,
        help="Max concurrent RLM scans in parallel mode (default: 3)",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=MAX_CHUNK_CHARS,
        help=f"Max characters per chunk in parallel mode (default: {MAX_CHUNK_CHARS:,})",
    )

    # Validation options
    parser.add_argument(
        "--validate",
        action="store_true",
        help="After scanning, run adversarial validation on each finding (deep-think pass)",
    )
    parser.add_argument(
        "--validate-report",
        default=None,
        metavar="REPORT.md",
        help="Validate an existing raw report instead of scanning (requires --source)",
    )
    parser.add_argument(
        "--source",
        default=None,
        help="Source code path for validation (used with --validate-report)",
    )
    parser.add_argument(
        "--validate-iterations",
        type=int,
        default=20,
        help="Max RLM iterations per finding during validation (default: 20)",
    )

    args = parser.parse_args()

    # Handle --validate-report mode (standalone validation of existing report)
    if args.validate_report:
        if not args.source and not args.target:
            print("Error: --validate-report requires --source or a target path", file=sys.stderr)
            sys.exit(1)

        source = args.source or args.target
        report_path = Path(args.validate_report)
        if not report_path.is_file():
            print(f"Error: {report_path} not found", file=sys.stderr)
            sys.exit(1)

        raw_report = report_path.read_text()
        tmp_dir = None

        try:
            if is_git_url(source):
                tmp_dir = tempfile.mkdtemp(prefix="rlm-validate-")
                source_path = clone_repo(source, tmp_dir, branch=args.branch)
            else:
                source_path = Path(source).resolve()

            print(f"Validating report: {report_path}")
            print(f"Source code:       {source_path}")
            print(f"Model:             {args.model}")
            print()

            report = validate_report(
                raw_report=raw_report,
                source_path=str(source_path),
                model=args.model,
                sub_model=args.sub_model,
                max_tokens=args.max_tokens,
                max_iterations=args.validate_iterations,
                verbose=not args.quiet,
                project_name=source_path.name,
            )

            if args.output:
                out = Path(args.output)
                out.write_text(report)
                print(f"\nValidated report written to {out}")
            else:
                print("\n" + "=" * 80)
                print("VALIDATED SECURITY AUDIT REPORT")
                print("=" * 80 + "\n")
                print(report)

        finally:
            if tmp_dir and Path(tmp_dir).exists():
                shutil.rmtree(tmp_dir, ignore_errors=True)

        return

    # Normal scan mode -- target is required
    if not args.target:
        parser.error("target is required (or use --validate-report for standalone validation)")

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
        if args.validate:
            print(f"Validation: enabled (devil's advocate pass)")

        # Decide scanning mode: parallel or single
        use_parallel = args.parallel
        if not use_parallel and not args.no_parallel:
            # Auto-detect: probe source tree size
            _configure_deno_tls()
            tree = load_source_tree(source_path)
            size = _tree_size(tree)
            files = _tree_file_count(tree)
            if size > AUTO_PARALLEL_CHARS:
                print(f"Large codebase detected ({files} files, {size:,} chars) -- using parallel mode")
                use_parallel = True

        print(f"Mode:     {'parallel' if use_parallel else 'single'}")
        print()

        if use_parallel:
            raw_report = run_parallel_audit(
                source_path=source_path,
                model=args.model,
                sub_model=args.sub_model,
                max_tokens=args.max_tokens,
                max_iterations=args.max_iterations,
                max_workers=args.workers,
                verbose=not args.quiet,
                reasoning_effort=args.reasoning_effort,
                max_chunk_chars=args.chunk_size,
            )
        else:
            raw_report = run_audit(
                source_path=source_path,
                model=args.model,
                sub_model=args.sub_model,
                max_tokens=args.max_tokens,
                max_iterations=args.max_iterations,
                verbose=not args.quiet,
                reasoning_effort=args.reasoning_effort,
            )

        # Validation pass
        if args.validate:
            print("\n" + "=" * 80)
            print("PHASE 2: ADVERSARIAL VALIDATION")
            print("=" * 80 + "\n")

            report = validate_report(
                raw_report=raw_report,
                source_path=str(source_path),
                model=args.model,
                sub_model=args.sub_model,
                max_tokens=args.max_tokens,
                max_iterations=args.validate_iterations,
                verbose=not args.quiet,
                project_name=source_path.name,
            )
        else:
            report = raw_report

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
