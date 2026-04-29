"""pre-flight-rehearsal: rehearse N implementation strategies before committing.

Usage:
    python pre-flight-rehearsal/cli.py <github-issue-url> [--out FILE]

Pipeline:
1. Fetch issue body + labels via GitHub API.
2. Spin up 4 implementer personas in parallel (Minimalist, Defensive, TestFirst,
   RefactorHappy). Each produces a plan + diff sketch independently.
3. Judge agent ranks them and picks a winner with rationale.
4. Markdown report written to ./reports/.

This is "ensembling-as-simulation" for managed coding agents: instead of one
single-shot plan, rehearse several styles and pick the strongest.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mirofish_lab import Agent, Report, load_config, parallel_run
from mirofish_lab.config import verify_model
from mirofish_lab.github import fetch_issue, load_issue_from_file
from mirofish_lab.personas import IMPLEMENTER_PERSONAS, JUDGE_PERSONA


def issue_prompt(issue) -> str:
    labels = ", ".join(issue.labels) if issue.labels else "(none)"
    return (
        f"# Issue: {issue.title}\n\n"
        f"Repo: {issue.owner}/{issue.repo}  ·  #{issue.number}  ·  {issue.url}\n"
        f"Labels: {labels}\n\n"
        f"## Description\n\n{issue.body or '(no description)'}\n\n"
        f"Produce:\n"
        f"1. A short plan (3-7 bullets).\n"
        f"2. A diff sketch (file paths + key edits, no need to be syntactically perfect).\n"
        f"3. Risks you foresee.\n"
    )


def _run(issue, cfg, *, out_path: Path) -> Path:
    print(f"[issue] #{issue.number}: {issue.title!r}", file=sys.stderr)

    implementers = [Agent(p, cfg) for p in IMPLEMENTER_PERSONAS]
    seed = issue_prompt(issue)
    print(f"[plan] {len(implementers)} implementers in parallel", file=sys.stderr)
    plans = parallel_run(implementers, seed)

    judge = Agent(JUDGE_PERSONA, cfg)
    plans_block = "\n\n---\n\n".join(
        f"### {r.agent_name}\n{r.content}" for r in plans
    )
    judge_prompt = (
        f"# Issue\n{seed}\n\n"
        f"# Candidate plans\n\n{plans_block}\n\n"
        f"Rank these plans 1..N. For each, give a one-sentence rationale. "
        f"Pick a winner. Note any synthesis you'd recommend (e.g. 'take TestFirst's "
        f"test list and Minimalist's diff'). Identify open questions for the human "
        f"engineer before any of these plans should actually be executed."
    )
    print("[judge] ranking plans", file=sys.stderr)
    judge_resp = judge.respond(judge_prompt)

    report = Report(
        title=f"Pre-flight Rehearsal — {issue.owner}/{issue.repo}#{issue.number}",
        meta={"Issue": issue.url, "title": issue.title, "model": cfg.model},
    )
    report.add("Issue Description", issue.body or "_(no description)_")
    for r in plans:
        report.add(f"Plan: {r.agent_name}", r.content)
    report.add("Judge Verdict", judge_resp.content)

    written = report.write(out_path)
    print(f"[done] wrote {written}", file=sys.stderr)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Rehearse multiple implementation strategies.")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--issue-url", help="GitHub issue URL")
    src.add_argument("--from-file", type=Path, help="Pre-fetched issue JSON")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)

    cfg = load_config()
    print(f"[config] model={cfg.model}", file=sys.stderr)
    verify_model(cfg)

    if args.issue_url:
        print(f"[fetch] {args.issue_url}", file=sys.stderr)
        issue = fetch_issue(args.issue_url)
    else:
        print(f"[load] {args.from_file}", file=sys.stderr)
        issue = load_issue_from_file(args.from_file)

    if args.out is None:
        slug = f"{issue.owner}_{issue.repo}_issues_{issue.number}"
        args.out = Path("pre-flight-rehearsal/reports") / f"{slug}.md"

    _run(issue, cfg, out_path=args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
