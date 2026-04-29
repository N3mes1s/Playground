"""pr-review-rehearsal: simulate a PR review thread before opening the PR.

Usage:
    python -m pr_review_rehearsal.cli <github-pr-url>
or:
    python pr-review-rehearsal/cli.py <github-pr-url> [--rounds 1] [--out FILE]

Pipeline:
1. Fetch PR diff + body via GitHub API.
2. Spin up 4 reviewer personas (security, perf, architect, product) in parallel,
   each with persistent memory keyed by repo (so future runs in the same repo
   accumulate reviewer history -- the closest local equivalent of MiroFish's
   Zep-backed agent memory).
3. Implementer agent reads all reviews, produces a refined-patch sketch and
   per-comment responses.
4. Judge agent summarises top concerns and verdict.
5. Markdown report dropped under ./reports/.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Make sibling mirofish_lab importable when invoked directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mirofish_lab import (
    Agent,
    Persona,
    Report,
    load_config,
    parallel_run,
)
from mirofish_lab.config import verify_model
from mirofish_lab.github import fetch_pr, load_pr_from_file
from mirofish_lab.personas import REVIEWER_PERSONAS, JUDGE_PERSONA


IMPLEMENTER = Persona(
    name="Implementer",
    role="patch author",
    system_prompt=(
        "You are the engineer who wrote this patch. You receive multiple reviewer "
        "comments and respond to each: accept and describe the concrete change you'd "
        "make, push back with reasoning, or ask a clarifying question. Be specific. "
        "End with a short bullet list of the actual diff edits you would make in v2 "
        "of the patch."
    ),
)


def diff_prompt(pr) -> str:
    return (
        f"# PR: {pr.title}\n\n"
        f"Repo: {pr.owner}/{pr.repo}  ·  PR #{pr.number}  ·  {pr.url}\n\n"
        f"## PR description\n\n{pr.body or '(no description)'}\n\n"
        f"## Diff\n\n```diff\n{pr.diff}\n```\n"
    )


def _run(pr, cfg, *, rounds: int, out_path: Path) -> Path:
    print(
        f"[pr] #{pr.number}: {pr.title!r} ({len(pr.diff)} chars of diff)",
        file=sys.stderr,
    )

    # Persistent memory per (repo, persona) so re-runs in same repo accumulate.
    repo_tag = f"{pr.owner}_{pr.repo}"
    reviewers = [
        Agent(
            persona=Persona(
                name=f"{p.name}__{repo_tag}",
                role=p.role,
                system_prompt=p.system_prompt,
            ),
            cfg=cfg,
            persistent=True,
        )
        for p in REVIEWER_PERSONAS
    ]

    seed = diff_prompt(pr)
    print(f"[review] running {len(reviewers)} reviewers in parallel", file=sys.stderr)
    review_resps = parallel_run(reviewers, seed)

    # Implementer iterates the patch.
    impl = Agent(persona=IMPLEMENTER, cfg=cfg, persistent=False)
    combined = "\n\n---\n\n".join(
        f"### {r.agent_name}\n{r.content}" for r in review_resps
    )
    impl_prompt = (
        f"{seed}\n\n"
        f"## Reviewer comments\n\n{combined}\n\n"
        f"Respond to each reviewer, then list the v2 diff edits."
    )
    print("[implementer] iterating patch", file=sys.stderr)
    impl_resp = impl.respond(impl_prompt)

    # Judge ranks top concerns.
    judge = Agent(persona=JUDGE_PERSONA, cfg=cfg, persistent=False)
    judge_prompt = (
        f"You are reviewing a simulated PR review thread.\n\n"
        f"## Reviewer comments\n{combined}\n\n"
        f"## Implementer response\n{impl_resp.content}\n\n"
        f"Produce: (1) the top 3 concerns ranked by likely real-reviewer impact, "
        f"(2) a 'merge-readiness' verdict in [block, request changes, approve with nits, approve], "
        f"(3) any open questions for the human PR author."
    )
    print("[judge] ranking", file=sys.stderr)
    judge_resp = judge.respond(judge_prompt)

    # Build report.
    report = Report(
        title=f"PR Review Rehearsal — {pr.owner}/{pr.repo}#{pr.number}",
        meta={
            "PR": pr.url,
            "title": pr.title,
            "model": cfg.model,
            "rounds": str(rounds),
        },
    )
    report.add("PR Description", pr.body or "_(no description)_")
    for r in review_resps:
        report.add(f"Reviewer: {r.agent_name.split('__')[0]}", r.content)
    report.add("Implementer Iteration", impl_resp.content)
    report.add("Judge Verdict", judge_resp.content)

    written = report.write(out_path)
    print(f"[done] wrote {written}", file=sys.stderr)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Simulate a PR review before opening the PR.")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--pr-url", help="GitHub PR URL, e.g. https://github.com/o/r/pull/123")
    src.add_argument("--from-file", type=Path, help="Pre-fetched PR JSON")
    parser.add_argument("--rounds", type=int, default=1, help="(reserved) reviewer-iteration rounds")
    parser.add_argument("--out", type=Path, default=None, help="Output markdown path")
    args = parser.parse_args(argv)

    cfg = load_config()
    print(f"[config] model={cfg.model} memory_dir={cfg.memory_dir}", file=sys.stderr)
    verify_model(cfg)

    if args.pr_url:
        print(f"[fetch] {args.pr_url}", file=sys.stderr)
        pr = fetch_pr(args.pr_url)
    else:
        print(f"[load] {args.from_file}", file=sys.stderr)
        pr = load_pr_from_file(args.from_file)

    if args.out is None:
        slug = f"{pr.owner}_{pr.repo}_pull_{pr.number}"
        args.out = Path("pr-review-rehearsal/reports") / f"{slug}.md"

    _run(pr, cfg, rounds=args.rounds, out_path=args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
