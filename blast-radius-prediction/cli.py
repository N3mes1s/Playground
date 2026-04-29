"""blast-radius-prediction: predict downstream breakage from a proposed diff.

Usage:
    # diff from a GitHub PR + the repo cloned locally:
    python blast-radius-prediction/cli.py \\
        --pr https://github.com/<o>/<r>/pull/<n> --repo /path/to/cloned/repo

    # or local diff file + repo:
    python blast-radius-prediction/cli.py \\
        --diff path/to/change.diff --repo /path/to/repo

Pipeline:
1. Fetch the diff (from PR URL or file).
2. Walk the diff, find changed Python symbols (functions/classes) using AST.
3. Cluster the repo's files into subsystem groups (top-level packages).
4. For each subsystem that grep-matches any changed symbol, instantiate an
   agent persona with that subsystem's role + a sample of its code as context.
5. Round-table simulation: each subsystem-agent reacts to the change.
6. Judge agent rolls up the predicted breakage per subsystem.

The closest fit to MiroFish's "graph building -> simulation -> report"
pipeline shape: the call graph is the seed, subsystems are the agents,
the diff is the perturbation.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mirofish_lab import Agent, Persona, Report, load_config, round_table
from mirofish_lab.config import verify_model
from mirofish_lab.github import fetch_pr
from mirofish_lab.personas import JUDGE_PERSONA
from mirofish_lab.repo import (
    Subsystem,
    cluster_into_subsystems,
    extract_symbols,
    grep_callers,
    parse_unified_diff,
    python_files,
)


def changed_symbols(diff_text: str, repo_root: Path) -> list[tuple[str, Path, int]]:
    """For each modified line in the diff, find the enclosing AST symbol."""
    out: list[tuple[str, Path, int]] = []
    for rel_path, line_nums in parse_unified_diff(diff_text):
        full = repo_root / rel_path
        if not full.exists() or full.suffix != ".py":
            continue
        syms = extract_symbols(full)
        if not syms:
            continue
        for ln in line_nums:
            best: tuple[str, Path, int] | None = None
            for s in syms:
                if s.lineno <= ln and (best is None or s.lineno > best[2]):
                    best = (s.name, full, s.lineno)
            if best is not None and best not in out:
                out.append(best)
    return out


def affected_subsystems(
    repo_root: Path,
    changed: list[tuple[str, Path, int]],
    all_subs: list[Subsystem],
) -> list[Subsystem]:
    """Subsystems are 'affected' if any of their files mentions a changed symbol."""
    affected: list[Subsystem] = []
    changed_files = {p.resolve() for _, p, _ in changed}
    for sub in all_subs:
        sub_files_resolved = {f.resolve() for f in sub.files}
        # Subsystem hit if it contains a changed file OR grep-matches any changed symbol.
        if sub_files_resolved & changed_files:
            affected.append(sub)
            continue
        for sym_name, _, _ in changed:
            callers = grep_callers(repo_root, sym_name)
            if any(c.resolve() in sub_files_resolved for c in callers):
                affected.append(sub)
                break
    return affected


def make_subsystem_persona(sub: Subsystem) -> Persona:
    return Persona(
        name=f"Subsys[{sub.name}]",
        role=f"owner of subsystem '{sub.name}'",
        system_prompt=(
            f"You are the engineer who owns the '{sub.name}' subsystem of this "
            f"codebase. {sub.description} You speak only for what your subsystem "
            f"does and how it would react to a change. You are precise about "
            f"what would break, what would still work, and what you'd need to "
            f"check. You do not speculate beyond your area.\n\n"
            f"Sample of your subsystem's code:\n\n{sub.files_summary()}"
        ),
    )


def run(diff_text: str, repo_root: Path, *, out_path: Path, source_label: str) -> Path:
    cfg = load_config()
    print(f"[config] model={cfg.model}", file=sys.stderr)
    verify_model(cfg)

    print(f"[scan] cataloguing {len(python_files(repo_root))} Python files", file=sys.stderr)
    all_subs = cluster_into_subsystems(repo_root)
    print(f"[scan] {len(all_subs)} subsystems: {', '.join(s.name for s in all_subs)}", file=sys.stderr)

    changed = changed_symbols(diff_text, repo_root)
    print(f"[diff] {len(changed)} changed symbols: {[s for s, _, _ in changed[:8]]}", file=sys.stderr)

    affected = affected_subsystems(repo_root, changed, all_subs)
    print(f"[blast] {len(affected)} affected subsystems: {[s.name for s in affected]}", file=sys.stderr)
    if not affected:
        affected = all_subs[:3]
        print(f"[blast] (no specific match; falling back to first {len(affected)})", file=sys.stderr)

    agents = [Agent(make_subsystem_persona(s), cfg) for s in affected]

    seed = (
        f"# Proposed change\n\n"
        f"Source: {source_label}\n\n"
        f"Changed symbols (name, file, line):\n"
        + "\n".join(f"- `{n}` in `{p.relative_to(repo_root)}`:{ln}" for n, p, ln in changed[:30])
        + f"\n\n## Diff\n\n```diff\n{diff_text[:30000]}\n```\n\n"
        f"As your subsystem's owner, predict: what breaks in your subsystem, "
        f"what still works, what you would need to check, and what migration "
        f"steps your callers would need."
    )

    print(f"[sim] round-table with {len(agents)} subsystem agents", file=sys.stderr)
    transcript = round_table(agents, seed_prompt=seed, rounds=1)

    judge = Agent(JUDGE_PERSONA, cfg)
    discussion = "\n\n".join(f"### {t.speaker}\n{t.content}" for t in transcript)
    verdict = judge.respond(
        f"# Proposed change\n{seed}\n\n# Subsystem reactions\n{discussion}\n\n"
        f"Produce a roll-up: per-subsystem risk in [low/medium/high], blocking "
        f"issues, recommended migration order, and any subsystems whose response "
        f"sounds confused (likely indicating you should give them more context "
        f"before merging)."
    )

    out = Report(
        title=f"Blast-radius prediction — {source_label}",
        meta={
            "Repo root": str(repo_root),
            "Changed symbols": str(len(changed)),
            "Affected subsystems": str(len(affected)),
            "Model": cfg.model,
        },
    )
    out.add("Changed symbols", "\n".join(f"- `{n}` in `{p.relative_to(repo_root)}`:{ln}" for n, p, ln in changed) or "_(none detected)_")
    for t in transcript:
        out.add(t.speaker, t.content)
    out.add("Judge roll-up", verdict.content)

    written = out.write(out_path)
    print(f"[done] wrote {written}", file=sys.stderr)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Predict blast radius of a diff via subsystem agents.")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--pr", help="GitHub PR URL")
    src.add_argument("--diff", type=Path, help="Path to a unified diff file")
    parser.add_argument("--repo", type=Path, required=True, help="Path to the repo on disk")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)

    if not args.repo.exists():
        parser.error(f"--repo path does not exist: {args.repo}")

    if args.pr:
        pr = fetch_pr(args.pr)
        diff_text = pr.diff
        label = f"PR {pr.owner}/{pr.repo}#{pr.number}"
        slug = f"{pr.owner}_{pr.repo}_pr{pr.number}"
    else:
        diff_text = args.diff.read_text()
        label = str(args.diff)
        slug = args.diff.stem

    if args.out is None:
        args.out = Path("blast-radius-prediction/reports") / f"{slug}.md"

    run(diff_text, args.repo.resolve(), out_path=args.out, source_label=label)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
