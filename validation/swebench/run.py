"""SWE-Bench Verified validation harness for pre-flight-rehearsal.

For 5 sampled SWE-Bench Verified issues:
  1. Build a pre-flight-rehearsal-shaped issue fixture from the
     `problem_statement` field.
  2. Run pre-flight-rehearsal/cli.py against it.
  3. Compare the Judge-picked plan's content (action / diff sketch /
     risks) to the canonical `patch` from the dataset.
  4. Score per case:
       - file overlap: did the picked plan name the file(s) the
         canonical patch touches?
       - token overlap: how much of the canonical patch's
         distinctive vocabulary appears in the picked plan?
       - judge-pick: which implementer style won?
  5. Aggregate into validation/swebench/REPORT.md.

This validates a different experiment (pre-flight-rehearsal) on a
different question (does the ranked-plans approach cover the strategy
that actually solved the issue?) than the post-mortem harness which
validates verified-rollout.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
THIS = Path(__file__).resolve().parent
FIXTURES_DIR = THIS / "fixtures"
REPORTS_DIR = THIS / "reports"
FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


_TOK = re.compile(r"[A-Za-z][A-Za-z0-9_]+")
_FILE_RE = re.compile(r"^\+\+\+ b/(.+)$", re.MULTILINE)


def _toks(s: str) -> set[str]:
    return {t.lower() for t in _TOK.findall(s or "") if len(t) > 3}


def _patch_files(patch: str) -> list[str]:
    return _FILE_RE.findall(patch)


def _patch_distinctive_tokens(patch: str) -> set[str]:
    """Tokens from the +/- lines of the patch that are likely meaningful
    (skip noise like 'def', 'self', 'return')."""
    noise = {
        "self", "return", "import", "from", "none", "true", "false",
        "the", "and", "for", "with", "this", "that", "into", "test",
        "tests", "args", "kwargs", "value", "default",
    }
    interesting: set[str] = set()
    for line in patch.splitlines():
        if not (line.startswith("+") or line.startswith("-")) or line.startswith("+++") or line.startswith("---"):
            continue
        for t in _TOK.findall(line):
            tl = t.lower()
            if len(tl) > 3 and tl not in noise:
                interesting.add(tl)
    return interesting


@dataclass
class SWECaseScore:
    instance_id: str
    repo: str
    canonical_files: list[str]
    canonical_patch_chars: int
    plan_files_mentioned: list[str] = field(default_factory=list)
    file_overlap_count: int = 0
    canonical_distinctive_tokens: int = 0
    distinctive_tokens_in_picked: int = 0
    judge_winner: str = ""
    judge_picked_plan_summary: str = ""
    verdict: str = "missed"


def _sample_cases(n: int = 5) -> list[dict]:
    from datasets import load_dataset

    ds = load_dataset("princeton-nlp/SWE-bench_Verified", split="test")
    # Diversity: different repos, manageable patch sizes (<2000 chars).
    by_repo: dict[str, list[dict]] = {}
    for r in ds:
        if len(r["patch"]) > 2000:
            continue
        by_repo.setdefault(r["repo"], []).append(r)
    out = []
    for repo in sorted(by_repo.keys())[:n]:
        rows = by_repo[repo]
        if rows:
            out.append(rows[0])
        if len(out) >= n:
            break
    return out


def _intent_for(case: dict) -> str:
    body = case["problem_statement"][:6000]
    return (
        f"# {case['instance_id']}\n\n"
        f"**Repository**: `{case['repo']}` at `{case['base_commit'][:8]}`\n\n"
        f"## Problem statement\n\n{body}\n\n"
        f"## What we're asking\n\nProduce a plan and a diff sketch that "
        f"would resolve this issue. Identify the file(s) you'd touch and "
        f"the key edits."
    )


def _build_fixture(case: dict) -> Path:
    fp = FIXTURES_DIR / f"{case['instance_id']}.json"
    if fp.exists():
        return fp
    issue = {
        "owner": case["repo"].split("/")[0],
        "repo": case["repo"].split("/")[1],
        "number": 0,
        "title": case["instance_id"],
        "body": _intent_for(case),
        "labels": ["swebench-verified"],
        "url": f"https://github.com/{case['repo']}/issues/{case['instance_id']}",
    }
    fp.write_text(json.dumps(issue, indent=2))
    return fp


def _run_preflight(fixture: Path, out_path: Path) -> Path:
    if out_path.exists():
        return out_path
    env = dict(os.environ)
    env.setdefault("MODEL", "gpt-5.4-mini")
    env.setdefault("MAX_TOKENS", "1800")
    cmd = [
        sys.executable,
        str(ROOT / "pre-flight-rehearsal" / "cli.py"),
        "--from-file", str(fixture),
        "--out", str(out_path),
    ]
    print(f"[run] {fixture.name}", file=sys.stderr)
    res = subprocess.run(cmd, env=env, cwd=str(ROOT), capture_output=True, text=True)
    if res.returncode != 0:
        print("--- stderr ---\n" + res.stderr[-2000:], file=sys.stderr)
        raise RuntimeError(f"preflight failed for {fixture.name}")
    return out_path


def _score_case(case: dict, report_path: Path) -> SWECaseScore:
    md = report_path.read_text()
    canonical_patch = case["patch"]
    canonical_files = _patch_files(canonical_patch)
    canonical_distinctive = _patch_distinctive_tokens(canonical_patch)

    score = SWECaseScore(
        instance_id=case["instance_id"],
        repo=case["repo"],
        canonical_files=canonical_files,
        canonical_patch_chars=len(canonical_patch),
        canonical_distinctive_tokens=len(canonical_distinctive),
    )

    # Identify the judge-picked plan (named in 'Judge Verdict' section).
    winner_match = re.search(
        r"##\s*Judge\s*Verdict[\s\S]+?\*\*Winner\*\*\s*[:\-]?\s*\n*\**(\w+)",
        md,
    )
    if winner_match:
        score.judge_winner = winner_match.group(1)
    else:
        # Fallback: any "Winner ... <Persona>" capitalised pattern.
        m = re.search(r"\*\*([A-Z][A-Za-z]+)\*\*\s*\n*\s*wins", md)
        if m:
            score.judge_winner = m.group(1)

    # Find the picked plan's section (Plan: <winner>) and extract its body.
    picked_body = ""
    if score.judge_winner:
        m = re.search(
            rf"^##\s*Plan:\s*{re.escape(score.judge_winner)}[\s\S]+?(?=^##\s|\Z)",
            md,
            re.MULTILINE,
        )
        if m:
            picked_body = m.group(0)
    if not picked_body:
        # Fallback: take all Plan sections combined.
        picked_body = "\n".join(re.findall(r"^##\s*Plan[\s\S]+?(?=^##\s|\Z)", md, re.MULTILINE))

    score.judge_picked_plan_summary = picked_body[:400].strip().replace("\n", " ")

    # File overlap.
    body_files = set()
    for fn in canonical_files:
        # Mention by full path or basename in plan body counts.
        if fn in picked_body or Path(fn).name in picked_body:
            body_files.add(fn)
    score.plan_files_mentioned = sorted(body_files)
    score.file_overlap_count = len(body_files)

    # Distinctive token overlap.
    body_toks = _toks(picked_body)
    overlap = canonical_distinctive & body_toks
    score.distinctive_tokens_in_picked = len(overlap)

    # Verdict.
    file_ratio = score.file_overlap_count / max(1, len(canonical_files))
    tok_ratio = score.distinctive_tokens_in_picked / max(1, score.canonical_distinctive_tokens)
    if file_ratio >= 0.5 and tok_ratio >= 0.20:
        score.verdict = "caught"
    elif file_ratio >= 0.5 or tok_ratio >= 0.10:
        score.verdict = "partial"
    else:
        score.verdict = "missed"
    return score


def main() -> None:
    cases = _sample_cases(5)
    if not cases:
        print("no cases", file=sys.stderr)
        return
    scores: list[SWECaseScore] = []
    for c in cases:
        fixture = _build_fixture(c)
        out_path = REPORTS_DIR / f"{c['instance_id']}.preflight.md"
        _run_preflight(fixture, out_path)
        score = _score_case(c, out_path)
        scores.append(score)
        print(
            f"[score] {c['instance_id']}: verdict={score.verdict} "
            f"files={score.file_overlap_count}/{len(score.canonical_files)} "
            f"toks={score.distinctive_tokens_in_picked}/{score.canonical_distinctive_tokens} "
            f"winner={score.judge_winner}",
            file=sys.stderr,
        )

    # Aggregate report.
    report_path = THIS / "REPORT.md"
    counts = {"caught": 0, "partial": 0, "missed": 0}
    lines = [
        "# SWE-Bench Verified validation: pre-flight-rehearsal",
        "",
        "5 sampled SWE-Bench Verified issues fed into "
        "`pre-flight-rehearsal/cli.py`. Per case we compare the Judge-"
        "picked implementer plan to the canonical patch.",
        "",
        "## Verdicts",
        "",
        "| Instance | Repo | Verdict | Files hit | Tokens hit | Judge winner |",
        "|---|---|---|---|---|---|",
    ]
    for s in scores:
        counts[s.verdict] += 1
        lines.append(
            f"| `{s.instance_id}` | `{s.repo}` | **{s.verdict}** | "
            f"{s.file_overlap_count}/{len(s.canonical_files)} | "
            f"{s.distinctive_tokens_in_picked}/{s.canonical_distinctive_tokens} | "
            f"{s.judge_winner or '—'} |"
        )
    lines.append("")
    lines.append(
        f"**Aggregate**: caught={counts['caught']}, "
        f"partial={counts['partial']}, missed={counts['missed']} "
        f"(out of {len(scores)})"
    )
    lines.append("")
    for s in scores:
        lines.append(f"## {s.instance_id} — verdict: **{s.verdict}**")
        lines.append("")
        lines.append(f"- repo: `{s.repo}`")
        lines.append(f"- canonical patch: {s.canonical_patch_chars} chars across {len(s.canonical_files)} files: {s.canonical_files}")
        lines.append(f"- judge winner: **{s.judge_winner or 'none-detected'}**")
        lines.append(f"- file overlap: {s.plan_files_mentioned or '_(none)_'}")
        lines.append(
            f"- distinctive-token overlap: {s.distinctive_tokens_in_picked}/"
            f"{s.canonical_distinctive_tokens} "
            f"({100 * s.distinctive_tokens_in_picked / max(1, s.canonical_distinctive_tokens):.0f}%)"
        )
        if s.judge_picked_plan_summary:
            lines.append(f"- picked plan first 400 chars: _{s.judge_picked_plan_summary}_")
        lines.append("")
    report_path.write_text("\n".join(lines))
    print(f"\n[done] wrote {report_path}")


if __name__ == "__main__":
    main()
