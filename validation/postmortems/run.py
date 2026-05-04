"""Retrospective validation harness for verified-rollout.

For each post-mortem case:
  1. Run verified-rollout PRO on the pre-incident intent.
  2. Score the output against expectations.json:
       - Was the violated constraint surfaced anywhere in the
         stakeholder constraints?
       - Did the conflicts list flag the relevant stakeholder pair?
       - Did open-questions / plan steps reference the root cause?
  3. Produce per-case verdicts: caught / partial / missed.
  4. Aggregate into validation/postmortems/REPORT.md.

Scoring uses TOKEN-OVERLAP against expectations.root_cause_keywords plus
EXPECTED-PAIR membership against expectations.expected_conflicts.
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
INTENTS_DIR = THIS / "intents"
REPORTS_DIR = THIS / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

EXPECTATIONS = json.loads((THIS / "expectations.json").read_text())["cases"]


_TOK = re.compile(r"[A-Za-z][A-Za-z0-9_-]+")


def _toks(s: str) -> set[str]:
    return {t.lower() for t in _TOK.findall(s or "") if len(t) > 2}


@dataclass
class CaseScore:
    case_id: str
    real_world: str
    constraint_keywords_hit: list[str] = field(default_factory=list)
    constraint_keywords_missed: list[str] = field(default_factory=list)
    expected_pair_hits: list[tuple[str, str]] = field(default_factory=list)
    expected_pair_misses: list[tuple[str, str]] = field(default_factory=list)
    plan_step_hits: list[str] = field(default_factory=list)
    open_question_hits: list[str] = field(default_factory=list)
    constraint_count: int = 0
    plan_step_count: int = 0
    conflict_count: int = 0
    smt_infeasible_count: int = 0
    fragility_winner: float = 0.0
    verdict: str = "missed"   # "caught" | "partial" | "missed"


def _score_case(case_id: str, sidecar_json: dict) -> CaseScore:
    exp = EXPECTATIONS[case_id]
    s = CaseScore(case_id=case_id, real_world=exp["real_world"])

    constraints = sidecar_json.get("constraints") or []
    plans = sidecar_json.get("plans") or {}
    smt = sidecar_json.get("smt") or {}
    chaos = sidecar_json.get("chaos") or {}
    pareto = sidecar_json.get("pareto") or {}
    winner_label = pareto.get("winner") or ""

    s.constraint_count = len(constraints)
    s.plan_step_count = sum(len((p.get("steps") or [])) for p in plans.values())
    s.smt_infeasible_count = sum(
        1 for v in smt.values() if not v.get("feasible", True)
    )
    if winner_label and winner_label in chaos:
        s.fragility_winner = float(chaos[winner_label].get("fragility", 0.0))

    # Token-overlap: were the root-cause keywords surfaced anywhere?
    haystack = []
    for c in constraints:
        haystack.append(
            " ".join(str(c.get(k, "") or "") for k in (
                "summary", "scope", "gate", "rollback"
            ))
        )
    plan_step_blob = []
    for label, plan in plans.items():
        for step in plan.get("steps") or []:
            blob = " ".join(str(step.get(k, "") or "") for k in (
                "action", "gate", "rollback", "observability"
            ))
            haystack.append(blob)
            plan_step_blob.append((label, step.get("id"), blob))
    open_qs = []
    for label, plan in plans.items():
        for q in plan.get("open_questions") or []:
            open_qs.append((label, str(q)))
            haystack.append(str(q))
    conflicts = []
    for label, plan in plans.items():
        for cf in plan.get("conflicts") or []:
            conflicts.append((label, cf))
            haystack.append(str(cf.get("issue", "")))

    haystack_tokens = set()
    for s_blob in haystack:
        haystack_tokens |= _toks(s_blob)

    for kw in exp["root_cause_keywords"]:
        if kw.lower() in haystack_tokens:
            s.constraint_keywords_hit.append(kw)
        else:
            s.constraint_keywords_missed.append(kw)

    # Expected-pair conflicts: see if any plan's conflicts list either
    # ordering of the expected pair.
    for pair in exp.get("expected_conflicts", []):
        a, b = pair[0], pair[1]
        hit = False
        for _label, cf in conflicts:
            between = [str(x) for x in cf.get("between") or []]
            if {a, b} <= set(between):
                hit = True
                break
        if hit:
            s.expected_pair_hits.append((a, b))
        else:
            s.expected_pair_misses.append((a, b))

    # Pull the most relevant plan steps + open questions for the report.
    for label, sid, blob in plan_step_blob:
        b_toks = _toks(blob)
        if any(kw.lower() in b_toks for kw in exp["root_cause_keywords"]):
            s.plan_step_hits.append(f"{label}:{sid} -> {blob[:140]}")
    for label, q in open_qs:
        q_toks = _toks(q)
        if any(kw.lower() in q_toks for kw in exp["root_cause_keywords"]):
            s.open_question_hits.append(f"{label}: {q[:140]}")

    # Verdict thresholds.
    kw_hit_ratio = len(s.constraint_keywords_hit) / max(
        1, len(exp["root_cause_keywords"])
    )
    pair_hit_ratio = len(s.expected_pair_hits) / max(
        1, len(exp.get("expected_conflicts", []) or [(None, None)])
    )
    if kw_hit_ratio >= 0.6 or (kw_hit_ratio >= 0.4 and pair_hit_ratio >= 0.5):
        s.verdict = "caught"
    elif kw_hit_ratio >= 0.3 or pair_hit_ratio >= 0.5:
        s.verdict = "partial"
    else:
        s.verdict = "missed"
    return s


def _run_pipeline(intent_path: Path, out_path: Path) -> Path:
    """Invoke verified-rollout/cli_pro.py as a subprocess.

    Returns the json sidecar path.
    """
    json_path = out_path.with_suffix(".json")
    if json_path.exists():
        print(f"[skip] {json_path} exists", file=sys.stderr)
        return json_path
    env = dict(os.environ)
    env.setdefault("MODEL", "gpt-5.4-mini")
    env.setdefault("MAX_TOKENS", "2200")
    cmd = [
        sys.executable,
        str(ROOT / "verified-rollout" / "cli_pro.py"),
        str(intent_path),
        "--n-plans", "4",          # smaller frontier for batch runs
        "--chaos-pairs", "1",
        "--utility", "fragility=0.4,coverage=0.3,steps=0.1,severity=0.15,rollback_failure=0.05",
        "--out", str(out_path),
    ]
    print(f"[run] {intent_path.name}", file=sys.stderr)
    res = subprocess.run(cmd, env=env, cwd=str(ROOT), capture_output=True, text=True)
    if res.returncode != 0:
        print("--- stdout ---\n" + res.stdout, file=sys.stderr)
        print("--- stderr ---\n" + res.stderr, file=sys.stderr)
        raise RuntimeError(f"pipeline failed for {intent_path.name}")
    return json_path


def main() -> None:
    intents = sorted(INTENTS_DIR.glob("*.md"))
    if not intents:
        print("no intents found", file=sys.stderr)
        return
    scores: list[CaseScore] = []
    for intent in intents:
        case_id = intent.stem
        if case_id not in EXPECTATIONS:
            print(f"[warn] no expectations for {case_id}, skipping", file=sys.stderr)
            continue
        out_path = REPORTS_DIR / f"{case_id}.pro.md"
        json_path = _run_pipeline(intent, out_path)
        sidecar = json.loads(json_path.read_text())
        score = _score_case(case_id, sidecar)
        scores.append(score)
        print(
            f"[score] {case_id}: verdict={score.verdict} "
            f"kw_hits={len(score.constraint_keywords_hit)}/"
            f"{len(score.constraint_keywords_hit)+len(score.constraint_keywords_missed)} "
            f"pair_hits={len(score.expected_pair_hits)}",
            file=sys.stderr,
        )

    # Build aggregate report.
    out_md = THIS / "REPORT.md"
    lines = [
        "# Retrospective validation: verified-rollout vs 5 real public post-mortems",
        "",
        "Each case was a real public migration / rollout incident. We crafted "
        "an intent capturing the **pre-incident** state and ran "
        "`verified-rollout/cli_pro.py` against it, then scored whether the "
        "pipeline surfaced the constraint that was actually violated.",
        "",
        "## Verdicts",
        "",
        "| Case | Real-world incident | Verdict | KW hits | Pair hits | SMT infeasible | Winner fragility |",
        "|---|---|---|---|---|---|---|",
    ]
    counts = {"caught": 0, "partial": 0, "missed": 0}
    for s in scores:
        counts[s.verdict] += 1
        kw_total = len(s.constraint_keywords_hit) + len(s.constraint_keywords_missed)
        pair_total = len(s.expected_pair_hits) + len(s.expected_pair_misses)
        lines.append(
            f"| `{s.case_id}` | {s.real_world[:80]}... | "
            f"**{s.verdict}** | "
            f"{len(s.constraint_keywords_hit)}/{kw_total} | "
            f"{len(s.expected_pair_hits)}/{pair_total} | "
            f"{s.smt_infeasible_count} | {s.fragility_winner:.2f} |"
        )
    lines.append("")
    lines.append(f"**Aggregate**: caught={counts['caught']}, partial={counts['partial']}, missed={counts['missed']} (out of {len(scores)})")
    lines.append("")

    for s in scores:
        lines.append(f"## {s.case_id} — verdict: **{s.verdict}**")
        lines.append("")
        lines.append(f"**Real-world incident**: {s.real_world}")
        lines.append("")
        lines.append(
            f"- constraint keywords surfaced: "
            f"{len(s.constraint_keywords_hit)}/"
            f"{len(s.constraint_keywords_hit) + len(s.constraint_keywords_missed)}: "
            + (", ".join(f"`{k}`" for k in s.constraint_keywords_hit) or "_none_")
        )
        if s.constraint_keywords_missed:
            lines.append(
                f"- keywords MISSED: " + ", ".join(f"`{k}`" for k in s.constraint_keywords_missed)
            )
        lines.append(
            f"- expected stakeholder-conflict pairs: "
            f"{len(s.expected_pair_hits)}/"
            f"{len(s.expected_pair_hits) + len(s.expected_pair_misses)} hit"
        )
        for p in s.expected_pair_hits:
            lines.append(f"  - HIT: {p[0]} ↔ {p[1]}")
        for p in s.expected_pair_misses:
            lines.append(f"  - miss: {p[0]} ↔ {p[1]}")
        lines.append("")
        if s.plan_step_hits:
            lines.append("- plan steps that referenced the root cause:")
            for h in s.plan_step_hits[:5]:
                lines.append(f"  - {h}")
            lines.append("")
        if s.open_question_hits:
            lines.append("- open questions that referenced the root cause:")
            for h in s.open_question_hits[:5]:
                lines.append(f"  - {h}")
            lines.append("")
        lines.append(
            f"- pipeline output: {s.constraint_count} constraints, "
            f"{s.plan_step_count} plan steps across all frontier plans, "
            f"{s.smt_infeasible_count} plans proven infeasible by Z3, "
            f"winner fragility {s.fragility_winner:.2f}"
        )
        lines.append("")
    out_md.write_text("\n".join(lines))
    print(f"\n[done] wrote {out_md}")


if __name__ == "__main__":
    main()
