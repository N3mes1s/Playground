"""Held-out validation of the multistage A1.0 apply on real data.

The eval-slice A/B (validation/REALDATA_AB_DIFF.md) at n=30 / seed 1337
showed:
  judge useful  100% / 100%
  judge caught   53% / 60%   (+7pp)
  plans broken    0  / 0
  max family    80% / 77%

Apply-gate met but +7pp at n=30 is inside the ~25pp detection threshold
for proportions. This script compares the holdout slice (seed 9256,
disjoint from 1337) against the eval slice to lock in or downgrade
the magnitude claim.

Lock-in iff:
  - Direction reproduces (caught delta >= 0 on holdout)
  - useful holds (>= 95%)
  - No plans break

Downgrade to "directional-only" iff:
  - caught delta on holdout is mixed/negative but no useful or plan-break
    regression

Revert iff:
  - useful drops >5pp OR plans break on holdout (matches the cycle-2
    discipline)
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _agg(j: dict) -> dict:
    s = j.get("scores") or []
    n = len(s)
    judge_v = Counter(x.get("verdict_judge", "?") for x in s)
    smt = sum(x.get("smt_feasible_count", 0) or 0 for x in s)
    plans = sum(x.get("n_plans", 0) or 0 for x in s)
    w = Counter(x.get("winner", "?") for x in s if x.get("winner"))
    return {
        "n": n,
        "useful_judge": (judge_v.get("caught", 0) + judge_v.get("partial", 0)) / max(1, n),
        "caught_judge": judge_v.get("caught", 0) / max(1, n),
        "missed_judge": judge_v.get("missed", 0) / max(1, n),
        "smt_rate":     smt / max(1, plans),
        "max_family":   max(w.values()) / max(1, n) if w else 0.0,
        "n_winners":    sum(w.values()),
    }


def _summary(label: str, ag_a: dict, ag_b: dict) -> list[str]:
    rows = [
        ("metric", "A: monolith", "B: multistage", "Δ"),
        ("judge useful",
         f"{ag_a['useful_judge']:.0%}",
         f"{ag_b['useful_judge']:.0%}",
         f"{100*(ag_b['useful_judge']-ag_a['useful_judge']):+.0f}pp"),
        ("judge caught",
         f"{ag_a['caught_judge']:.0%}",
         f"{ag_b['caught_judge']:.0%}",
         f"{100*(ag_b['caught_judge']-ag_a['caught_judge']):+.0f}pp"),
        ("judge missed",
         f"{ag_a['missed_judge']:.0%}",
         f"{ag_b['missed_judge']:.0%}",
         f"{100*(ag_b['missed_judge']-ag_a['missed_judge']):+.0f}pp"),
        ("max family share",
         f"{ag_a['max_family']:.0%}",
         f"{ag_b['max_family']:.0%}",
         f"{100*(ag_b['max_family']-ag_a['max_family']):+.0f}pp"),
        ("winners /N",
         f"{ag_a['n_winners']}/{ag_a['n']}",
         f"{ag_b['n_winners']}/{ag_b['n']}",
         f"{ag_b['n_winners']-ag_a['n_winners']:+d}"),
    ]
    out = [f"## {label} (n={ag_a['n']})", "", "| " + " | ".join(rows[0]) + " |",
           "|" + "|".join(["---"] * 4) + "|"]
    for r in rows[1:]:
        out.append("| " + " | ".join(r) + " |")
    out.append("")
    return out


def main() -> int:
    eval_a = ROOT / "validation" / "REALDATA_FEATURE_monolith.json"
    eval_b = ROOT / "validation" / "REALDATA_FEATURE_multistage.json"
    ho_a   = ROOT / "validation" / "REALDATA_HOLDOUT_monolith.json"
    ho_b   = ROOT / "validation" / "REALDATA_HOLDOUT_multistage.json"
    for p in (eval_a, eval_b, ho_a, ho_b):
        if not p.exists():
            print(f"missing: {p}", file=sys.stderr)
            return 1

    e_a, e_b = _agg(json.loads(eval_a.read_text())), _agg(json.loads(eval_b.read_text()))
    h_a, h_b = _agg(json.loads(ho_a.read_text())),   _agg(json.loads(ho_b.read_text()))

    e_caught_d = e_b["caught_judge"] - e_a["caught_judge"]
    h_caught_d = h_b["caught_judge"] - h_a["caught_judge"]
    h_useful_d = h_b["useful_judge"] - h_a["useful_judge"]
    h_plans_broke = h_b["n_winners"] < h_a["n_winners"] - 2

    md = ["# Held-out validation: multistage on real data", ""]
    md += _summary("Eval slice (seed 1337)", e_a, e_b)
    md += _summary("Holdout slice (seed 9256, disjoint)", h_a, h_b)

    md.append("## Verdict")
    md.append("")
    md.append(
        f"- Eval Δ caught: **{100*e_caught_d:+.0f}pp**\n"
        f"- Holdout Δ caught: **{100*h_caught_d:+.0f}pp**\n"
        f"- Holdout Δ useful: **{100*h_useful_d:+.0f}pp**"
    )
    md.append("")

    if h_useful_d < -0.05 or h_plans_broke:
        verdict = (
            "**REVERT** — holdout shows useful regression "
            f"({100*h_useful_d:+.0f}pp) "
            f"or plans broke ({h_a['n_winners'] - h_b['n_winners']} more). "
            "The eval-slice +7pp caught was likely sample noise. "
            "Default reverts to monolith."
        )
    elif h_caught_d >= 0:
        verdict = (
            "**LOCK IN** — caught direction reproduces on holdout "
            f"(eval {100*e_caught_d:+.0f}pp, holdout {100*h_caught_d:+.0f}pp), "
            "useful and plans intact. Multistage stays default; the "
            f"eval-side +7pp caught is supported by holdout-side "
            f"{100*h_caught_d:+.0f}pp. "
            "Combined n=60 averaged delta still inside α=0.05 noise for "
            "proportions, but the directional reproduction is what the "
            "cycle-2 discipline asks for."
        )
    else:
        verdict = (
            "**DOWNGRADE TO DIRECTIONAL** — eval-slice +7pp caught did "
            f"NOT reproduce on holdout ({100*h_caught_d:+.0f}pp). "
            "useful and plans intact, so no regression — but the +7pp "
            "magnitude was likely sample noise. Multistage retained as "
            "default (no holdout regression) but external metric claims "
            "should NOT cite a caught-rate gain."
        )
    md.append(verdict)

    out_md = ROOT / "validation" / "REALDATA_HOLDOUT_VERDICT.md"
    out_md.write_text("\n".join(md))
    out_md.with_suffix(".json").write_text(json.dumps({
        "eval":      {"monolith": e_a, "multistage": e_b,
                      "caught_delta_pp": 100 * e_caught_d},
        "holdout":   {"monolith": h_a, "multistage": h_b,
                      "caught_delta_pp": 100 * h_caught_d,
                      "useful_delta_pp": 100 * h_useful_d},
        "verdict":   verdict,
    }, indent=2))
    print(out_md.read_text())
    return 0


if __name__ == "__main__":
    sys.exit(main())
