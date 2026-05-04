"""Compare cli_feature monolith vs multistage on REAL data
(SWE-Bench Verified + danluu post-mortems), scored by the
rollout-style LLM judge (dataset/bench/llm_judge.py) which uses
files_touched / root_cause_keywords / outcome — semantic GT grounded
in actual shipped patches and post-mortems, NOT the synthetic
template GT that may have saturated.

Hypothesis being tested: the synthetic-N=48 multistage regression
may not reproduce on real data, where the GT is grounded in actual
code/outcomes rather than template opinion.

Apply gate (per the cycle-2 discipline):
  judge_caught_rate gain > +5pp at N=30
  AND useful_rate not down > 2pp
  AND no axis collapses
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
    # Rollout-judge fields
    judge_v = Counter(x.get("verdict_judge", "?") for x in s)
    lit_v = Counter(x.get("verdict", "?") for x in s)
    smt = sum(x.get("smt_feasible_count", 0) or 0 for x in s)
    plans = sum(x.get("n_plans", 0) or 0 for x in s)
    w = Counter(x.get("winner", "?") for x in s if x.get("winner"))
    return {
        "n": n,
        "judge_v": dict(judge_v),
        "lit_v": dict(lit_v),
        "useful_judge": (judge_v.get("caught", 0) + judge_v.get("partial", 0)) / max(1, n),
        "caught_judge": judge_v.get("caught", 0) / max(1, n),
        "missed_judge": judge_v.get("missed", 0) / max(1, n),
        "smt_rate":     smt / max(1, plans),
        "winners":      dict(w),
        "max_family":   max(w.values()) / max(1, n) if w else 0.0,
        "n_with_winner": sum(w.values()),
    }


def _per_element_diff(a: dict, b: dict):
    by_a = {x["id"]: x for x in (a.get("scores") or [])}
    by_b = {x["id"]: x for x in (b.get("scores") or [])}
    overlap = set(by_a) & set(by_b)
    trans: Counter = Counter()
    for eid in overlap:
        va = by_a[eid].get("verdict_judge", "?")
        vb = by_b[eid].get("verdict_judge", "?")
        trans[f"{va} -> {vb}"] += 1
    return trans, overlap


def main() -> int:
    a_path = ROOT / "validation" / "REALDATA_FEATURE_monolith.json"
    b_path = ROOT / "validation" / "REALDATA_FEATURE_multistage.json"
    if not (a_path.exists() and b_path.exists()):
        print("missing artifacts", file=sys.stderr)
        return 1
    a = json.loads(a_path.read_text())
    b = json.loads(b_path.read_text())
    ag_a = _agg(a)
    ag_b = _agg(b)
    trans, overlap = _per_element_diff(a, b)

    rows = [
        ("metric", "A: monolith", "B: multistage", "Δ"),
        ("judge useful", f"{ag_a['useful_judge']:.0%}",
                         f"{ag_b['useful_judge']:.0%}",
                         f"{100*(ag_b['useful_judge']-ag_a['useful_judge']):+.0f}pp"),
        ("judge caught ←target",
                         f"{ag_a['caught_judge']:.0%}",
                         f"{ag_b['caught_judge']:.0%}",
                         f"{100*(ag_b['caught_judge']-ag_a['caught_judge']):+.0f}pp"),
        ("judge missed", f"{ag_a['missed_judge']:.0%}",
                         f"{ag_b['missed_judge']:.0%}",
                         f"{100*(ag_b['missed_judge']-ag_a['missed_judge']):+.0f}pp"),
        ("SMT feasibility",
                         f"{ag_a['smt_rate']:.0%}",
                         f"{ag_b['smt_rate']:.0%}",
                         f"{100*(ag_b['smt_rate']-ag_a['smt_rate']):+.0f}pp"),
        ("max family share",
                         f"{ag_a['max_family']:.0%}",
                         f"{ag_b['max_family']:.0%}",
                         f"{100*(ag_b['max_family']-ag_a['max_family']):+.0f}pp"),
        ("winners /N",   f"{ag_a['n_with_winner']}/{ag_a['n']}",
                         f"{ag_b['n_with_winner']}/{ag_b['n']}",
                         f"{ag_b['n_with_winner']-ag_a['n_with_winner']:+d}"),
    ]

    md = [
        f"# Real-data A/B at n={len(overlap)}: monolith vs multistage",
        "",
        f"_SWE-Bench Verified + danluu post-mortems, seed 1337, "
        f"rollout-style LLM judge (files_touched / root_cause_keywords / outcome)._",
        "",
        "## Aggregate metrics",
        "",
        "| " + " | ".join(rows[0]) + " |",
        "|" + "|".join(["---"] * 4) + "|",
    ]
    for r in rows[1:]:
        md.append("| " + " | ".join(r) + " |")

    md += ["", "## Winner distribution", "",
           "| variant | A | B |", "|---|---|---|"]
    for v in sorted(set(ag_a["winners"]) | set(ag_b["winners"])):
        md.append(f"| `{v}` | {ag_a['winners'].get(v, 0)} | {ag_b['winners'].get(v, 0)} |")

    md += ["", "## Per-element judge transitions (A → B)", "",
           "| transition | count |", "|---|---|"]
    for k, v in sorted(trans.items(), key=lambda kv: -kv[1]):
        md.append(f"| {k} | {v} |")

    md += ["", "## Verdict", ""]
    caught_d = ag_b["caught_judge"] - ag_a["caught_judge"]
    useful_d = ag_b["useful_judge"] - ag_a["useful_judge"]
    plans_broke = ag_b["n_with_winner"] < ag_a["n_with_winner"] - 2

    if caught_d > 0.05 and useful_d > -0.02 and not plans_broke:
        verdict = (
            f"**APPLY ON REAL DATA** — judge caught {100*caught_d:+.0f}pp, "
            f"useful {100*useful_d:+.0f}pp. The synthetic-N=48 regression "
            "did NOT reproduce on real-data GT — confirms the synthetic "
            "dataset's expected_launch_strategy was the bottleneck. "
            "Re-instate multistage as default for cli_feature."
        )
    elif useful_d < -0.05 or plans_broke:
        reasons = []
        if useful_d < -0.05:
            reasons.append(f"useful dropped {100*useful_d:+.0f}pp")
        if plans_broke:
            reasons.append(f"{ag_a['n_with_winner']-ag_b['n_with_winner']} more plans broke")
        verdict = (
            "**REVERT CONFIRMED** — multistage regresses on real data too: "
            + "; ".join(reasons) + ". Architectural decomposition is the "
            "wrong direction; the synthetic-saturation hypothesis is "
            "REFUTED — multistage is genuinely worse, not just opinion-mismatched."
        )
    else:
        verdict = (
            f"**INCONCLUSIVE** — judge caught Δ {100*caught_d:+.0f}pp, "
            f"useful Δ {100*useful_d:+.0f}pp at n={ag_a['n']}. Within noise "
            "for real-data variance. n=30 has roughly ±25pp detection threshold "
            "for proportions. Multistage stays opt-in; bigger n=60+ would be "
            "needed to disambiguate."
        )
    md.append(verdict)

    out_md = ROOT / "validation" / "REALDATA_AB_DIFF.md"
    out_md.write_text("\n".join(md))
    out_md.with_suffix(".json").write_text(json.dumps({
        "agg_monolith": ag_a,
        "agg_multistage": ag_b,
        "transitions": dict(trans),
        "deltas_pp": {
            "caught_judge": 100 * caught_d,
            "useful_judge": 100 * useful_d,
            "missed_judge": 100 * (ag_b["missed_judge"] - ag_a["missed_judge"]),
            "smt_rate": 100 * (ag_b["smt_rate"] - ag_a["smt_rate"]),
        },
        "verdict": verdict,
    }, indent=2))
    print(out_md.read_text())
    return 0


if __name__ == "__main__":
    sys.exit(main())
