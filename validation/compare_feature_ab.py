"""Compare FEATURE_BASELINE_N50 (balanced weights) vs FEATURE_BASELINE_N50_safe
(slip_risk-dominant weights). Same seed 1337 and source set, so the
element set is identical.

Decides whether the riskward rebalance actually surfaces robust_launch
and improves caught_rate (the open question from the N=48 baseline).
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


def _agg(j: dict) -> dict:
    scores = j.get("scores") or []
    n = len(scores)
    lit = j.get("literal_verdicts") or {}
    jud = j.get("judge_verdicts") or {}
    winners = Counter(s.get("winner", "?") for s in scores
                      if s.get("winner"))
    strat_ok = sum(1 for s in scores
                   if "literal" in s
                   and s["literal"].get("launch_strategy_ok"))
    sec_ok = sum(1 for s in scores
                 if "literal" in s
                 and (not s["literal"].get("regulated")
                      or s["literal"].get("security_step_present")))
    return {
        "n": n,
        "literal_caught_rate": (lit.get("caught", 0)) / max(1, n),
        "literal_useful_rate": (lit.get("caught", 0) + lit.get("partial", 0)) / max(1, n),
        "judge_caught_rate": (jud.get("caught", 0)) / max(1, n),
        "judge_useful_rate": (jud.get("caught", 0) + jud.get("partial", 0)) / max(1, n),
        "winners": dict(winners),
        "max_family_share": max(winners.values()) / max(1, n) if winners else 0.0,
        "launch_strategy_ok_rate": strat_ok / max(1, n),
        "security_step_compliance_rate": sec_ok / max(1, n),
    }


def main() -> int:
    a_path = ROOT / "validation" / "FEATURE_BASELINE_N50.json"
    b_path = ROOT / "validation" / "FEATURE_BASELINE_N50_safe.json"
    if not b_path.exists():
        print(f"missing: {b_path}", file=sys.stderr)
        return 1
    a = _load(a_path)
    b = _load(b_path)
    agg_a = _agg(a)
    agg_b = _agg(b)

    # Same elements check
    ids_a = {s["id"] for s in a.get("scores", [])}
    ids_b = {s["id"] for s in b.get("scores", [])}
    overlap = ids_a & ids_b
    print(f"elements: A={len(ids_a)} B={len(ids_b)} overlap={len(overlap)}",
          file=sys.stderr)

    # Per-element transitions on judge verdict
    by_id_a = {s["id"]: s for s in a.get("scores", [])}
    by_id_b = {s["id"]: s for s in b.get("scores", [])}
    transitions = Counter()
    for eid in sorted(overlap):
        va = (by_id_a[eid].get("judge") or {}).get("verdict", "?")
        vb = (by_id_b[eid].get("judge") or {}).get("verdict", "?")
        transitions[f"{va} -> {vb}"] += 1

    out_md = ROOT / "validation" / "FEATURE_AB_balanced_vs_safe_DIFF.md"
    out_json = out_md.with_suffix(".json")

    summary = {
        "n_overlap": len(overlap),
        "agg_balanced": agg_a,
        "agg_safe": agg_b,
        "judge_transitions": dict(transitions),
        "delta_judge_caught_pp": 100 * (agg_b["judge_caught_rate"] - agg_a["judge_caught_rate"]),
        "delta_max_family_share_pp": 100 * (agg_b["max_family_share"] - agg_a["max_family_share"]),
        "delta_launch_strat_ok_pp": 100 * (agg_b["launch_strategy_ok_rate"] - agg_a["launch_strategy_ok_rate"]),
    }
    out_json.write_text(json.dumps(summary, indent=2))

    rows = [
        ("metric", "A: balanced", "B: safe", "Δ"),
        ("literal caught_rate",
         f"{agg_a['literal_caught_rate']:.0%}",
         f"{agg_b['literal_caught_rate']:.0%}",
         f"{100*(agg_b['literal_caught_rate']-agg_a['literal_caught_rate']):+.0f}pp"),
        ("judge caught_rate",
         f"{agg_a['judge_caught_rate']:.0%}",
         f"{agg_b['judge_caught_rate']:.0%}",
         f"{100*(agg_b['judge_caught_rate']-agg_a['judge_caught_rate']):+.0f}pp"),
        ("judge useful_rate",
         f"{agg_a['judge_useful_rate']:.0%}",
         f"{agg_b['judge_useful_rate']:.0%}",
         f"{100*(agg_b['judge_useful_rate']-agg_a['judge_useful_rate']):+.0f}pp"),
        ("max family share",
         f"{agg_a['max_family_share']:.0%}",
         f"{agg_b['max_family_share']:.0%}",
         f"{100*(agg_b['max_family_share']-agg_a['max_family_share']):+.0f}pp"),
        ("launch_strategy_ok",
         f"{agg_a['launch_strategy_ok_rate']:.0%}",
         f"{agg_b['launch_strategy_ok_rate']:.0%}",
         f"{100*(agg_b['launch_strategy_ok_rate']-agg_a['launch_strategy_ok_rate']):+.0f}pp"),
    ]

    md = [
        f"# Feature A/B: balanced vs safe (n={len(overlap)} matched)",
        "",
        "## Aggregate metrics",
        "",
        "| " + " | ".join(rows[0]) + " |",
        "|" + "|".join(["---"] * 4) + "|",
    ]
    for r in rows[1:]:
        md.append("| " + " | ".join(r) + " |")
    md += [
        "",
        f"_A: --prefer balanced (default 0.30/0.25/0.30/0.15)._",
        f"_B: --prefer safe (0.15/0.20/0.50/0.15)._",
        "",
        "## Winner-family distribution",
        "",
        "| variant | A: balanced | B: safe |",
        "|---|---|---|",
    ]
    families = sorted(set(agg_a["winners"]) | set(agg_b["winners"]))
    for fam in families:
        md.append(
            f"| `{fam}` | {agg_a['winners'].get(fam, 0)} | "
            f"{agg_b['winners'].get(fam, 0)} |"
        )

    md += ["", "## Per-element judge-verdict transitions", "",
           "| transition | count |", "|---|---|"]
    for k, v in sorted(transitions.items(), key=lambda kv: -kv[1]):
        md.append(f"| {k} | {v} |")

    md += [
        "",
        "## Verdict",
        "",
    ]
    delta = agg_b["judge_caught_rate"] - agg_a["judge_caught_rate"]
    family_delta = agg_b["max_family_share"] - agg_a["max_family_share"]

    if delta > 0.05 and family_delta < 0:
        md.append(
            "> **APPLY safe.** judge caught_rate is up "
            f"{100*delta:+.0f}pp AND max-family-share is down "
            f"{100*family_delta:+.0f}pp. Both targets improved."
        )
    elif delta > 0.02 and family_delta < 0:
        md.append(
            "> **TENTATIVE: apply with care.** judge caught_rate up "
            f"{100*delta:+.0f}pp; family-share down "
            f"{100*family_delta:+.0f}pp; both small. Consider a held-out "
            "validation before persisting (cycle-4 lesson)."
        )
    elif delta < -0.02:
        md.append(
            "> **DO NOT apply.** safe weights regress judge caught_rate by "
            f"{100*delta:+.0f}pp. Keep balanced as default."
        )
    else:
        md.append(
            "> **No clear winner.** judge caught_rate Δ "
            f"{100*delta:+.0f}pp, family-share Δ "
            f"{100*family_delta:+.0f}pp. Both within noise. The "
            "polish_coverage metric or sequencer prompts may need work "
            "before weight-tuning matters."
        )

    out_md.write_text("\n".join(md))
    print(out_md.read_text())
    return 0


if __name__ == "__main__":
    sys.exit(main())
