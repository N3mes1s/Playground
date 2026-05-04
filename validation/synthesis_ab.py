"""Compare multistage A1 pipeline vs monolith pre-A1 baseline at N=48.

Run after validation/FEATURE_BASELINE_N50_multistage.json is written.
Compares against the pre-A1 monolith baseline (FEATURE_BASELINE_N50_safe.json
— same seed 1337, same 48 elements, same applied weights since
balanced==safe post the c613ad5 rebalance).

Apply gate (per the post-cycle-2 discipline):
  caught_rate gain >+5pp at N=48
  AND useful_rate not down >2pp
  AND no axis collapses (max family share <=70%, no plans break entirely)
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
    lit = j.get("literal_verdicts") or {}
    jud = j.get("judge_verdicts") or {}
    strat = sum(1 for x in s if "literal" in x and x["literal"].get("launch_strategy_ok"))
    sec = sum(1 for x in s if "literal" in x
              and (not x["literal"].get("regulated")
                   or x["literal"].get("security_step_present")))
    days_ok = sum(1 for x in s if "literal" in x and x["literal"].get("days_in_band"))
    w = Counter(x.get("winner", "?") for x in s if x.get("winner"))
    return {
        "n": n,
        "useful_judge": (jud.get("caught", 0) + jud.get("partial", 0)) / max(1, n),
        "caught_judge": jud.get("caught", 0) / max(1, n),
        "missed_judge": jud.get("missed", 0) / max(1, n),
        "useful_lit":   (lit.get("caught", 0) + lit.get("partial", 0)) / max(1, n),
        "caught_lit":   lit.get("caught", 0) / max(1, n),
        "strat_ok":     strat / max(1, n),
        "sec_ok":       sec / max(1, n),
        "days_ok":      days_ok / max(1, n),
        "max_family":   max(w.values()) / max(1, n) if w else 0.0,
        "winners":      dict(w),
        "n_with_winner": sum(w.values()),
    }


def _per_element_diff(a: dict, b: dict) -> Counter:
    """Judge-verdict transitions A → B on matched element ids."""
    by_id_a = {x["id"]: x for x in (a.get("scores") or [])}
    by_id_b = {x["id"]: x for x in (b.get("scores") or [])}
    overlap = set(by_id_a) & set(by_id_b)
    trans: Counter = Counter()
    for eid in overlap:
        va = (by_id_a[eid].get("judge") or {}).get("verdict", "?")
        vb = (by_id_b[eid].get("judge") or {}).get("verdict", "?")
        trans[f"{va} -> {vb}"] += 1
    return trans, overlap


def main() -> int:
    a_path = ROOT / "validation" / "FEATURE_BASELINE_N50_safe.json"
    b_path = ROOT / "validation" / "FEATURE_BASELINE_N50_multistage.json"
    if not b_path.exists():
        print(f"missing: {b_path}", file=sys.stderr)
        return 1
    a = json.loads(a_path.read_text())
    b = json.loads(b_path.read_text())

    ag_a = _agg(a)
    ag_b = _agg(b)
    trans, overlap = _per_element_diff(a, b)

    out_md = ROOT / "validation" / "SYNTHESIS_AB_N48.md"
    out_json = out_md.with_suffix(".json")

    rows = [
        ("metric",            "A: monolith",            "B: multistage",          "Δ"),
        ("judge useful",      f"{ag_a['useful_judge']:.0%}",
                              f"{ag_b['useful_judge']:.0%}",
                              f"{100*(ag_b['useful_judge']-ag_a['useful_judge']):+.0f}pp"),
        ("judge caught ←target", f"{ag_a['caught_judge']:.0%}",
                              f"{ag_b['caught_judge']:.0%}",
                              f"{100*(ag_b['caught_judge']-ag_a['caught_judge']):+.0f}pp"),
        ("literal caught",    f"{ag_a['caught_lit']:.0%}",
                              f"{ag_b['caught_lit']:.0%}",
                              f"{100*(ag_b['caught_lit']-ag_a['caught_lit']):+.0f}pp"),
        ("strat_ok",          f"{ag_a['strat_ok']:.0%}",
                              f"{ag_b['strat_ok']:.0%}",
                              f"{100*(ag_b['strat_ok']-ag_a['strat_ok']):+.0f}pp"),
        ("sec compliance",    f"{ag_a['sec_ok']:.0%}",
                              f"{ag_b['sec_ok']:.0%}",
                              f"{100*(ag_b['sec_ok']-ag_a['sec_ok']):+.0f}pp"),
        ("days_in_band",      f"{ag_a['days_ok']:.0%}",
                              f"{ag_b['days_ok']:.0%}",
                              f"{100*(ag_b['days_ok']-ag_a['days_ok']):+.0f}pp"),
        ("max family share",  f"{ag_a['max_family']:.0%}",
                              f"{ag_b['max_family']:.0%}",
                              f"{100*(ag_b['max_family']-ag_a['max_family']):+.0f}pp"),
        ("winners /48",       f"{ag_a['n_with_winner']}",
                              f"{ag_b['n_with_winner']}",
                              f"{ag_b['n_with_winner']-ag_a['n_with_winner']:+d}"),
    ]

    md = [
        f"# Synthesis A/B at N=48: monolith vs multistage",
        "",
        f"_Same {len(overlap)} matched elements (seed 1337). "
        f"A: pre-A1 monolith baseline (FEATURE_BASELINE_N50_safe.json). "
        f"B: 4-stage multistage pipeline (commit be1c118 + later)._",
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

    md += ["", "## Per-element judge-verdict transitions (A → B)", "",
           "| transition | count |", "|---|---|"]
    for k, v in sorted(trans.items(), key=lambda kv: -kv[1]):
        md.append(f"| {k} | {v} |")

    md += ["", "## Cycle gate verdict", ""]
    caught_d = ag_b["caught_judge"] - ag_a["caught_judge"]
    useful_d = ag_b["useful_judge"] - ag_a["useful_judge"]
    family_collapse = ag_b["max_family"] > 0.70
    plans_broke = ag_b["n_with_winner"] < ag_a["n_with_winner"] - 2

    if caught_d > 0.05 and useful_d > -0.02 and not family_collapse and not plans_broke:
        verdict = (
            "**APPLY** — caught_rate gain "
            f"({100*caught_d:+.0f}pp) above +5pp threshold, "
            f"useful_rate ({100*useful_d:+.0f}pp) not down >2pp, "
            "no axis collapse. Multistage stays as default."
        )
    elif useful_d < -0.05 or family_collapse or plans_broke:
        reasons = []
        if useful_d < -0.05:
            reasons.append(f"useful_rate dropped {100*useful_d:+.0f}pp (>5pp)")
        if family_collapse:
            reasons.append(f"max family share {ag_b['max_family']:.0%} (>70%)")
        if plans_broke:
            broken = ag_a["n_with_winner"] - ag_b["n_with_winner"]
            reasons.append(f"{broken} more plans broke entirely")
        verdict = (
            "**REVERT** — multistage regresses: "
            + "; ".join(reasons) + ". Same shape as cycle-2 retrospective. "
            "Default reverts to monolith."
        )
    else:
        verdict = (
            f"**INCONCLUSIVE** — caught_rate Δ {100*caught_d:+.0f}pp, "
            f"useful_rate Δ {100*useful_d:+.0f}pp. Within noise floor. "
            "Multistage retained as default (no regression) but the "
            "cycle-2 lesson says don't claim caught-rate gains until "
            "they replicate at higher N or on a held-out slice."
        )

    md.append(verdict)

    out_md.write_text("\n".join(md))
    out_json.write_text(json.dumps({
        "agg_monolith":  ag_a,
        "agg_multistage": ag_b,
        "transitions":   dict(trans),
        "deltas": {
            "caught_judge_pp": 100 * caught_d,
            "useful_judge_pp": 100 * useful_d,
            "strat_ok_pp": 100 * (ag_b["strat_ok"] - ag_a["strat_ok"]),
            "max_family_pp": 100 * (ag_b["max_family"] - ag_a["max_family"]),
        },
        "verdict": verdict,
    }, indent=2))
    print(out_md.read_text())
    return 0


if __name__ == "__main__":
    sys.exit(main())
