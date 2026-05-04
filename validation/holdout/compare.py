"""Compare bench A (GEPA winner active) vs bench B (winner off) on the
held-out slice. Decides whether the +17pp / +0.183-composite gain from
GEPA cycle 4 generalises beyond the cycle's eval slice.

A = pareto_extra.txt active (winner persisted)
B = MIROFISH_PARETO_TAIL_EXTRA="" forces empty extension (pre-winner)

If A meaningfully beats B, the winner generalises and we keep
pareto_extra.txt. Otherwise the winner is an eval-slice artefact and
should be reverted.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "dataset" / "bench"))
from bench_ab import _aggregate, _verdict  # noqa: E402


def main() -> int:
    a_path = ROOT / "validation" / "holdout" / "A_winner_active.json"
    b_path = ROOT / "validation" / "holdout" / "B_winner_off.json"
    if not a_path.exists() or not b_path.exists():
        print(f"missing sidecar(s): {a_path.exists()=} {b_path.exists()=}",
              file=sys.stderr)
        return 1

    a = json.loads(a_path.read_text())
    b = json.loads(b_path.read_text())
    agg_a = _aggregate(a.get("scores", []), judge=True)
    agg_b = _aggregate(b.get("scores", []), judge=True)

    v_useful = _verdict(agg_a, agg_b, "useful_rate")
    v_balanced = _verdict(agg_a, agg_b, "balanced")

    # Note: A is the post-fix state (extension active), B is pre-fix.
    # The GEPA win generalises iff A > B (so verdict label "A better" is the
    # outcome we want).
    generalises = "A better" in v_useful["label"] or "A better" in v_balanced["label"]
    regression  = "B better" in v_useful["label"] or "B better" in v_balanced["label"]

    out_md = ROOT / "validation" / "holdout" / "HOLDOUT_REPORT.md"
    out_json = ROOT / "validation" / "holdout" / "HOLDOUT_REPORT.json"

    summary = {
        "n": agg_a["n"],
        "agg_a_winner_active": agg_a,
        "agg_b_winner_off": agg_b,
        "verdict_useful_rate": v_useful,
        "verdict_balanced":     v_balanced,
        "generalises": generalises,
        "regression":  regression,
    }
    out_json.write_text(json.dumps(summary, indent=2))

    md = [
        "# Held-out validation of GEPA cycle 4 winner",
        "",
        f"_n={agg_a['n']} elements, disjoint from cycle-4 eval slice "
        "(see `validation/holdout_ids.txt`)._",
        "",
        "## A: GEPA winner active (`pareto_extra.txt` loaded)",
        "",
        f"- useful_rate: **{agg_a['useful_rate']:.0%}**",
        f"- caught_rate: {agg_a['caught_rate']:.0%}",
        f"- missed_rate: {agg_a['missed_rate']:.0%}",
        f"- SMT feasibility: {agg_a['smt_feasibility_rate']:.0%}",
        f"- family share max: {agg_a['max_family_share']:.0%}",
        "",
        "## B: GEPA winner OFF (empty extension)",
        "",
        f"- useful_rate: **{agg_b['useful_rate']:.0%}**",
        f"- caught_rate: {agg_b['caught_rate']:.0%}",
        f"- missed_rate: {agg_b['missed_rate']:.0%}",
        f"- SMT feasibility: {agg_b['smt_feasibility_rate']:.0%}",
        f"- family share max: {agg_b['max_family_share']:.0%}",
        "",
        "## Verdict",
        "",
        f"- on **useful_rate**: {v_useful['label']} — {v_useful['reason']}",
        f"- on **balanced composite**: {v_balanced['label']} — {v_balanced['reason']}",
        "",
        f"**Generalises:** {generalises}  ",
        f"**Regression:** {regression}",
        "",
    ]
    if generalises and not regression:
        md.append(
            "> The GEPA winner reproduces a positive signal on a disjoint "
            "slice; keep `mirofish_lab/pareto_extra.txt`."
        )
    elif regression:
        md.append(
            "> The winner regresses on the held-out slice. The cycle-4 "
            "+17pp gain was likely an eval-slice artefact. Recommended: "
            "revert `mirofish_lab/pareto_extra.txt` and treat cycle 4 as "
            "inconclusive."
        )
    else:
        md.append(
            "> Tie within the ±2pp threshold. Insufficient evidence to "
            "claim generalisation; safe to keep but don't update README "
            "metrics from cycle 4 alone."
        )
    out_md.write_text("\n".join(md))
    print(out_md.read_text())
    return 0 if generalises and not regression else (2 if regression else 1)


if __name__ == "__main__":
    sys.exit(main())
