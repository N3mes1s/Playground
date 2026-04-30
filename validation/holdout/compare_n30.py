"""Compare REBASELINE_2026-04-30 (no extension) against the new N=30 run
with pareto_extra.txt active.

Both runs use seed 1337 + same 5 sources, so the element set is identical
and the per-element verdict deltas are directly meaningful.

Decides whether the +5pp SMT lift seen on n=6 holdout reproduces at N=30.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "dataset" / "bench"))
from bench_ab import _aggregate, _verdict  # noqa: E402


def main() -> int:
    no_ext = ROOT / "validation" / "REBASELINE_2026-04-30.json"
    with_ext = ROOT / "validation" / "REBASELINE_2026-04-30_with_extension.json"
    if not with_ext.exists():
        print(f"missing: {with_ext}", file=sys.stderr)
        return 1

    a = json.loads(no_ext.read_text())  # baseline (no extension)
    b = json.loads(with_ext.read_text())  # with pareto_extra.txt

    sa = a["scores"]
    sb = b["scores"]

    # Sanity: same element IDs?
    ids_a = {s["id"] for s in sa}
    ids_b = {s["id"] for s in sb}
    overlap = ids_a & ids_b
    print(f"elements: A={len(ids_a)}, B={len(ids_b)}, overlap={len(overlap)}",
          file=sys.stderr)

    agg_a = _aggregate(sa, judge=True)
    agg_b = _aggregate(sb, judge=True)

    v_useful = _verdict(agg_a, agg_b, "useful_rate")
    v_balanced = _verdict(agg_a, agg_b, "balanced")

    # Per-element verdict transitions: what changed when extension turned on?
    transitions = Counter()
    by_id_a = {s["id"]: s for s in sa}
    by_id_b = {s["id"]: s for s in sb}
    for eid in sorted(overlap):
        va = by_id_a[eid].get("verdict_judge", "?")
        vb = by_id_b[eid].get("verdict_judge", "?")
        transitions[f"{va} -> {vb}"] += 1

    out_md = ROOT / "validation" / "REBASELINE_with_extension_DIFF.md"
    out_json = out_md.with_suffix(".json")

    summary = {
        "n": len(overlap),
        "agg_a_no_extension":   agg_a,
        "agg_b_with_extension": agg_b,
        "verdict_useful_rate": v_useful,
        "verdict_balanced":     v_balanced,
        "per_element_transitions": dict(transitions),
        "smt_delta_pp": 100 * (agg_b["smt_feasibility_rate"] - agg_a["smt_feasibility_rate"]),
        "useful_delta_pp": 100 * (agg_b["useful_rate"] - agg_a["useful_rate"]),
        "caught_delta_pp": 100 * (agg_b["caught_rate"] - agg_a["caught_rate"]),
    }
    out_json.write_text(json.dumps(summary, indent=2))

    md = [
        "# N=30 re-baseline diff: with vs without `pareto_extra.txt`",
        "",
        f"_Same {len(overlap)} elements (seed 1337, 5 sources). Comparing "
        "the cycle-4 winner directive at scale against the prior baseline._",
        "",
        "## Aggregate metrics",
        "",
        "| metric | A: no extension | B: with extension | Δ |",
        "|---|---|---|---|",
        f"| useful_rate | {agg_a['useful_rate']:.0%} | {agg_b['useful_rate']:.0%} | "
        f"{100*(agg_b['useful_rate']-agg_a['useful_rate']):+.0f}pp |",
        f"| caught_rate | {agg_a['caught_rate']:.0%} | {agg_b['caught_rate']:.0%} | "
        f"{100*(agg_b['caught_rate']-agg_a['caught_rate']):+.0f}pp |",
        f"| missed_rate | {agg_a['missed_rate']:.0%} | {agg_b['missed_rate']:.0%} | "
        f"{100*(agg_b['missed_rate']-agg_a['missed_rate']):+.0f}pp |",
        f"| SMT feasibility | {agg_a['smt_feasibility_rate']:.0%} | "
        f"{agg_b['smt_feasibility_rate']:.0%} | "
        f"{100*(agg_b['smt_feasibility_rate']-agg_a['smt_feasibility_rate']):+.0f}pp |",
        f"| family share max | {agg_a['max_family_share']:.0%} | "
        f"{agg_b['max_family_share']:.0%} | "
        f"{100*(agg_b['max_family_share']-agg_a['max_family_share']):+.0f}pp |",
        "",
        "## Per-element verdict transitions",
        "",
        "| transition | count |",
        "|---|---|",
    ]
    for k, v in sorted(transitions.items(), key=lambda kv: -kv[1]):
        md.append(f"| {k} | {v} |")
    md += [
        "",
        "## Verdict",
        "",
        f"- on **useful_rate**: {v_useful['label']} — {v_useful['reason']}",
        f"- on **balanced composite**: {v_balanced['label']} — {v_balanced['reason']}",
        "",
    ]
    out_md.write_text("\n".join(md))
    print(out_md.read_text())
    return 0


if __name__ == "__main__":
    sys.exit(main())
