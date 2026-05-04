"""Scaling test for adversarial chaos search.

The previous validation showed adversarial search hits the exhaustive
optimum (ratio = 1.00) on tiny synthetic plans (4-5 steps). The
honest concern is that this trivially holds because the optimum is
easy to find when there are only ~10 candidate K-tuples.

This script tests adversarial search on a 15-step plan with
deliberately mixed structure (deep linear segments + diamond + fan
out + late-merge) where:

  - exhaustive enumeration of all C(15, 2) = 105 pairs is still
    tractable, so we can compute the true exhaustive optimum;
  - the optimum is non-obvious because the cascade structure has
    multiple local maxima.

We then compare adversarial search at k=2 and k=3 to the exhaustive
optimum and report the ratio. Anything below 1.00 means the LLM
search is leaving worse cases on the table; we report which.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
THIS = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from mirofish_lab import load_config
from mirofish_lab.chaos_search import adversarial_search
from mirofish_lab.chaos_static import worst_k_failures
from mirofish_lab.config import verify_model


def _make_step(sid: str, deps: list[str]) -> dict:
    return {
        "id": sid,
        "action": f"action {sid}",
        "owner": "TestOwner",
        "depends_on": deps,
        "gate": "monitor:test",
        "rollback": f"undo {sid}",
        "observability": "smoke",
    }


# 15-step plan: linear core + parallel branch + late merge
LARGE_PLAN = {
    "summary": "15-step mixed-topology plan for scaling test",
    "steps": [
        _make_step("S1", []),                       # root
        _make_step("S2", ["S1"]),                   # linear
        _make_step("S3", ["S2"]),                   # linear
        _make_step("S4", ["S3"]),                   # linear (deep chain mid)
        _make_step("S5", ["S1"]),                   # parallel branch
        _make_step("S6", ["S5"]),                   # branch deepens
        _make_step("S7", ["S5"]),                   # branch widens
        _make_step("S8", ["S4", "S6"]),             # merge of linear + branch
        _make_step("S9", ["S8"]),                   # post-merge
        _make_step("S10", ["S8"]),                  # post-merge parallel
        _make_step("S11", ["S9", "S10"]),           # post-merge fan-in
        _make_step("S12", ["S7", "S11"]),           # late merge
        _make_step("S13", ["S12"]),                 # tail
        _make_step("S14", ["S12"]),                 # tail parallel
        _make_step("S15", ["S13", "S14"]),          # final
    ],
    "open_questions": [],
    "conflicts": [],
}


def main() -> None:
    cfg = load_config()
    verify_model(cfg)

    out: dict = {"plan_n_steps": 15, "results": {}}
    for k in (2, 3):
        print(f"\n=== k = {k} ===", file=sys.stderr)
        exhaustive = worst_k_failures(LARGE_PLAN, k=k, top_n=10)
        ex_best = exhaustive[0].fragility if exhaustive else 0.0
        print(f"exhaustive top-3:", file=sys.stderr)
        for e in exhaustive[:3]:
            print(f"  {list(e.failure_set)} -> blocks {list(e.blocked)} f={e.fragility}", file=sys.stderr)

        # Run adversarial search at multiple round counts.
        for rounds in (2, 4):
            print(f"adversarial search (rounds={rounds})...", file=sys.stderr)
            search = adversarial_search(
                LARGE_PLAN, cfg=cfg, plan_id=f"large_k{k}_r{rounds}",
                k=k, rounds=rounds, top_n=10,
            )
            search_best = search.best[0].fragility if search.best else 0.0
            ratio = search_best / max(0.001, ex_best)
            in_top = sum(
                1 for c in search.best
                if any(set(c.ids) == set(e.failure_set) for e in exhaustive[:5])
            )
            print(
                f"  search best={search_best} (ratio {ratio:.2f}); "
                f"{in_top}/5 of search top-5 are in exhaustive top-5; "
                f"proposed={search.n_candidates_proposed} "
                f"scored={search.n_candidates_scored}",
                file=sys.stderr,
            )
            out["results"][f"k={k},rounds={rounds}"] = {
                "k": k,
                "rounds": rounds,
                "exhaustive_best": ex_best,
                "search_best": search_best,
                "ratio": round(ratio, 3),
                "search_proposed": search.n_candidates_proposed,
                "search_scored": search.n_candidates_scored,
                "search_top_in_exhaustive_top5": in_top,
                "search_top_3": [
                    {"ids": list(c.ids), "blocked": list(c.blocked),
                     "fragility": c.fragility}
                    for c in search.best[:3]
                ],
                "exhaustive_top_3": [
                    {"failure_set": list(e.failure_set),
                     "blocked": list(e.blocked),
                     "fragility": e.fragility}
                    for e in exhaustive[:3]
                ],
            }

    out_md = THIS / "SCALING_REPORT.md"
    out_json = THIS / "SCALING_REPORT.json"
    out_json.write_text(json.dumps(out, indent=2))

    lines = [
        "# Adversarial chaos search scaling test",
        "",
        "15-step synthetic plan with mixed topology (linear core, parallel "
        "branch, late merge). Compares adversarial LLM search to exhaustive "
        "static enumeration at k=2 and k=3, with 2 and 4 search rounds.",
        "",
        "Plan structure: S1→S2→S3→S4→S8 (linear core), S1→S5→{S6,S7} "
        "(parallel branch), S8→{S9,S10}→S11→S12→{S13,S14}→S15 "
        "(post-merge fan-out).",
        "",
        "| Config | Exhaustive best | Search best | Ratio | Top-5 overlap | Scored |",
        "|---|---|---|---|---|---|",
    ]
    for label, r in out["results"].items():
        lines.append(
            f"| `{label}` | {r['exhaustive_best']} | {r['search_best']} | "
            f"{r['ratio']} | {r['search_top_in_exhaustive_top5']}/5 | "
            f"{r['search_scored']} |"
        )
    lines.append("")
    lines.append(
        "**Interpretation**: ratio = 1.00 means LLM search hit the optimum. "
        "Ratio < 1.00 means LLM left worse cases on the table; the "
        "exhaustive top-5 overlap shows how many of the LLM's top-5 picks "
        "are actually in the true top-5."
    )
    out_md.write_text("\n".join(lines))
    print(f"\n[done] wrote {out_md} and {out_json}")


if __name__ == "__main__":
    main()
