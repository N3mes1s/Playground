"""Chaos ground-truth validation.

Validates ALL chaos primitives against synthetic plans whose cascade
structure is known exactly:

  1. **LLM probe (chaos_probe)**: per-step blocked-downstream prediction;
     compared to true downstream by Jaccard.
  2. **Static cascade (chaos_static)**: should be CORRECT BY CONSTRUCTION
     since both ground truth and the function compute over the same
     dependency graph; we sanity-check this anyway.
  3. **Adversarial search (chaos_search)**: finds worst-K failure
     combination via LLM proposals + static scoring; verified that the
     LLM cannot exceed the exhaustive-static optimum and reports how
     close it gets.
  4. **Monte Carlo (chaos_montecarlo)**: per-gate priors are heuristic
     and not validated; we just sanity-check that high-fragility plans
     have lower full-success rates than low-fragility plans.

Three plan topologies: linear chain, diamond, parallel fan-out.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
THIS = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from mirofish_lab import load_config
from mirofish_lab.chaos import chaos_probe, _downstream_set
from mirofish_lab.chaos_montecarlo import montecarlo_simulate
from mirofish_lab.chaos_search import adversarial_search
from mirofish_lab.chaos_static import (
    static_achilles_heel,
    static_cascade,
    worst_k_failures,
)
from mirofish_lab.config import verify_model


def _make_step(sid: str, action: str, deps: list[str]) -> dict:
    return {
        "id": sid,
        "action": action,
        "owner": "TestOwner",
        "depends_on": deps,
        "gate": "monitor:always-fails-for-test",
        "rollback": f"undo {action}",
        "observability": "smoke test",
    }


PLANS = {
    "linear_chain": {
        "summary": "linear chain S1 -> ... -> S5",
        "steps": [
            _make_step("S1", "start", []),
            _make_step("S2", "step two", ["S1"]),
            _make_step("S3", "step three", ["S2"]),
            _make_step("S4", "step four", ["S3"]),
            _make_step("S5", "finish", ["S4"]),
        ],
        "open_questions": [],
        "conflicts": [],
    },
    "diamond": {
        "summary": "diamond: S1 -> {S2, S3} -> S4 (S4 needs both)",
        "steps": [
            _make_step("S1", "start", []),
            _make_step("S2", "left arm", ["S1"]),
            _make_step("S3", "right arm", ["S1"]),
            _make_step("S4", "merge", ["S2", "S3"]),
        ],
        "open_questions": [],
        "conflicts": [],
    },
    "parallel": {
        "summary": "parallel fan-out: S1 -> {S2, S3, S4, S5}",
        "steps": [
            _make_step("S1", "start", []),
            _make_step("S2", "branch a", ["S1"]),
            _make_step("S3", "branch b", ["S1"]),
            _make_step("S4", "branch c", ["S1"]),
            _make_step("S5", "branch d", ["S1"]),
        ],
        "open_questions": [],
        "conflicts": [],
    },
}


_INTENT = (
    "# Synthetic test plan\n\nWe are running a Chaos probe accuracy test. "
    "The plan below is intentionally generic; each step is a placeholder "
    "for an arbitrary deploy operation. The Chaos probe should reason "
    "about the dependency structure (the `depends_on` field) when "
    "predicting cascades, not about the action contents."
)


@dataclass
class CaseResult:
    name: str
    n_steps: int
    probes: list[dict] = field(default_factory=list)
    avg_jaccard: float = 0.0
    avg_overprediction: float = 0.0
    avg_underprediction: float = 0.0
    n_empty_predictions: int = 0


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def main() -> None:
    cfg = load_config()
    verify_model(cfg)
    results: list[CaseResult] = []
    static_validation: list[dict] = []
    search_validation: list[dict] = []
    mc_validation: list[dict] = []

    for name, plan in PLANS.items():
        true_downstream = {s["id"]: _downstream_set(plan, s["id"]) for s in plan["steps"]}

        # 1. LLM probe (the original test).
        chaos = chaos_probe(
            plan,
            cfg=cfg,
            plan_id=f"groundtruth_{name}",
            intent=_INTENT,
            n_samples=0,
            multi_failure_pairs=0,
            extra_failure_types=(),
        )
        case = CaseResult(name=name, n_steps=len(plan["steps"]))
        for p in chaos.probes:
            tid = p.target_ids[0] if p.target_ids else None
            true = true_downstream.get(tid, set())
            pred = set(p.blocked_downstream)
            j = _jaccard(true, pred)
            over = len(pred - true) / max(1, len(pred))
            under = len(true - pred) / max(1, len(true))
            case.probes.append({
                "target": tid,
                "true_downstream": sorted(true),
                "predicted": sorted(pred),
                "jaccard": round(j, 3),
                "overprediction_ratio": round(over, 3),
                "underprediction_ratio": round(under, 3),
                "rollback_holds": p.rollback_holds,
                "severity": p.severity,
            })
            if not pred:
                case.n_empty_predictions += 1
        if case.probes:
            case.avg_jaccard = round(
                sum(p["jaccard"] for p in case.probes) / len(case.probes), 3
            )
            case.avg_overprediction = round(
                sum(p["overprediction_ratio"] for p in case.probes) / len(case.probes), 3
            )
            case.avg_underprediction = round(
                sum(p["underprediction_ratio"] for p in case.probes) / len(case.probes), 3
            )
        results.append(case)
        print(
            f"[case] {name}: LLM probes={len(case.probes)} "
            f"avg_jaccard={case.avg_jaccard}",
            file=sys.stderr,
        )

        # 2. Static cascade — should be exact (correct by construction).
        static_correct = 0
        static_total = 0
        for sid in true_downstream:
            true = true_downstream[sid]
            pred = static_cascade(plan, [sid])
            if true == pred:
                static_correct += 1
            static_total += 1
        static_validation.append({
            "topology": name,
            "static_per_step_correct": f"{static_correct}/{static_total}",
            "is_exact": static_correct == static_total,
        })
        print(
            f"[case] {name}: static_per_step_correct={static_correct}/{static_total}",
            file=sys.stderr,
        )

        # 3. Adversarial search at k=2 (only meaningful for non-trivial plans).
        if len(plan["steps"]) >= 4:
            search = adversarial_search(
                plan, cfg=cfg, plan_id=f"groundtruth_{name}",
                k=2, rounds=2, top_n=3,
            )
            exhaustive = worst_k_failures(plan, k=2, top_n=3)
            search_best = search.best[0].fragility if search.best else 0.0
            exhaustive_best = exhaustive[0].fragility if exhaustive else 0.0
            ratio = search_best / max(0.001, exhaustive_best)
            search_validation.append({
                "topology": name,
                "k": 2,
                "rounds": search.rounds,
                "n_proposed": search.n_candidates_proposed,
                "n_scored": search.n_candidates_scored,
                "search_best_fragility": search_best,
                "exhaustive_best_fragility": exhaustive_best,
                "ratio": round(ratio, 3),
                "search_top_set": list(search.best[0].ids) if search.best else [],
                "exhaustive_top_set": list(exhaustive[0].failure_set) if exhaustive else [],
            })
            print(
                f"[case] {name}: adversarial k=2: search={search_best} "
                f"exhaustive={exhaustive_best} ratio={ratio:.2f}",
                file=sys.stderr,
            )

        # 4. Monte Carlo — sanity check.
        mc = montecarlo_simulate(plan, plan_id=f"groundtruth_{name}", n_samples=500)
        mc_validation.append({
            "topology": name,
            "avg_success_rate": mc.avg_success_rate,
            "p10": mc.p10_success_rate,
            "full_success_rate": mc.full_success_rate,
            "full_failure_rate": mc.full_failure_rate,
            "per_step_failure_rate": mc.per_step_failure_rate,
        })
        print(
            f"[case] {name}: MC avg_success={mc.avg_success_rate}",
            file=sys.stderr,
        )

    # Build report.
    out_md = THIS / "REPORT.md"
    out_json = THIS / "REPORT.json"
    lines = [
        "# Chaos primitives ground-truth validation",
        "",
        "Synthetic plans with known cascade structure validate FOUR chaos "
        "primitives end-to-end:",
        "",
        "1. **LLM probe** (chaos_probe) — per-step blocked-downstream "
        "   prediction by an LLM; compared to true downstream by Jaccard.",
        "2. **Static cascade** (chaos_static) — graph-based exact "
        "   computation; correct by construction.",
        "3. **Adversarial search** (chaos_search) — LLM Attacker proposes "
        "   worst-K combinations, scored by static cascade; compared to "
        "   exhaustive-static optimum.",
        "4. **Monte Carlo** (chaos_montecarlo) — per-gate failure priors + "
        "   N-sample simulation; sanity-checked against topology fragility.",
        "",
        "## 1. LLM probe Jaccard",
        "",
        "| Topology | Steps | Probes | Avg Jaccard | Underpred. | Overpred. | Empty preds |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in results:
        lines.append(
            f"| `{r.name}` | {r.n_steps} | {len(r.probes)} | "
            f"{r.avg_jaccard} | {r.avg_underprediction} | "
            f"{r.avg_overprediction} | {r.n_empty_predictions}/{len(r.probes)} |"
        )
    aj = round(sum(r.avg_jaccard for r in results) / max(1, len(results)), 3)
    lines.append("")
    lines.append(f"**Aggregate LLM Jaccard**: {aj}")
    lines.append("")

    lines.append("## 2. Static cascade exactness")
    lines.append("")
    lines.append("Pure graph computation; should be 100% by construction.")
    lines.append("")
    lines.append("| Topology | Per-step correctness |")
    lines.append("|---|---|")
    for v in static_validation:
        lines.append(f"| `{v['topology']}` | {v['static_per_step_correct']} |")
    all_exact = all(v["is_exact"] for v in static_validation)
    lines.append("")
    lines.append(f"**All topologies exact?**: {'YES' if all_exact else 'NO'}")
    lines.append("")

    lines.append("## 3. Adversarial search vs exhaustive static")
    lines.append("")
    lines.append(
        "Adversarial search uses LLM proposals scored by static cascade. "
        "Ratio = search_best / exhaustive_best. 1.0 means the LLM "
        "found the exhaustive optimum; <1.0 means it left worse cases on "
        "the table."
    )
    lines.append("")
    lines.append(
        "| Topology | Rounds | Proposed | Scored | Search best | Exhaustive | Ratio | Search top set | Exhaustive top set |"
    )
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for v in search_validation:
        lines.append(
            f"| `{v['topology']}` | {v['rounds']} | {v['n_proposed']} | "
            f"{v['n_scored']} | {v['search_best_fragility']} | "
            f"{v['exhaustive_best_fragility']} | {v['ratio']} | "
            f"{v['search_top_set']} | {v['exhaustive_top_set']} |"
        )
    if search_validation:
        avg_ratio = round(sum(v["ratio"] for v in search_validation) / len(search_validation), 3)
        lines.append("")
        lines.append(f"**Average ratio (LLM / exhaustive)**: {avg_ratio}")
    lines.append("")

    lines.append("## 4. Monte Carlo sanity")
    lines.append("")
    lines.append(
        "Higher-fragility topologies (linear chain) should have LOWER "
        "Monte Carlo full-success rates than parallel fan-outs. This is a "
        "structural sanity check, not a calibration."
    )
    lines.append("")
    lines.append("| Topology | Avg success | p10 | Full success | Full failure |")
    lines.append("|---|---|---|---|---|")
    for v in mc_validation:
        lines.append(
            f"| `{v['topology']}` | {v['avg_success_rate']} | "
            f"{v['p10']} | {v['full_success_rate']} | {v['full_failure_rate']} |"
        )
    lines.append("")
    out_md.write_text("\n".join(lines))
    out_json.write_text(json.dumps({
        "llm_probe": [
            {"name": r.name, "n_steps": r.n_steps, "probes": r.probes,
             "avg_jaccard": r.avg_jaccard,
             "avg_underprediction": r.avg_underprediction,
             "avg_overprediction": r.avg_overprediction,
             "n_empty_predictions": r.n_empty_predictions}
            for r in results
        ],
        "static_validation": static_validation,
        "search_validation": search_validation,
        "montecarlo_validation": mc_validation,
    }, indent=2))
    print(f"\n[done] wrote {out_md} and {out_json}")


if __name__ == "__main__":
    main()
