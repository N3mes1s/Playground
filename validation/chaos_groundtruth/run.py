"""Chaos ground-truth validation.

We construct synthetic rollout plans whose cascade structure we know
exactly, run the Chaos probe, and check whether the probe's predicted
blocked-downstream sets match the true downstream sets.

Three plan topologies, each with a known answer:

  1. **Linear chain**: S1 -> S2 -> S3 -> S4 -> S5. If Sk fails, true
     blocked = {S(k+1) ... S5}. Fragility upper bound = 1.0 mid-chain,
     decreasing toward leaves.

  2. **Diamond**: S1 -> {S2, S3} -> S4. If S2 fails:
       - if S4 depends on BOTH S2 AND S3: S4 blocked.
       - if S4 depends on S2 OR S3 (logical-or): S4 still proceeds.
     We use AND-semantics in the test (both required) which matches
     the typical "all dependencies satisfied" behaviour in deploy
     orchestrators.

  3. **Independent parallel**: S1 -> {S2, S3, S4, S5}. If Sk fails for
     k >= 2, no other Sk is blocked. Fragility = 0.

For each topology we compute:
  - true cascade size (ground truth)
  - Chaos probe's predicted blocked_downstream
  - Jaccard(predicted, true)
  - over- and under-prediction counts

If the probe systematically reports empty cascades (the budget=2
finding from the previous commit), we'll see Jaccard = 0 here. If it
correctly tracks structure, Jaccard should be >= 0.6 on average.
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
from mirofish_lab.config import verify_model
from mirofish_lab.chaos import chaos_probe, _downstream_set


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
    for name, plan in PLANS.items():
        true_downstream = {s["id"]: _downstream_set(plan, s["id"]) for s in plan["steps"]}
        chaos = chaos_probe(
            plan,
            cfg=cfg,
            plan_id=f"groundtruth_{name}",
            intent=_INTENT,
            n_samples=0,                      # exhaustive
            multi_failure_pairs=0,            # disable pairs (the budget=2 known weakness)
            extra_failure_types=(),           # only gate_violation
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
            f"[case] {name}: probes={len(case.probes)} "
            f"avg_jaccard={case.avg_jaccard} "
            f"under={case.avg_underprediction} over={case.avg_overprediction} "
            f"empty={case.n_empty_predictions}",
            file=sys.stderr,
        )

    # Build report.
    out_md = THIS / "REPORT.md"
    out_json = THIS / "REPORT.json"
    lines = [
        "# Chaos probe ground-truth validation",
        "",
        "Synthetic plans with known cascade structure. Per probe we "
        "compare the Chaos agent's predicted `blocked_downstream` to "
        "the true downstream set computed from the dependency graph.",
        "",
        "Metrics:",
        "- **Jaccard** = |pred ∩ true| / |pred ∪ true|",
        "- **Underprediction** = |true − pred| / |true|  (probe missed real cascades)",
        "- **Overprediction** = |pred − true| / |pred|   (probe invented cascades)",
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
    lines.append("")
    aj = round(sum(r.avg_jaccard for r in results) / max(1, len(results)), 3)
    au = round(sum(r.avg_underprediction for r in results) / max(1, len(results)), 3)
    ao = round(sum(r.avg_overprediction for r in results) / max(1, len(results)), 3)
    lines.append(
        f"**Aggregate** — Jaccard {aj}, underprediction {au}, overprediction {ao}."
    )
    lines.append("")
    for r in results:
        lines.append(f"## {r.name}")
        lines.append("")
        lines.append("| Target | True downstream | Predicted | Jaccard | Underpred | Overpred |")
        lines.append("|---|---|---|---|---|---|")
        for p in r.probes:
            lines.append(
                f"| `{p['target']}` | {p['true_downstream']} | {p['predicted']} | "
                f"{p['jaccard']} | {p['underprediction_ratio']} | "
                f"{p['overprediction_ratio']} |"
            )
        lines.append("")
    out_md.write_text("\n".join(lines))
    out_json.write_text(json.dumps([
        {"name": r.name, "n_steps": r.n_steps, "probes": r.probes,
         "avg_jaccard": r.avg_jaccard, "avg_underprediction": r.avg_underprediction,
         "avg_overprediction": r.avg_overprediction,
         "n_empty_predictions": r.n_empty_predictions}
        for r in results
    ], indent=2))
    print(f"\n[done] wrote {out_md} and {out_json}")


if __name__ == "__main__":
    main()
