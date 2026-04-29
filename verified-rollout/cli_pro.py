"""verified-rollout pro mode: comprehensive upgrade of the three flagged limits.

1. Verification: SMT-backed Z3 ordering check + minimal unsat core
   explanation for infeasible plans (`mirofish_lab.verify_smt`),
   alongside the original structural check (`mirofish_lab.verify`).

2. Chaos: exhaustive single-step probes (every non-leaf step), random
   multi-failure pairs at budget=2, and rollback-failure-mode probes.
   Adds Achilles-heel ranking, fragility-budget curve, and recovery
   classification (`mirofish_lab.chaos`).

3. Pareto: N plans (default 6) with weight tuples spanning the
   (speed, safety, cost) simplex; NSGA-II non-dominated sort +
   crowding distance; user-supplied utility weights select the
   single recommendation; ASCII chart of the frontier
   (`mirofish_lab.pareto_frontier`).

Usage:
    python verified-rollout/cli_pro.py <intent.md> \
        [--n-plans 6] \
        [--chaos-pairs 3] \
        [--utility "fragility=0.4,coverage=0.3,steps=0.1,severity=0.15,rollback_failure=0.05"]
"""

from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mirofish_lab import Agent, Report, load_config, parallel_run
from mirofish_lab.config import verify_model
from mirofish_lab.chaos import ChaosResult, chaos_probe
from mirofish_lab.pareto_frontier import (
    FrontierPoint,
    UtilityWeights,
    build_frontier_slots,
    crowding_distance,
    non_dominated_sort,
    render_ascii_chart,
    utility_score,
)
from mirofish_lab.rollout import (
    Constraint,
    STAKEHOLDER_PERSONAS,
    extract_json,
)
from mirofish_lab.verify import VerificationResult, verify_plan
from mirofish_lab.verify_smt import (
    SMTVerificationResult,
    explain_infeasibility,
    smt_verify_plan,
)


# ---------------------------------------------------------------------------


def _intent_prompt(intent_text: str) -> str:
    return (
        "# Proposed change\n\n"
        f"{intent_text.strip()}\n\n"
        "As your stakeholder persona, contribute the constraints in your "
        "axis that this rollout must honour. Output JSON per the schema in "
        "your system prompt."
    )


def _parse_constraints(raw: object, owner: str) -> list[Constraint]:
    if not isinstance(raw, list):
        return []
    out: list[Constraint] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        item["owner"] = owner
        c = Constraint.from_dict(item, default_owner=owner)
        if c.summary:
            out.append(c)
    return out


def _gather_constraints(intent: str, cfg) -> list[Constraint]:
    agents = [Agent(p, cfg) for p in STAKEHOLDER_PERSONAS]
    print(f"[constraints] {len(agents)} stakeholders in parallel", file=sys.stderr)
    responses = parallel_run(agents, _intent_prompt(intent))
    out: list[Constraint] = []
    for r in responses:
        parsed = extract_json(r.content)
        cs = _parse_constraints(parsed, owner=r.agent_name)
        print(f"[constraints]   {r.agent_name}: {len(cs)}", file=sys.stderr)
        out.extend(cs)
    return out


def _generate_frontier_plans(
    intent: str, constraints: list[Constraint], cfg, n_plans: int
) -> dict[str, dict]:
    constraints_json = json.dumps([c.raw for c in constraints], indent=2)
    slots = build_frontier_slots(n_plans)

    def one(slot) -> tuple[str, dict, tuple[float, float, float]]:
        agent = Agent(slot.persona, cfg)
        prompt = (
            f"# Migration intent\n\n{intent.strip()}\n\n"
            f"# Stakeholder constraints (merged)\n\n```json\n{constraints_json}\n```\n\n"
            "Produce the partial-order plan as a JSON object per your schema, "
            "biased per your weight priorities."
        )
        resp = agent.respond(prompt)
        plan = extract_json(resp.content) or {}
        return slot.label, plan, slot.weights

    out: dict[str, dict] = {}
    weights_for: dict[str, tuple[float, float, float]] = {}
    with ThreadPoolExecutor(max_workers=min(6, n_plans)) as pool:
        futures = [pool.submit(one, s) for s in slots]
        for fut in as_completed(futures):
            label, plan, w = fut.result()
            out[label] = plan
            weights_for[label] = w
            print(
                f"[pareto] {label} (w={w}): "
                f"{len(plan.get('steps') or [])} steps, "
                f"{len(plan.get('conflicts') or [])} conflicts",
                file=sys.stderr,
            )
    # Stable order by slot index in label.
    ordered_labels = sorted(out.keys(), key=lambda l: int(l.split("-")[0]))
    return {l: out[l] for l in ordered_labels}, {l: weights_for[l] for l in ordered_labels}


def _score(plan: dict, ver: VerificationResult, smt: SMTVerificationResult, chaos: ChaosResult) -> dict:
    steps = plan.get("steps") or []
    n = len(steps)
    approval = sum(1 for s in steps if isinstance(s, dict) and (s.get("gate", "") or "").startswith("approval:"))
    window = sum(1 for s in steps if isinstance(s, dict) and (s.get("gate", "") or "").startswith("window:"))
    monitor = sum(1 for s in steps if isinstance(s, dict) and (s.get("gate", "") or "").startswith("monitor:"))
    return {
        "steps": n,
        "structural_pass": ver.passes,
        "smt_feasible": smt.feasible,
        "smt_unsat_core_size": len(smt.unsat_core),
        "is_dag": ver.is_dag,
        "unreachable": len(ver.unreachable_steps),
        "coverage_ratio": round(ver.coverage_ratio, 2),
        "fragility": chaos.fragility,
        "fragility_at_budget_1": chaos.fragility_curve.points.get(1, 0.0),
        "fragility_at_budget_2": chaos.fragility_curve.points.get(2, 0.0),
        "avg_severity": chaos.avg_severity,
        "rollback_failure_rate": chaos.rollback_failure_rate,
        "approval_gates": approval,
        "window_gates": window,
        "monitor_gates": monitor,
        "achilles_heel": chaos.achilles_heel,
        "recovery_distribution": chaos.recovery_distribution,
    }


# ---------------------------------------------------------------------------


def _render_plan_table(plan: dict) -> str:
    steps = plan.get("steps") or []
    if not steps:
        return "_(empty)_"
    rows = ["| # | Action | Owner | Deps | Gate | Rollback |", "|---|---|---|---|---|---|"]
    for s in steps:
        if not isinstance(s, dict):
            continue
        deps = ", ".join(s.get("depends_on", []) or []) or "—"
        rows.append(
            f"| {s.get('id','?')} | {(s.get('action','') or '')[:80]} | "
            f"{s.get('owner','')} | {deps} | `{s.get('gate','')}` | "
            f"{(s.get('rollback','') or '')[:60]} |"
        )
    return "\n".join(rows)


def _render_smt(smt: SMTVerificationResult) -> str:
    lines = [
        f"- backend: `{smt.backend}` ({smt.n_steps} steps, "
        f"{smt.n_dependency_edges} dep edges, "
        f"{smt.n_constraint_edges} constraint edges)",
        f"- feasible: **{smt.feasible}**",
    ]
    if smt.feasible and smt.witness_ordering:
        lines.append("- witness ordering: " + " → ".join(f"`{s}`" for s in smt.witness_ordering))
    elif not smt.feasible:
        lines.append(explain_infeasibility(smt))
    if smt.notes:
        lines.append("- notes: " + "; ".join(smt.notes))
    return "\n".join(lines)


def _render_chaos(chaos: ChaosResult) -> str:
    if not chaos.probes:
        return "_(no probes ran)_"
    out = [
        f"- **fragility (overall)**: {chaos.fragility}",
        f"- **fragility curve**: " + ", ".join(
            f"budget={k} → {v}" for k, v in sorted(chaos.fragility_curve.points.items())
        ),
        f"- **avg severity**: {chaos.avg_severity} (1=low … 4=critical)",
        f"- **rollback-failure rate**: {chaos.rollback_failure_rate} "
        f"({int(chaos.rollback_failure_rate * len(chaos.probes))}/{len(chaos.probes)} probes)",
        "- **recovery distribution**: " + ", ".join(
            f"{k}={v}" for k, v in chaos.recovery_distribution.items()
        ),
        "- **Achilles heel** (top 5 by per-step fragility):",
    ]
    for sid, score in chaos.achilles_heel:
        out.append(f"  - `{sid}` → {score}")
    out.append("")
    out.append("| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |")
    out.append("|---|---|---|---|---|---|")
    for p in chaos.probes:
        out.append(
            f"| {', '.join(p.target_ids)} | {p.failure_type} | {p.severity} | "
            f"{'yes' if p.rollback_holds else 'NO'} | "
            f"{', '.join(p.blocked_downstream[:6]) or '—'} | "
            f"{p.recovery_class} |"
        )
    return "\n".join(out)


def _render_frontier(points: list[FrontierPoint], fronts: list[list[FrontierPoint]]) -> str:
    lines = [
        f"_{len(points)} plans, {sum(1 for p in points if p.rank == 0)} on the Pareto front._",
        "",
        "| Plan | Weights (s/sf/c) | Rank | Crowding | Fragility | Cov | Steps | Severity | RB-fail |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for p in sorted(points, key=lambda q: (q.rank, -q.crowding)):
        speed, safety, cost = p.weights
        lines.append(
            f"| {p.label} | {speed:.2f}/{safety:.2f}/{cost:.2f} | "
            f"{p.rank} | {'∞' if p.crowding == float('inf') else f'{p.crowding:.2f}'} | "
            f"{p.metrics['fragility']:.2f} | {-p.metrics['neg_coverage']:.2f} | "
            f"{int(p.metrics['steps'])} | {p.metrics['avg_severity']:.2f} | "
            f"{p.metrics['rollback_failure_rate']:.2f} |"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------


def run(
    intent_path: Path,
    *,
    n_plans: int,
    chaos_pairs: int,
    utility_str: str | None,
    out_path: Path,
) -> Path:
    cfg = load_config()
    verify_model(cfg)
    intent = intent_path.read_text()
    print(f"[intent] {intent_path} ({len(intent)} chars)", file=sys.stderr)

    constraints = _gather_constraints(intent, cfg)
    plans, weights_for = _generate_frontier_plans(intent, constraints, cfg, n_plans)

    raw_constraints = [c.raw for c in constraints]
    verifications: dict[str, VerificationResult] = {}
    smt_results: dict[str, SMTVerificationResult] = {}
    chaos_results: dict[str, ChaosResult] = {}
    scores: dict[str, dict] = {}

    for label, plan in plans.items():
        ver = verify_plan(plan, raw_constraints, plan_id=label)
        smt = smt_verify_plan(plan, raw_constraints, plan_id=label)
        chaos = chaos_probe(
            plan,
            cfg=cfg,
            plan_id=label,
            intent=intent,
            n_samples=0,                        # 0 = exhaustive single-step
            multi_failure_pairs=chaos_pairs,
            extra_failure_types=("rollback_failure",),
        )
        verifications[label] = ver
        smt_results[label] = smt
        chaos_results[label] = chaos
        scores[label] = _score(plan, ver, smt, chaos)
        print(
            f"[score] {label}: smt_ok={smt.feasible} fragility={chaos.fragility} "
            f"sev={chaos.avg_severity} rb_fail={chaos.rollback_failure_rate}",
            file=sys.stderr,
        )

    # Build frontier points and sort.
    points: list[FrontierPoint] = []
    for label, plan in plans.items():
        from mirofish_lab.pareto_frontier import _to_objectives
        points.append(
            FrontierPoint(
                label=label,
                weights=weights_for[label],
                metrics=_to_objectives(scores[label]),
            )
        )
    fronts = non_dominated_sort(points)
    for f in fronts:
        crowding_distance(f)

    weights = UtilityWeights.from_string(utility_str)
    front0 = fronts[0] if fronts else []
    if front0:
        winner = max(front0, key=lambda p: utility_score(p, weights))
    else:
        winner = max(points, key=lambda p: utility_score(p, weights))

    print(
        f"[recommend] {winner.label} (rank=0, "
        f"utility={utility_score(winner, weights):.3f}, "
        f"weights=fragility={weights.fragility:.2f},coverage={weights.coverage:.2f},"
        f"steps={weights.steps:.2f},severity={weights.severity:.2f},"
        f"rollback_failure={weights.rollback_failure:.2f})",
        file=sys.stderr,
    )

    # Build markdown.
    out_path.parent.mkdir(parents=True, exist_ok=True)
    report = Report(
        title=f"Verified Rollout (PRO) — {intent_path.stem}",
        meta={
            "Intent": str(intent_path),
            "N plans": str(n_plans),
            "Pareto-front size": str(len(front0)),
            "Recommendation": winner.label,
            "Utility weights": json.dumps(weights.__dict__),
            "Model": cfg.model,
        },
    )
    report.add(
        "Recommendation",
        f"**{winner.label}** — rank-0 (Pareto-optimal), utility "
        f"{utility_score(winner, weights):.3f} under user weights.",
    )
    report.add("Pareto frontier (NSGA-II)", _render_frontier(points, fronts))
    report.add("Pareto chart", render_ascii_chart(points, x="fragility", y="steps"))

    for label in plans:
        report.add(f"Plan: {label} (weights {weights_for[label]})", _render_plan_table(plans[label]))
        report.add(f"SMT verification: {label}", _render_smt(smt_results[label]))
        report.add(f"Chaos probe: {label}", _render_chaos(chaos_results[label]))

    written = report.write(out_path)

    # Sidecar JSON.
    json_path = out_path.with_suffix(".json")
    json_path.write_text(
        json.dumps(
            {
                "intent_path": str(intent_path),
                "constraints": raw_constraints,
                "plans": plans,
                "weights_for": weights_for,
                "scores": scores,
                "smt": {
                    k: {
                        "feasible": v.feasible,
                        "backend": v.backend,
                        "n_dependency_edges": v.n_dependency_edges,
                        "n_constraint_edges": v.n_constraint_edges,
                        "witness_ordering": v.witness_ordering,
                        "unsat_core": v.unsat_core,
                        "unsat_core_explanations": v.unsat_core_explanations,
                        "notes": v.notes,
                    }
                    for k, v in smt_results.items()
                },
                "chaos": {
                    k: {
                        "fragility": v.fragility,
                        "fragility_curve": v.fragility_curve.points,
                        "avg_severity": v.avg_severity,
                        "rollback_failure_rate": v.rollback_failure_rate,
                        "achilles_heel": v.achilles_heel,
                        "recovery_distribution": v.recovery_distribution,
                        "probes": [
                            {
                                "target_ids": p.target_ids,
                                "failure_type": p.failure_type,
                                "blocked_downstream": p.blocked_downstream,
                                "rollback_holds": p.rollback_holds,
                                "recovery_class": p.recovery_class,
                                "severity": p.severity,
                            }
                            for p in v.probes
                        ],
                    }
                    for k, v in chaos_results.items()
                },
                "pareto": {
                    "front_0_labels": [p.label for p in front0],
                    "all_points": [
                        {
                            "label": p.label,
                            "rank": p.rank,
                            "crowding": p.crowding if p.crowding != float("inf") else None,
                            "metrics": p.metrics,
                            "weights": p.weights,
                        }
                        for p in points
                    ],
                    "winner": winner.label,
                    "winner_utility": utility_score(winner, weights),
                    "user_weights": weights.__dict__,
                },
            },
            indent=2,
        )
    )
    print(f"[done] wrote {written} and {json_path}", file=sys.stderr)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="verified-rollout PRO mode")
    parser.add_argument("intent", type=Path)
    parser.add_argument("--n-plans", type=int, default=6)
    parser.add_argument("--chaos-pairs", type=int, default=2)
    parser.add_argument("--utility", type=str, default=None,
                        help='e.g. "fragility=0.4,coverage=0.3,steps=0.1,severity=0.15,rollback_failure=0.05"')
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    if args.out is None:
        args.out = Path("verified-rollout/reports") / f"{args.intent.stem}.pro.md"
    run(
        args.intent,
        n_plans=args.n_plans,
        chaos_pairs=args.chaos_pairs,
        utility_str=args.utility,
        out_path=args.out,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
