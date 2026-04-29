"""verified-rollout chaos-depth mode: comprehensive chaos analysis on a single plan.

Pipeline:
    1. Gather stakeholder constraints (reuse rollout-rehearsal personas).
    2. Generate ONE plan with the balanced sequencer.
    3. Run FOUR chaos analyses on it:
        a) LLM-based per-step probe (the original chaos_probe).
        b) Static cascade computation: exhaustive K-tuple Achilles for
           K in {1, 2, 3} via mirofish_lab.chaos_static.
        c) Adversarial search: LLM Attacker proposes worst-K combos,
           static-scored, multi-round (mirofish_lab.chaos_search).
        d) Monte Carlo: per-gate failure priors + N-sample
           probabilistic simulation (mirofish_lab.chaos_montecarlo).
    4. Cross-validate the three approaches (LLM probe vs static vs MC)
       and surface where they agree/disagree.
    5. Render a deep markdown chaos report + JSON sidecar.

Usage:
    python verified-rollout/cli_chaos.py <intent.md> \\
        [--mc-samples 500] [--search-rounds 3] [--search-k 2]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mirofish_lab import Agent, Report, load_config, parallel_run
from mirofish_lab.chaos import chaos_probe
from mirofish_lab.chaos_montecarlo import montecarlo_simulate
from mirofish_lab.chaos_search import adversarial_search
from mirofish_lab.chaos_static import (
    AchillesEntry,
    static_cascade,
    static_chaos_summary,
)
from mirofish_lab.config import verify_model
from mirofish_lab.pareto import PARETO_SEQUENCERS
from mirofish_lab.rollout import (
    Constraint,
    STAKEHOLDER_PERSONAS,
    extract_json,
)


def _intent_prompt(intent_text: str) -> str:
    return (
        "# Proposed change\n\n"
        f"{intent_text.strip()}\n\n"
        "As your stakeholder persona, contribute the constraints in your "
        "axis that this rollout must honour."
    )


def _parse_constraints(raw, owner: str) -> list[Constraint]:
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
        out.extend(cs)
    return out


def _generate_balanced_plan(intent: str, constraints: list[Constraint], cfg) -> dict:
    constraints_json = json.dumps([c.raw for c in constraints], indent=2)
    persona = PARETO_SEQUENCERS["balanced"]
    agent = Agent(persona, cfg)
    prompt = (
        f"# Migration intent\n\n{intent.strip()}\n\n"
        f"# Stakeholder constraints (merged)\n\n```json\n{constraints_json}\n```\n\n"
        "Produce the partial-order plan as a JSON object per your schema."
    )
    resp = agent.respond(prompt)
    plan = extract_json(resp.content) or {}
    if isinstance(plan, list):
        plan = {"summary": "", "steps": plan, "open_questions": [], "conflicts": []}
    if not isinstance(plan, dict):
        plan = {"summary": "", "steps": [], "open_questions": [], "conflicts": []}
    return plan


def _render_static(static_summary, plan: dict) -> str:
    by_id = {s["id"]: s for s in plan.get("steps") or [] if isinstance(s, dict) and s.get("id")}
    lines = [
        f"- N steps: {static_summary.n_steps}",
        f"- Fragility curve (avg over all K-tuples): "
        + ", ".join(f"k={k} → {v}" for k, v in sorted(static_summary.fragility_curve.items())),
    ]
    for k, entries in sorted(static_summary.achilles_top_per_k.items()):
        lines.append(f"\n**Top-3 worst-{k} failures (structural)**:")
        lines.append("")
        lines.append("| Failure set | Blocked | Fragility |")
        lines.append("|---|---|---|")
        for e in entries[:3]:
            ids = ", ".join(f"`{i}`" for i in e.failure_set)
            blocked = ", ".join(f"`{b}`" for b in e.blocked) or "—"
            lines.append(f"| {ids} | {blocked} | {e.fragility} |")
    return "\n".join(lines)


def _render_search(search_result) -> str:
    lines = [
        f"- K = {search_result.k}; rounds = {search_result.rounds}",
        f"- Candidates proposed: {search_result.n_candidates_proposed}; "
        f"unique scored: {search_result.n_candidates_scored}",
        "- Round-by-round:",
    ]
    for h in search_result.history:
        lines.append(
            f"  - round {h['round']}: proposed={h['proposed']} added={h['added']} "
            f"best_round={h['best_fragility_round']} best_so_far={h['best_fragility_so_far']}"
        )
    if not search_result.best:
        lines.append("\n_(no candidates scored)_")
        return "\n".join(lines)
    lines.append("")
    lines.append("**Top adversarial finds**:")
    lines.append("")
    lines.append("| Failure set | Blocked | Fragility | Reasoning |")
    lines.append("|---|---|---|---|")
    for c in search_result.best:
        ids = ", ".join(f"`{i}`" for i in c.ids)
        blocked = ", ".join(f"`{b}`" for b in c.blocked) or "—"
        lines.append(f"| {ids} | {blocked} | {c.fragility} | {c.reasoning[:80]} |")
    return "\n".join(lines)


def _render_montecarlo(mc) -> str:
    lines = [
        f"- N samples: {mc.n_samples}",
        f"- Avg success rate: **{mc.avg_success_rate}**",
        f"- p10 / p50 / p90: {mc.p10_success_rate} / {mc.p50_success_rate} / {mc.p90_success_rate}",
        f"- Full success rate (every step completed): {mc.full_success_rate}",
        f"- Full failure rate (no steps completed): {mc.full_failure_rate}",
        "",
        "**Per-step failure rate (descending)**:",
        "",
        "| Step | Failure rate |",
        "|---|---|",
    ]
    for sid, r in sorted(mc.per_step_failure_rate.items(), key=lambda kv: -kv[1]):
        lines.append(f"| `{sid}` | {r} |")
    lines.append("")
    lines.append("**Success-rate histogram**:")
    lines.append("")
    lines.append("| Bucket | Count |")
    lines.append("|---|---|")
    for bucket, count in mc.histogram.items():
        lines.append(f"| {bucket} | {count} |")
    return "\n".join(lines)


def _cross_validate(llm_chaos, static_summary, search_result) -> str:
    """Identify where LLM and structural agree/disagree on Achilles heel."""
    static_top1 = []
    if 1 in static_summary.achilles_top_per_k:
        static_top1 = [
            e.failure_set[0] for e in static_summary.achilles_top_per_k[1][:5]
        ]
    llm_top = [sid for sid, _ in llm_chaos.achilles_heel[:5]]
    in_both = set(static_top1) & set(llm_top)
    only_static = set(static_top1) - set(llm_top)
    only_llm = set(llm_top) - set(static_top1)

    lines = [
        f"- LLM probe top-5 Achilles: {llm_top}",
        f"- Static top-5 Achilles (k=1): {static_top1}",
        f"- Agreement: {sorted(in_both) or 'NONE'}",
        f"- Static-only (LLM missed): {sorted(only_static) or 'none'}",
        f"- LLM-only (probably noise): {sorted(only_llm) or 'none'}",
    ]
    if search_result.best:
        worst_search = search_result.best[0]
        worst_static_k = static_summary.achilles_top_per_k.get(search_result.k, [])
        worst_static = worst_static_k[0] if worst_static_k else None
        lines.append("")
        lines.append(
            f"- Adversarial search best k={search_result.k}: "
            f"{list(worst_search.ids)} → fragility {worst_search.fragility}"
        )
        if worst_static:
            lines.append(
                f"- Exhaustive-static best k={search_result.k}: "
                f"{list(worst_static.failure_set)} → fragility {worst_static.fragility}"
            )
            if worst_search.fragility >= worst_static.fragility:
                lines.append(
                    "- **Adversarial search matched or beat exhaustive search "
                    "(unusual; likely LLM got lucky on a tie)**"
                )
            else:
                ratio = worst_search.fragility / max(0.001, worst_static.fragility)
                lines.append(
                    f"- Adversarial / exhaustive ratio: {ratio:.2f} "
                    f"(1.0 = adversarial found the optimum; lower = LLM left worse cases on table)"
                )
    return "\n".join(lines)


def run(intent_path: Path, *, mc_samples: int, search_rounds: int, search_k: int,
        out_path: Path) -> Path:
    cfg = load_config()
    verify_model(cfg)
    intent = intent_path.read_text()
    print(f"[intent] {intent_path}", file=sys.stderr)

    constraints = _gather_constraints(intent, cfg)
    plan = _generate_balanced_plan(intent, constraints, cfg)
    print(
        f"[plan] {len(plan.get('steps') or [])} steps, "
        f"{len(plan.get('conflicts') or [])} conflicts",
        file=sys.stderr,
    )

    # 1. LLM-based probe.
    print("[chaos] running LLM-based probe...", file=sys.stderr)
    llm_chaos = chaos_probe(
        plan,
        cfg=cfg,
        plan_id="balanced",
        intent=intent,
        n_samples=0,
        multi_failure_pairs=0,        # disable LLM multi-pair (validated weakness)
        extra_failure_types=("rollback_failure",),
    )

    # 2. Static cascade summary.
    print("[chaos] running static cascade analysis...", file=sys.stderr)
    static_summary = static_chaos_summary(plan, plan_id="balanced",
                                          budgets=(1, 2, 3), top_n=5)

    # 3. Adversarial search.
    print(f"[chaos] running adversarial search (k={search_k}, rounds={search_rounds})...",
          file=sys.stderr)
    search_result = adversarial_search(
        plan, cfg=cfg, plan_id="balanced",
        k=search_k, rounds=search_rounds, top_n=5,
    )

    # 4. Monte Carlo.
    print(f"[chaos] running Monte Carlo (n_samples={mc_samples})...", file=sys.stderr)
    mc = montecarlo_simulate(plan, plan_id="balanced", n_samples=mc_samples)

    # Build report.
    out_path.parent.mkdir(parents=True, exist_ok=True)
    report = Report(
        title=f"Chaos Depth — {intent_path.stem}",
        meta={
            "Intent": str(intent_path),
            "Steps": str(len(plan.get("steps") or [])),
            "MC samples": str(mc_samples),
            "Adversarial K": str(search_k),
            "Adversarial rounds": str(search_rounds),
            "Model": cfg.model,
        },
    )
    report.add(
        "Plan summary",
        f"Generated by `Sequencer_Balanced`. {len(plan.get('steps') or [])} steps."
    )
    report.add("LLM probe", f"- fragility (single-step): {llm_chaos.fragility}\n"
                            f"- avg severity: {llm_chaos.avg_severity}\n"
                            f"- rollback-failure rate: {llm_chaos.rollback_failure_rate}\n"
                            f"- top Achilles (LLM): "
                            + ", ".join(f"`{s}`={f}" for s, f in llm_chaos.achilles_heel[:5]))
    report.add("Static cascade analysis (graph-based, exact)", _render_static(static_summary, plan))
    report.add("Adversarial chaos search (LLM-proposed, static-scored)",
               _render_search(search_result))
    report.add("Monte Carlo robustness simulation", _render_montecarlo(mc))
    report.add("Cross-validation (LLM vs static vs adversarial)",
               _cross_validate(llm_chaos, static_summary, search_result))

    written = report.write(out_path)

    # JSON sidecar.
    json_path = out_path.with_suffix(".json")
    json_path.write_text(json.dumps({
        "intent_path": str(intent_path),
        "plan": plan,
        "constraints": [c.raw for c in constraints],
        "llm_probe": {
            "fragility": llm_chaos.fragility,
            "avg_severity": llm_chaos.avg_severity,
            "rollback_failure_rate": llm_chaos.rollback_failure_rate,
            "achilles_heel": llm_chaos.achilles_heel,
            "recovery_distribution": llm_chaos.recovery_distribution,
        },
        "static": {
            "fragility_curve": static_summary.fragility_curve,
            "overall_fragility": static_summary.overall_fragility,
            "achilles_top_per_k": {
                k: [
                    {
                        "failure_set": list(e.failure_set),
                        "blocked": list(e.blocked),
                        "fragility": e.fragility,
                    }
                    for e in entries
                ]
                for k, entries in static_summary.achilles_top_per_k.items()
            },
        },
        "adversarial_search": {
            "k": search_result.k,
            "rounds": search_result.rounds,
            "n_proposed": search_result.n_candidates_proposed,
            "n_scored": search_result.n_candidates_scored,
            "history": search_result.history,
            "best": [
                {
                    "ids": list(c.ids),
                    "blocked": list(c.blocked),
                    "fragility": c.fragility,
                    "reasoning": c.reasoning,
                }
                for c in search_result.best
            ],
        },
        "montecarlo": {
            "n_samples": mc.n_samples,
            "avg_success_rate": mc.avg_success_rate,
            "p10": mc.p10_success_rate,
            "p50": mc.p50_success_rate,
            "p90": mc.p90_success_rate,
            "full_success_rate": mc.full_success_rate,
            "full_failure_rate": mc.full_failure_rate,
            "per_step_failure_rate": mc.per_step_failure_rate,
            "histogram": mc.histogram,
        },
    }, indent=2))
    print(f"[done] wrote {written} and {json_path}", file=sys.stderr)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deep chaos analysis on a single plan.")
    parser.add_argument("intent", type=Path)
    parser.add_argument("--mc-samples", type=int, default=500)
    parser.add_argument("--search-rounds", type=int, default=3)
    parser.add_argument("--search-k", type=int, default=2)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    if args.out is None:
        args.out = Path("verified-rollout/reports") / f"{args.intent.stem}.chaos.md"
    run(
        args.intent,
        mc_samples=args.mc_samples,
        search_rounds=args.search_rounds,
        search_k=args.search_k,
        out_path=args.out,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
