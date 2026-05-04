"""Feature-planning CLI — spike pivot of cli_pro.

Same architecture as verified-rollout's cli_pro:
  1. 6 stakeholder personas debate via structured constraints (parallel).
  2. 3 sequencer variants produce plan variants (parallel).
  3. Z3 SMT verifies each plan's step ordering.
  4. Markdown report + JSON sidecar.

Differences from cli_pro:
  - Personas: ProductPM, Designer, EngLead, QA, Security, GTM.
  - Step schema: success_criterion / definition_of_done / instrumentation /
    launch_strategy / estimated_days (vs gate / rollback / observability).
  - Sequencers: mvp_fast / standard / robust_launch (vs aggressive / balanced /
    conservative).
  - No chaos analysis in the spike (timeline-risk mode is a TODO; the static
    cascade analysis already in mirofish_lab.chaos_static would carry over
    unchanged).

Usage:
    python feature-planning/cli_feature.py <intent.md> [--out path.md]
"""

from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import os

from mirofish_lab import Agent, load_config, parallel_run
from mirofish_lab.feature_planning import (
    FEATURE_SEQUENCERS,
    FEATURE_STAKEHOLDER_PERSONAS,
    FeatureConstraint,
    FeatureUtilityWeights,
    score_feature_plan,
    utility_score,
)
from mirofish_lab.feature_synthesis import SynthesisResult, synthesize_all
from mirofish_lab.rollout import extract_json
from mirofish_lab.timeline_chaos import (
    TimelineChaosResult,
    timeline_chaos_summary,
)
from mirofish_lab.verify_smt import (
    SMTVerificationResult,
    explain_infeasibility,
    smt_verify_plan,
)


def _synthesis_mode() -> str:
    """Selects 'multistage' (default) or 'monolith' (back-compat).

    Default flipped to multistage after the A1 architectural change
    (commit landing the 4-stage pipeline). Set
    MIROFISH_FEATURE_SYNTHESIS=monolith to compare against pre-A1
    baselines like FEATURE_BASELINE_N50_safe.json.
    """
    val = os.environ.get("MIROFISH_FEATURE_SYNTHESIS", "").strip().lower()
    if val in ("monolith", "single", "legacy"):
        return "monolith"
    return "multistage"


def _intent_prompt(intent_text: str) -> str:
    return (
        "# Proposed feature\n\n"
        f"{intent_text.strip()}\n\n"
        "As your stakeholder persona, contribute the constraints in your "
        "axis that this feature plan must honour. Output JSON per the "
        "schema in your system prompt."
    )


def _parse_constraints(raw: object, owner: str) -> list[FeatureConstraint]:
    if not isinstance(raw, list):
        return []
    out: list[FeatureConstraint] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        item["owner"] = owner
        c = FeatureConstraint.from_dict(item, default_owner=owner)
        if c.summary:
            out.append(c)
    return out


def _gather_constraints(intent: str, cfg) -> list[FeatureConstraint]:
    agents = [Agent(p, cfg) for p in FEATURE_STAKEHOLDER_PERSONAS]
    print(f"[constraints] {len(agents)} stakeholders in parallel", file=sys.stderr)
    responses = parallel_run(agents, _intent_prompt(intent))
    out: list[FeatureConstraint] = []
    for r in responses:
        parsed = extract_json(r.content)
        cs = _parse_constraints(parsed, owner=r.agent_name)
        print(f"[constraints]   {r.agent_name}: {len(cs)}", file=sys.stderr)
        out.extend(cs)
    return out


def _generate_plans(intent: str, constraints: list[FeatureConstraint], cfg) -> dict[str, dict]:
    constraints_json = json.dumps([c.raw for c in constraints], indent=2)

    def one(label: str, persona) -> tuple[str, dict]:
        agent = Agent(persona, cfg)
        prompt = (
            f"# Feature intent\n\n{intent.strip()}\n\n"
            f"# Stakeholder constraints (merged)\n\n```json\n{constraints_json}\n```\n\n"
            "Produce the feature plan as a JSON object per your schema."
        )
        resp = agent.respond(prompt)
        plan = extract_json(resp.content) or {}
        if isinstance(plan, list):
            plan = {"summary": "", "steps": plan, "open_questions": [], "conflicts": []}
        if not isinstance(plan, dict):
            plan = {"summary": "", "steps": [], "open_questions": [], "conflicts": []}
        return label, plan

    out: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(one, label, p) for label, p in FEATURE_SEQUENCERS.items()]
        for fut in as_completed(futures):
            label, plan = fut.result()
            out[label] = plan
            print(
                f"[sequencer] {label}: {len(plan.get('steps') or [])} steps, "
                f"{len(plan.get('conflicts') or [])} conflicts",
                file=sys.stderr,
            )
    return {k: out[k] for k in FEATURE_SEQUENCERS if k in out}


def _smt_verify_all(plans: dict[str, dict], constraints: list[FeatureConstraint]) -> dict[str, SMTVerificationResult]:
    out = {}
    constr_dicts = [c.raw for c in constraints]
    for label, plan in plans.items():
        out[label] = smt_verify_plan(plan, constr_dicts, plan_id=label)
    return out


def _render_plan_table(plan: dict) -> str:
    steps = plan.get("steps") or []
    if not steps:
        return "_(empty plan)_\n"
    lines = [
        "| ID | Action | Owner | depends_on | Success criterion | DoD | Instrumentation | Launch | Est. days |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for s in steps:
        if not isinstance(s, dict):
            continue
        lines.append(
            f"| {s.get('id','?')} | {s.get('action','?')} | "
            f"{s.get('owner','?')} | {','.join(s.get('depends_on', []))} | "
            f"{s.get('success_criterion','?')} | {s.get('definition_of_done','?')} | "
            f"{s.get('instrumentation','?')} | {s.get('launch_strategy','?')} | "
            f"{s.get('estimated_days','?')} |"
        )
    return "\n".join(lines) + "\n"


def _total_days(plan: dict) -> int:
    return sum(int(s.get("estimated_days", 0) or 0)
               for s in (plan.get("steps") or []) if isinstance(s, dict))


def _render_smt(smt: SMTVerificationResult) -> str:
    if smt.feasible:
        return f"_Z3 SMT: feasible ({smt.n_steps} steps, backend={smt.backend})_"
    core = explain_infeasibility(smt)
    return f"_Z3 SMT: **INFEASIBLE** — {core}_"


def _render_timeline_chaos(tl: TimelineChaosResult) -> list[str]:
    if tl.n_steps == 0:
        return ["_Timeline chaos: empty plan_"]
    cp = " -> ".join(tl.critical_path) if tl.critical_path else "(none)"
    lines = [
        f"_Timeline: base **{tl.base_total_days} days** (critical path "
        f"{len(tl.critical_path)}/{tl.n_steps} steps), slip-fragility "
        f"**{tl.slip_fragility:.2f}** (1.0 = every step is binding)._",
        "",
        f"- Critical path: `{cp}`",
    ]
    if tl.top_single_slips:
        worst = tl.top_single_slips[0]
        lines.append(
            f"- Worst single slip (+{worst.slip_days}d): `{worst.step_ids[0]}` "
            f"→ project +{worst.delta_days}d"
        )
    if tl.top_pair_slips:
        worst = tl.top_pair_slips[0]
        lines.append(
            f"- Worst pair slip (+{worst.slip_days}d each): "
            f"`{worst.step_ids[0]}` + `{worst.step_ids[1]}` "
            f"→ project +{worst.delta_days}d"
        )
    # Steps with most slack (safest to slip)
    slack_sorted = sorted(tl.slack_per_step.items(), key=lambda kv: -kv[1])
    safest = [f"`{sid}` ({d}d)" for sid, d in slack_sorted[:3] if d > 0]
    if safest:
        lines.append(f"- Steps with most slack (safest to slip): {', '.join(safest)}")
    return lines


def run(
    intent_path: Path,
    *,
    out_md: Path | None = None,
    weights: FeatureUtilityWeights | None = None,
) -> dict:
    cfg = load_config()
    intent = intent_path.read_text()
    weights = weights or FeatureUtilityWeights()

    constraints = _gather_constraints(intent, cfg)

    mode = _synthesis_mode()
    print(f"[synthesis] mode={mode}", file=sys.stderr)
    if mode == "multistage":
        synth: SynthesisResult = synthesize_all(intent, constraints, cfg)
        plans = synth.plans
        synth_audit = synth.as_audit_dict()
    else:
        plans = _generate_plans(intent, constraints, cfg)
        synth_audit = None

    smt = _smt_verify_all(plans, constraints)
    timeline = {label: timeline_chaos_summary(plan, plan_id=label)
                for label, plan in plans.items()}
    metrics = {
        label: score_feature_plan(
            plans[label], constraints,
            slip_fragility=timeline[label].slip_fragility,
        )
        for label in plans
    }
    scores = {label: utility_score(metrics[label], weights)
              for label in plans}

    # Render report.
    lines = [
        f"# Feature plan — `{intent_path.name}`",
        "",
        f"_Generated by feature-planning/cli_feature.py · {len(constraints)} "
        f"stakeholder constraints · {len(plans)} plan variants._",
        "",
        "## Stakeholder constraints (merged)",
        "",
        "| Owner | Axis | Blocking | Summary | Acceptance | Prereq |",
        "|---|---|---|---|---|---|",
    ]
    for c in constraints:
        lines.append(
            f"| {c.owner} | {c.axis} | {'**yes**' if c.blocking else 'no'} | "
            f"{c.summary} | {c.acceptance} | {c.prereq} |"
        )
    lines.append("")

    for label, plan in plans.items():
        s_total = _total_days(plan)
        lines += [
            f"## Plan: `{label}` ({len(plan.get('steps', []))} steps, "
            f"~{s_total} sum-days, **{timeline[label].base_total_days} "
            f"critical-path days**)",
            "",
            f"_{plan.get('summary','(no summary)')}_",
            "",
            _render_smt(smt[label]),
            "",
            *_render_timeline_chaos(timeline[label]),
            "",
            f"_Utility score: **{scores[label]:.3f}** "
            f"(polish={metrics[label]['polish_coverage']:.0%}, "
            f"days={metrics[label]['total_days']}, "
            f"slip-fragility={metrics[label]['slip_fragility']:.2f}, "
            f"conflicts={metrics[label]['n_conflicts']})_",
            "",
            _render_plan_table(plan),
            "",
        ]
        conflicts = plan.get("conflicts") or []
        if conflicts:
            lines.append("**Conflicts found:**")
            for c in conflicts:
                if isinstance(c, dict):
                    lines.append(f"- {c.get('between','?')}: {c.get('issue','?')}")
            lines.append("")
        oq = plan.get("open_questions") or []
        if oq:
            lines.append("**Open questions:**")
            for q in oq:
                lines.append(f"- {q}")
            lines.append("")

    # Pick a winner: highest utility score among Z3-feasible plans.
    feasible_scored = [(label, scores[label]) for label in plans
                       if smt[label].feasible]
    if feasible_scored:
        winner = max(feasible_scored, key=lambda kv: kv[1])[0]
        lines += [
            "## Recommendation",
            "",
            f"**Winner:** `{winner}` — highest utility score "
            f"({scores[winner]:.3f}) under weights "
            f"`time_to_market={weights.time_to_market:.2f}, "
            f"polish={weights.polish:.2f}, "
            f"slip_risk={weights.slip_risk:.2f}, "
            f"conflicts={weights.conflicts:.2f}`.",
            "",
            "| Plan | Utility | Polish | Days (cp) | Slip-fragility | Conflicts |",
            "|---|---|---|---|---|---|",
        ]
        for label in plans:
            m = metrics[label]
            lines.append(
                f"| `{label}` | {scores[label]:.3f} | "
                f"{m['polish_coverage']:.0%} | "
                f"{timeline[label].base_total_days} | "
                f"{m['slip_fragility']:.2f} | "
                f"{m['n_conflicts']} |"
            )
        lines.append("")
        lines.append(
            "_Use `--prefer fast|polished|safe|balanced` or "
            "`--utility 'time_to_market=0.5,polish=0.2,slip_risk=0.2,conflicts=0.1'` "
            "to override._"
        )
    else:
        lines += ["## Recommendation", "", "_No feasible plan; review conflicts._"]

    out_md = out_md or Path(f"feature-planning/reports/{intent_path.stem}.feature.md")
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text("\n".join(lines))

    sidecar = {
        "intent_path": str(intent_path),
        "constraints": [c.raw for c in constraints],
        "plans": plans,
        "smt": {label: {"feasible": r.feasible, "backend": r.backend,
                        "n_steps": r.n_steps, "notes": r.notes,
                        "unsat_core": list(r.unsat_core)}
                for label, r in smt.items()},
        "timeline": {label: {
            "base_total_days": tl.base_total_days,
            "critical_path": list(tl.critical_path),
            "slack_per_step": tl.slack_per_step,
            "slip_fragility": tl.slip_fragility,
            "top_single_slips": [
                {"step_ids": list(e.step_ids), "slip_days": e.slip_days,
                 "delta_days": e.delta_days, "new_total": e.new_total}
                for e in tl.top_single_slips],
            "top_pair_slips": [
                {"step_ids": list(e.step_ids), "slip_days": e.slip_days,
                 "delta_days": e.delta_days, "new_total": e.new_total}
                for e in tl.top_pair_slips],
        } for label, tl in timeline.items()},
        "metrics": metrics,
        "scores": scores,
        "weights": {
            "time_to_market": weights.time_to_market,
            "polish": weights.polish,
            "slip_risk": weights.slip_risk,
            "conflicts": weights.conflicts,
        },
        "winner": winner if feasible_scored else None,
        "synthesis_mode": mode,
    }
    if synth_audit is not None:
        sidecar["multistage_audit"] = synth_audit
    out_md.with_suffix(".json").write_text(json.dumps(sidecar, indent=2))
    print(f"\n[done] wrote {out_md}", file=sys.stderr)
    return sidecar


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Feature plan synthesiser — multi-stakeholder + Z3 + timeline-risk"
    )
    parser.add_argument("intent_path", type=Path)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument(
        "--prefer", choices=["fast", "polished", "safe", "balanced"],
        default=None,
        help="Named utility-weight preset for the recommendation.",
    )
    parser.add_argument(
        "--utility", default=None,
        help="Custom utility weights, e.g. "
             "'time_to_market=0.5,polish=0.2,slip_risk=0.2,conflicts=0.1'. "
             "Overrides --prefer.",
    )
    args = parser.parse_args(argv)

    if not args.intent_path.exists():
        print(f"intent not found: {args.intent_path}", file=sys.stderr)
        return 1

    if args.utility:
        weights = FeatureUtilityWeights.from_string(args.utility)
    elif args.prefer:
        weights = FeatureUtilityWeights.preset(args.prefer)
    else:
        weights = FeatureUtilityWeights()

    run(args.intent_path, out_md=args.out, weights=weights)
    return 0


if __name__ == "__main__":
    sys.exit(main())
