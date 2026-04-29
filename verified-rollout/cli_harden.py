"""verified-rollout closed-loop hardening: iteratively fix a fragile plan.

Pipeline:
  1. Gather stakeholder constraints (reuse rollout-rehearsal).
  2. Generate base plan (balanced sequencer).
  3. Loop until fragility threshold met or max-iterations:
       a. Run chaos analyses (static + LLM probe).
       b. If fragility <= threshold: stop, success.
       c. Hardener proposes new plan targeting current findings.
       d. Verify new plan with Z3 SMT. If infeasible: rollback to
          previous and stop.
       e. Replace plan with hardened version.
  4. Render full trajectory + final plan + before/after diff.

The output is the most differentiated artifact this playground
produces: instead of "your plan is fragile" it shows "your plan was
fragile (X), here's the hardened version (Y), here's exactly what
changed and why."

Usage:
    python verified-rollout/cli_harden.py <intent.md> \\
        [--threshold 0.3] [--max-iterations 4]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mirofish_lab import Agent, Report, load_config, parallel_run
from mirofish_lab.chaos import chaos_probe
from mirofish_lab.chaos_hardener import HardenResult, harden_plan
from mirofish_lab.chaos_static import static_chaos_summary
from mirofish_lab.config import verify_model
from mirofish_lab.pareto import PARETO_SEQUENCERS
from mirofish_lab.rollout import (
    Constraint,
    STAKEHOLDER_PERSONAS,
    extract_json,
)
from mirofish_lab.verify_smt import smt_verify_plan


def _intent_prompt(intent: str) -> str:
    return (
        "# Proposed change\n\n"
        f"{intent.strip()}\n\n"
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


def _generate_base_plan(intent: str, constraints: list[Constraint], cfg) -> dict:
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


def _llm_probe_summary(chaos_result) -> dict:
    return {
        "rollback_failure_rate": chaos_result.rollback_failure_rate,
        "achilles_heel": chaos_result.achilles_heel,
    }


def _diff_steps(plan_a: dict, plan_b: dict) -> list[str]:
    a_ids = [s.get("id") for s in plan_a.get("steps") or [] if isinstance(s, dict)]
    b_ids = [s.get("id") for s in plan_b.get("steps") or [] if isinstance(s, dict)]
    a_by_id = {s.get("id"): s for s in plan_a.get("steps") or [] if isinstance(s, dict)}
    b_by_id = {s.get("id"): s for s in plan_b.get("steps") or [] if isinstance(s, dict)}
    notes = []
    if len(a_ids) != len(b_ids):
        notes.append(f"step count: {len(a_ids)} -> {len(b_ids)}")
    added = set(b_ids) - set(a_ids)
    removed = set(a_ids) - set(b_ids)
    if added:
        notes.append(f"added: {sorted(added)}")
    if removed:
        notes.append(f"removed: {sorted(removed)}")
    edited: list[str] = []
    for sid in set(a_ids) & set(b_ids):
        a, b = a_by_id[sid], b_by_id[sid]
        for field in ("action", "gate", "rollback", "observability"):
            if a.get(field) != b.get(field):
                edited.append(f"{sid}.{field}: '{(a.get(field) or '')[:40]}' → '{(b.get(field) or '')[:40]}'")
        if (a.get("depends_on") or []) != (b.get("depends_on") or []):
            edited.append(f"{sid}.depends_on: {a.get('depends_on')} → {b.get('depends_on')}")
    if edited:
        notes.append("edits:")
        notes.extend(f"  - {e}" for e in edited[:20])
    return notes


def run(
    intent_path: Path,
    *,
    threshold: float,
    max_iterations: int,
    out_path: Path,
) -> Path:
    cfg = load_config()
    verify_model(cfg)
    intent = intent_path.read_text()
    print(f"[intent] {intent_path}", file=sys.stderr)

    constraints = _gather_constraints(intent, cfg)
    plan = _generate_base_plan(intent, constraints, cfg)
    print(f"[base] {len(plan.get('steps') or [])} steps", file=sys.stderr)

    raw_constraints = [c.raw for c in constraints]
    trajectory: list[dict] = []
    iteration = 0
    converged = False
    final_reason = "max_iterations_reached"

    # Initial chaos analysis on base plan.
    base_chaos = static_chaos_summary(plan, plan_id="base", budgets=(1, 2))
    base_smt = smt_verify_plan(plan, raw_constraints, plan_id="base")
    print(
        f"[iter 0 (base)] fragility={base_chaos.overall_fragility} "
        f"smt_feasible={base_smt.feasible}",
        file=sys.stderr,
    )
    trajectory.append({
        "iteration": 0,
        "stage": "base",
        "fragility": base_chaos.overall_fragility,
        "n_steps": base_chaos.n_steps,
        "smt_feasible": base_smt.feasible,
        "smt_unsat_core_size": len(base_smt.unsat_core),
        "achilles_top": [list(e.failure_set) for e in base_chaos.achilles_top_per_k.get(1, [])[:3]],
        "diff_from_previous": ["initial plan"],
    })

    if base_chaos.overall_fragility <= threshold:
        converged = True
        final_reason = f"already below threshold ({base_chaos.overall_fragility} <= {threshold})"
    else:
        current_plan = plan
        current_chaos = base_chaos

        for iteration in range(1, max_iterations + 1):
            # Run a quick LLM probe so the Hardener has rollback signal too.
            llm_chaos = chaos_probe(
                current_plan,
                cfg=cfg,
                plan_id=f"iter{iteration}",
                intent=intent,
                n_samples=0,                  # exhaustive single-step
                multi_failure_pairs=0,
                extra_failure_types=("rollback_failure",),
            )
            print(
                f"[iter {iteration}] probing... fragility(LLM)={llm_chaos.fragility} "
                f"rb_fail={llm_chaos.rollback_failure_rate}",
                file=sys.stderr,
            )

            # If the current plan is SMT-infeasible, pass the unsat core to
            # the hardener so it can prioritise ordering fixes over fragility.
            current_smt = smt_verify_plan(
                current_plan, raw_constraints, plan_id=f"iter{iteration}_pre"
            )
            smt_findings = None
            if not current_smt.feasible:
                smt_findings = {
                    "infeasible": True,
                    "unsat_core_explanations": current_smt.unsat_core_explanations,
                }

            harden_result = harden_plan(
                current_plan,
                cfg=cfg,
                plan_id=f"iter{iteration}",
                iteration=iteration,
                chaos=current_chaos,
                llm_probe_summary=_llm_probe_summary(llm_chaos),
                smt_findings=smt_findings,
            )

            new_plan = harden_result.plan_after
            new_smt = smt_verify_plan(
                new_plan, raw_constraints, plan_id=f"iter{iteration}"
            )
            new_chaos = static_chaos_summary(
                new_plan, plan_id=f"iter{iteration}", budgets=(1, 2)
            )

            diff = _diff_steps(current_plan, new_plan)

            print(
                f"[iter {iteration}] fragility {harden_result.fragility_before} → "
                f"{harden_result.fragility_after} "
                f"(Δ {harden_result.fragility_delta}); "
                f"steps {harden_result.n_steps_before}→{harden_result.n_steps_after}; "
                f"smt_feasible={new_smt.feasible}",
                file=sys.stderr,
            )

            trajectory.append({
                "iteration": iteration,
                "stage": "hardened",
                "fragility": new_chaos.overall_fragility,
                "fragility_delta": harden_result.fragility_delta,
                "n_steps": new_chaos.n_steps,
                "smt_feasible": new_smt.feasible,
                "smt_unsat_core_size": len(new_smt.unsat_core),
                "achilles_top": [list(e.failure_set) for e in new_chaos.achilles_top_per_k.get(1, [])[:3]],
                "diff_from_previous": diff,
                "llm_probe_rollback_failure_rate": llm_chaos.rollback_failure_rate,
            })

            if not new_smt.feasible:
                # Hardener produced an infeasible plan; stop and keep current.
                final_reason = (
                    f"iteration {iteration}: hardened plan infeasible by Z3 "
                    f"(unsat core size {len(new_smt.unsat_core)})"
                )
                break

            current_plan = new_plan
            current_chaos = new_chaos

            if new_chaos.overall_fragility <= threshold:
                converged = True
                final_reason = (
                    f"converged at iteration {iteration}: "
                    f"fragility {new_chaos.overall_fragility} <= {threshold}"
                )
                break

            if abs(harden_result.fragility_delta) < 0.01:
                final_reason = (
                    f"iteration {iteration}: no improvement "
                    f"(Δ {harden_result.fragility_delta})"
                )
                break

        plan = current_plan
        base_chaos = current_chaos

    # Build report.
    out_path.parent.mkdir(parents=True, exist_ok=True)
    report = Report(
        title=f"Closed-Loop Hardening — {intent_path.stem}",
        meta={
            "Intent": str(intent_path),
            "Threshold": str(threshold),
            "Max iterations": str(max_iterations),
            "Converged": "YES" if converged else "no",
            "Reason": final_reason,
            "Initial fragility": str(trajectory[0]["fragility"]),
            "Final fragility": str(trajectory[-1]["fragility"]),
            "Model": cfg.model,
        },
    )
    report.add(
        "Convergence summary",
        f"- iterations run: {len(trajectory) - 1} (after base)\n"
        f"- final reason: **{final_reason}**\n"
        f"- fragility trajectory: " +
        " → ".join(f"{t['fragility']}" for t in trajectory)
    )

    rows = ["| Iter | Stage | Steps | Fragility | Δ | SMT feasible | Top Achilles |",
            "|---|---|---|---|---|---|---|"]
    for t in trajectory:
        delta = t.get("fragility_delta", "—")
        rows.append(
            f"| {t['iteration']} | {t['stage']} | {t['n_steps']} | "
            f"{t['fragility']} | {delta} | "
            f"{'Y' if t['smt_feasible'] else 'N'} | "
            f"{t['achilles_top']} |"
        )
    report.add("Trajectory", "\n".join(rows))

    for t in trajectory:
        if t["iteration"] == 0:
            continue
        report.add(
            f"Iteration {t['iteration']} — diff",
            "\n".join(f"- {d}" for d in t["diff_from_previous"])
        )

    report.add("Final plan", json.dumps(plan, indent=2))

    written = report.write(out_path)
    json_path = out_path.with_suffix(".json")
    json_path.write_text(json.dumps({
        "intent_path": str(intent_path),
        "constraints": raw_constraints,
        "trajectory": trajectory,
        "converged": converged,
        "reason": final_reason,
        "final_plan": plan,
    }, indent=2))
    print(f"[done] wrote {written} and {json_path}", file=sys.stderr)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Closed-loop plan hardening")
    parser.add_argument("intent", type=Path)
    parser.add_argument("--threshold", type=float, default=0.4)
    parser.add_argument("--max-iterations", type=int, default=4)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    if args.out is None:
        args.out = Path("verified-rollout/reports") / f"{args.intent.stem}.harden.md"
    run(args.intent, threshold=args.threshold,
        max_iterations=args.max_iterations, out_path=args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
