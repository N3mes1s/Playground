"""verified-rollout: Pareto-frontier rollout plans with formal verification
and counterfactual chaos probing.

Pipeline:
    1. Gather stakeholder constraints (reuse rollout-rehearsal personas).
    2. Generate THREE plans on a Pareto frontier:
        - Aggressive    (speed-optimised)
        - Balanced      (default)
        - Conservative  (safety-optimised)
    3. Verify each plan structurally:
        - DAG check (no cycles in depends_on)
        - Reachability check (every step reachable)
        - Gate validity (well-formed gate strings)
        - Blocking-constraint coverage (token-overlap heuristic)
    4. Chaos-probe each plan:
        - Sample N mid-graph steps
        - For each, ask Chaos agent to predict the failure cascade
        - Aggregate fragility / severity / rollback-failure rate
    5. Recommend the Pareto-optimal plan given fragility + verification.

Usage:
    python verified-rollout/cli.py <intent.md> [--samples N] [--out FILE]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mirofish_lab import Agent, Report, load_config, parallel_run
from mirofish_lab.config import verify_model
from mirofish_lab.chaos import chaos_probe
from mirofish_lab.pareto import PARETO_SEQUENCERS
from mirofish_lab.rollout import (
    Constraint,
    SEQUENCER_PERSONA,  # not used directly; kept for parity
    STAKEHOLDER_PERSONAS,
    extract_json,
)
from mirofish_lab.verify import VerificationResult, verify_plan


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


def _generate_pareto_plans(intent: str, constraints: list[Constraint], cfg) -> dict[str, dict]:
    """Run all three Pareto sequencers in parallel; returns label -> plan dict."""
    constraints_json = json.dumps([c.raw for c in constraints], indent=2)

    def one(label: str) -> tuple[str, dict]:
        persona = PARETO_SEQUENCERS[label]
        agent = Agent(persona, cfg)
        prompt = (
            f"# Migration intent\n\n{intent.strip()}\n\n"
            f"# Stakeholder constraints (merged)\n\n```json\n{constraints_json}\n```\n\n"
            f"Produce the partial-order plan as a JSON object per your schema, "
            f"optimised for your specific axis."
        )
        resp = agent.respond(prompt)
        plan = extract_json(resp.content) or {}
        return label, plan

    # parallel_run uses Agents but here we have heterogeneous personas with
    # different prompts; just run sequentially with a tiny wrapper. Three
    # calls is fine.
    out: dict[str, dict] = {}
    from concurrent.futures import ThreadPoolExecutor, as_completed

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {pool.submit(one, k): k for k in PARETO_SEQUENCERS}
        for fut in as_completed(futures):
            label, plan = fut.result()
            out[label] = plan
            print(
                f"[pareto] {label}: {len(plan.get('steps') or [])} steps, "
                f"{len(plan.get('conflicts') or [])} conflicts",
                file=sys.stderr,
            )
    return out


def _score(plan: dict, ver: VerificationResult, chaos) -> dict:
    steps = plan.get("steps") or []
    n = len(steps)
    approval_gates = sum(
        1 for s in steps if isinstance(s, dict)
        and (s.get("gate", "") or "").startswith("approval:")
    )
    window_gates = sum(
        1 for s in steps if isinstance(s, dict)
        and (s.get("gate", "") or "").startswith("window:")
    )
    monitor_gates = sum(
        1 for s in steps if isinstance(s, dict)
        and (s.get("gate", "") or "").startswith("monitor:")
    )
    return {
        "steps": n,
        "verification_pass": ver.passes,
        "is_dag": ver.is_dag,
        "unreachable": len(ver.unreachable_steps),
        "coverage_ratio": round(ver.coverage_ratio, 2),
        "uncovered_blocking": len(ver.uncovered_blocking_summaries),
        "fragility": chaos.fragility,
        "avg_severity": chaos.avg_severity,
        "rollback_failure_rate": chaos.rollback_failure_rate,
        "approval_gates": approval_gates,
        "window_gates": window_gates,
        "monitor_gates": monitor_gates,
    }


def _recommend(scores: dict[str, dict]) -> tuple[str, str]:
    """Pareto-pick: minimise fragility, break ties by coverage_ratio, then by
    smaller step count, then prefer balanced."""
    def key(label):
        s = scores[label]
        return (
            s["fragility"],
            -s["coverage_ratio"],
            s["steps"],
            0 if label == "balanced" else 1,
        )
    ranked = sorted(scores, key=key)
    winner = ranked[0]
    rationale = (
        f"Picked '{winner}' as Pareto-optimal: "
        f"fragility={scores[winner]['fragility']}, "
        f"coverage={scores[winner]['coverage_ratio']}, "
        f"steps={scores[winner]['steps']}, "
        f"avg_severity={scores[winner]['avg_severity']}."
    )
    return winner, rationale


# ---------------------------------------------------------------------------


def _render_plan_table(plan: dict) -> str:
    steps = plan.get("steps") or []
    if not steps:
        return "_(empty)_"
    rows = ["| # | Action | Owner | Deps | Gate | Rollback |",
            "|---|---|---|---|---|---|"]
    for s in steps:
        if not isinstance(s, dict):
            continue
        deps = ", ".join(s.get("depends_on", []) or []) or "—"
        rows.append(
            f"| {s.get('id','?')} | {(s.get('action','') or '')[:90]} | "
            f"{s.get('owner','')} | {deps} | `{s.get('gate','')}` | "
            f"{(s.get('rollback','') or '')[:60]} |"
        )
    return "\n".join(rows)


def _render_verification(ver: VerificationResult) -> str:
    bullets = [
        f"- DAG: **{'pass' if ver.is_dag else 'FAIL'}**"
        + (f" cycles: {ver.cycles}" if ver.cycles else ""),
        f"- Unreachable steps: {ver.unreachable_steps or 'none'}",
        f"- Invalid gates: "
        + (", ".join(f"{i}=`{g}`" for i, g in ver.invalid_gates) or "none"),
        f"- Blocking-constraint coverage: "
        f"{ver.blocking_covered}/{ver.blocking_total} "
        f"(ratio {ver.coverage_ratio:.2f})",
    ]
    if ver.uncovered_blocking_summaries:
        bullets.append("- **Uncovered blocking constraints**:")
        for s in ver.uncovered_blocking_summaries:
            bullets.append(f"  - {s}")
    bullets.append(f"- Overall: {'PASS' if ver.passes else 'FAIL'}")
    return "\n".join(bullets)


def _render_chaos(chaos) -> str:
    if not chaos.probes:
        return "_(no probes ran)_"
    lines = [
        f"- **fragility**: {chaos.fragility} "
        f"(0 = robust, 1 = single failure cascades to all downstream)",
        f"- **avg severity**: {chaos.avg_severity} "
        f"(scale: 1 low, 2 medium, 3 high, 4 critical)",
        f"- **rollback-failure rate**: {chaos.rollback_failure_rate} "
        f"({int(chaos.rollback_failure_rate * len(chaos.probes))}/{len(chaos.probes)} "
        "probes had broken rollback chain)",
        "",
        "| Target | Severity | Rollback holds | Blocked downstream | Recovery |",
        "|---|---|---|---|---|",
    ]
    for p in chaos.probes:
        lines.append(
            f"| {p.target_id} ({p.target_action[:40]}) | {p.severity} | "
            f"{'yes' if p.rollback_holds else 'NO'} | "
            f"{', '.join(p.blocked_downstream[:6]) or '—'} | "
            f"{(p.recovery_path or 'unspecified')[:80]} |"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------


def run(intent_path: Path, *, samples: int, out_path: Path) -> Path:
    cfg = load_config()
    verify_model(cfg)
    intent = intent_path.read_text()
    print(f"[intent] {intent_path} ({len(intent)} chars)", file=sys.stderr)

    constraints = _gather_constraints(intent, cfg)
    plans = _generate_pareto_plans(intent, constraints, cfg)

    verifications: dict[str, VerificationResult] = {}
    chaos_results: dict[str, "object"] = {}
    raw_constraints = [c.raw for c in constraints]
    for label, plan in plans.items():
        ver = verify_plan(plan, raw_constraints, plan_id=label)
        verifications[label] = ver
        print(
            f"[verify]  {label}: dag={ver.is_dag} cov={ver.coverage_ratio:.2f} "
            f"pass={ver.passes}",
            file=sys.stderr,
        )
        chaos = chaos_probe(plan, cfg=cfg, plan_id=label, intent=intent, n_samples=samples)
        chaos_results[label] = chaos
        print(
            f"[chaos]   {label}: fragility={chaos.fragility} "
            f"sev={chaos.avg_severity} rb_fail={chaos.rollback_failure_rate}",
            file=sys.stderr,
        )

    scores = {
        label: _score(plans[label], verifications[label], chaos_results[label])
        for label in plans
    }
    winner, rationale = _recommend(scores)
    print(f"[recommend] {winner} — {rationale}", file=sys.stderr)

    # Build markdown.
    out_path.parent.mkdir(parents=True, exist_ok=True)
    report = Report(
        title=f"Verified Rollout — {intent_path.stem}",
        meta={
            "Intent": str(intent_path),
            "Stakeholders": str(len(STAKEHOLDER_PERSONAS)),
            "Constraints": str(len(constraints)),
            "Pareto plans": ", ".join(plans),
            "Chaos samples per plan": str(samples),
            "Recommendation": winner,
            "Model": cfg.model,
        },
    )
    report.add("Recommendation", f"**{winner}** — {rationale}")
    report.add(
        "Scoreboard",
        "| Plan | Steps | DAG | Coverage | Fragility | Severity | RB-fail | Approval | Monitor |\n"
        "|---|---|---|---|---|---|---|---|---|\n"
        + "\n".join(
            f"| {label} | {s['steps']} | {'Y' if s['is_dag'] else 'N'} | "
            f"{s['coverage_ratio']} | {s['fragility']} | {s['avg_severity']} | "
            f"{s['rollback_failure_rate']} | {s['approval_gates']} | "
            f"{s['monitor_gates']} |"
            for label, s in scores.items()
        ),
    )
    for label in plans:
        report.add(f"Plan: {label}", _render_plan_table(plans[label]))
        report.add(f"Verification: {label}", _render_verification(verifications[label]))
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
                "verifications": {
                    k: {
                        "is_dag": v.is_dag,
                        "cycles": v.cycles,
                        "unreachable_steps": v.unreachable_steps,
                        "invalid_gates": v.invalid_gates,
                        "blocking_total": v.blocking_total,
                        "blocking_covered": v.blocking_covered,
                        "uncovered_blocking_summaries": v.uncovered_blocking_summaries,
                        "passes": v.passes,
                    }
                    for k, v in verifications.items()
                },
                "chaos": {
                    k: {
                        "fragility": v.fragility,
                        "avg_severity": v.avg_severity,
                        "rollback_failure_rate": v.rollback_failure_rate,
                        "probes": [
                            {
                                "target_id": p.target_id,
                                "blocked_downstream": p.blocked_downstream,
                                "rollback_holds": p.rollback_holds,
                                "rollback_failure_reason": p.rollback_failure_reason,
                                "severity": p.severity,
                                "recovery_path": p.recovery_path,
                            }
                            for p in v.probes
                        ],
                    }
                    for k, v in chaos_results.items()
                },
                "scores": scores,
                "recommendation": {"winner": winner, "rationale": rationale},
            },
            indent=2,
        )
    )
    print(f"[done] wrote {written} and {json_path}", file=sys.stderr)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Pareto-frontier rollout plans with formal verification + chaos probing."
    )
    parser.add_argument("intent", type=Path)
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    if args.out is None:
        args.out = Path("verified-rollout/reports") / f"{args.intent.stem}.md"
    run(args.intent, samples=args.samples, out_path=args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
