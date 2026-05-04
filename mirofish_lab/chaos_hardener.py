"""Closed-loop plan hardener.

Given a plan that the chaos analyses flagged as fragile, the Hardener
agent proposes a NEW plan (same intent, same constraint set) targeted
at fixing the specific fragility findings:

  - Achilles-heel single-step failure cascades:
      hint = "split S<id> into multiple checkpointed sub-steps so a
      single failure does not cascade to all downstream"
  - High-rollback-failure-rate steps:
      hint = "tighten rollback for S<id> to a concrete inverse, not
      'redeploy_previous'"
  - Approval-heavy steps with high MC failure rate:
      hint = "consider replacing approval:vague with monitor:explicit"
  - Worst-K failure combinations:
      hint = "add a redundant path so failure of {S2, S5} does not
      block all downstream"

The Hardener returns a complete replacement plan (JSON), which we then
re-verify with chaos_static and Z3 SMT. We compute fragility_before vs
fragility_after to measure improvement, and check Z3 still proves the
plan feasible.

The loop in cli_harden.py runs:
   plan -> chaos -> harden -> chaos -> harden -> ... until threshold met
   or max iterations reached.

Reference: analogous to closed-loop self-improvement in code-agent
work (Cursor's plan-revise-replan loop), specialised to *plan
robustness* rather than implementation correctness.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from mirofish_lab.agent import Agent
from mirofish_lab.chaos_static import (
    AchillesEntry,
    StaticChaosResult,
    static_chaos_summary,
)
from mirofish_lab.config import Config
from mirofish_lab.personas import Persona
from mirofish_lab.rollout import extract_json


HARDENER_PERSONA = Persona(
    name="PlanHardener",
    role="rollout plan hardener",
    system_prompt=(
        "You receive a rollout plan that chaos analysis flagged as fragile, "
        "plus the specific fragility findings (Achilles-heel steps, worst-K "
        "failure combinations, high-rollback-failure steps, high-MC-failure "
        "steps). Produce a NEW plan -- same intent, same merged stakeholder "
        "constraints -- that targets the fragility findings.\n\n"
        "Output ONLY a JSON object (wrap in ```json fenced block) with the "
        "same shape as the input plan:\n\n"
        "{\n"
        '  "summary": "<= 200 chars, what the rollout achieves",\n'
        '  "steps": [\n'
        "    {\n"
        '      "id": "S1",\n'
        '      "action": "...",\n'
        '      "owner": "...",\n'
        '      "depends_on": ["..."],\n'
        '      "gate": "wait_for:... | monitor:... | approval:... | window:... | none",\n'
        '      "rollback": "concrete inverse",\n'
        '      "observability": "what to watch"\n'
        "    }\n"
        "  ],\n"
        '  "open_questions": [],\n'
        '  "conflicts": []\n'
        "}\n\n"
        "Hardening techniques you may apply:\n"
        "- **Split** an Achilles-heel step into 2-3 smaller sub-steps with "
        "  intermediate gates. The cascade size of any single failure shrinks.\n"
        "- **Add a checkpoint** (monitor:metric<threshold) after a step so "
        "  downstream steps wait for explicit health, not implicit success.\n"
        "- **Tighten a rollback**: replace 'redeploy_previous' with a "
        "  concrete inverse describing the exact restore action.\n"
        "- **Replace approval:vague with monitor:explicit** when an approval "
        "  gate is doing the work of a metric check.\n"
        "- **Add redundancy**: where two steps form an Achilles-pair, add a "
        "  parallel alternative path so the worst-K failure no longer blocks "
        "  all downstream.\n"
        "- **Re-order**: pull a low-risk step earlier or push a high-risk "
        "  step later so the cascade structure is favourable.\n"
        "- **Move dependencies**: weaken a chain by breaking depends_on into "
        "  an alternative path where it is safe to do so.\n\n"
        "Rules:\n"
        "- Honour the original constraints (do NOT drop blocking gates the "
        "  stakeholders required).\n"
        "- Step IDs may be renumbered, but every dependency must point at a "
        "  step that exists in the new plan.\n"
        "- Every step must still have a rollback.\n"
        "- Do not expand the step count by more than ~50% (don't bloat for "
        "  the sake of safety; targeted edits only).\n"
        "- If you make no change to a step, keep it byte-identical."
    ),
)


@dataclass
class HardenResult:
    iteration: int
    plan_before: dict
    plan_after: dict
    fragility_before: float
    fragility_after: float
    fragility_delta: float
    achilles_top_before: list[tuple[str, ...]] = field(default_factory=list)
    achilles_top_after: list[tuple[str, ...]] = field(default_factory=list)
    n_steps_before: int = 0
    n_steps_after: int = 0
    notes: str = ""


def _summarise_findings(
    plan: dict,
    chaos: StaticChaosResult,
    llm_probe_summary: dict | None,
    smt_findings: dict | None = None,
) -> str:
    """Render a compact text summary of fragility findings for the Hardener.

    If smt_findings indicates the plan is currently infeasible, that
    explanation is surfaced FIRST as the top-priority fix.
    """
    parts: list[str] = []
    if smt_findings and smt_findings.get("infeasible"):
        parts.append(
            "**TOP PRIORITY** — Z3 has proven the current plan INFEASIBLE. "
            "You MUST fix the ordering before improving fragility. "
            "Minimal unsat core (these orderings cannot all hold):"
        )
        for e in smt_findings.get("unsat_core_explanations", []) or []:
            parts.append(f"  - {e}")
        parts.append(
            "Resolve by reordering steps, removing one of the conflicting "
            "dependencies, or inserting an intermediate step."
        )
    parts.append(f"Plan has {chaos.n_steps} steps. Fragility curve: " +
                 ", ".join(f"k={k}={v}" for k, v in sorted(chaos.fragility_curve.items())))
    if 1 in chaos.achilles_top_per_k:
        top = chaos.achilles_top_per_k[1][:5]
        parts.append("Top single-step Achilles (structural):")
        for e in top:
            parts.append(f"  - {list(e.failure_set)} -> blocks {list(e.blocked)} "
                         f"(fragility {e.fragility})")
    if 2 in chaos.achilles_top_per_k:
        top = chaos.achilles_top_per_k[2][:3]
        parts.append("Top worst-2 simultaneous failures (structural):")
        for e in top:
            parts.append(f"  - {list(e.failure_set)} -> blocks {list(e.blocked)} "
                         f"(fragility {e.fragility})")
    if llm_probe_summary:
        rb = llm_probe_summary.get("rollback_failure_rate", 0)
        parts.append(f"LLM probe found rollback-failure rate {rb} "
                     "(fraction of probes whose rollback chain did not hold).")
        ah = llm_probe_summary.get("achilles_heel", [])
        if ah:
            parts.append("LLM-probe Achilles (top 5):")
            for sid, score in ah[:5]:
                parts.append(f"  - {sid} -> {score}")
    return "\n".join(parts)


def harden_plan(
    plan: dict,
    *,
    cfg: Config,
    plan_id: str,
    iteration: int,
    chaos: StaticChaosResult | None = None,
    llm_probe_summary: dict | None = None,
    smt_findings: dict | None = None,
) -> HardenResult:
    """Run one Hardener pass and return the new plan + fragility delta."""
    if chaos is None:
        chaos = static_chaos_summary(plan, plan_id=plan_id, budgets=(1, 2))

    findings = _summarise_findings(plan, chaos, llm_probe_summary, smt_findings)
    plan_json = json.dumps(plan, indent=2)
    prompt = (
        "# Plan to harden\n\n"
        f"```json\n{plan_json}\n```\n\n"
        "# Fragility findings\n\n"
        f"{findings}\n\n"
        "Produce the hardened plan as a JSON object per your schema."
    )

    agent = Agent(HARDENER_PERSONA, cfg)
    resp = agent.respond(prompt)
    new_plan = extract_json(resp.content) or {}
    if isinstance(new_plan, list):
        new_plan = {"summary": "", "steps": new_plan,
                    "open_questions": [], "conflicts": []}
    if not isinstance(new_plan, dict) or not new_plan.get("steps"):
        # Fallback: keep the original plan on bad output.
        new_plan = plan

    new_chaos = static_chaos_summary(
        new_plan, plan_id=f"{plan_id}_harden_iter{iteration}", budgets=(1, 2)
    )
    fragility_before = chaos.overall_fragility
    fragility_after = new_chaos.overall_fragility

    achilles_before = (
        [e.failure_set for e in chaos.achilles_top_per_k.get(1, [])[:5]]
    )
    achilles_after = (
        [e.failure_set for e in new_chaos.achilles_top_per_k.get(1, [])[:5]]
    )

    return HardenResult(
        iteration=iteration,
        plan_before=plan,
        plan_after=new_plan,
        fragility_before=round(fragility_before, 3),
        fragility_after=round(fragility_after, 3),
        fragility_delta=round(fragility_after - fragility_before, 3),
        achilles_top_before=achilles_before,
        achilles_top_after=achilles_after,
        n_steps_before=chaos.n_steps,
        n_steps_after=new_chaos.n_steps,
        notes="",
    )
