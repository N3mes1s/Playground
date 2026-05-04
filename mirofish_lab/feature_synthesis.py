"""Decomposed multi-stage synthesis for feature plans.

Replaces the single "produce-the-whole-plan" LLM call in cli_feature
with four focused stages. Built after the cycle-2 retrospective showed
that prompt-only optimization on a single call has saturated (the
schema-level strategy_reasoning fix passed n=12+12 holdout but was
-27pp useful_rate at N=48 because the LLM ran out of output budget).

Architecture:
  Stage 1 — Strategy decision (1 LLM call, shared across variants)
  Stage 2 — Step decomposition (1 LLM call per sequencer variant)
  Stage 3 — Stakeholder verification (6 personas in parallel per variant)
  Stage 4 — Finalise under feedback (1 LLM call per variant)

Total: 1 + 3 + 18 + 3 = 25 LLM calls per run (plus existing 6 for
constraint gathering = 31 total). ~$0.30/run on gpt-5.4-mini.

Reused patterns (do not re-implement):
  - mirofish_lab/agent.py:Agent.respond — single-shot LLM call
  - mirofish_lab/simulation.py:parallel_run — fan-out for Stage 3
  - mirofish_lab/chaos_hardener.py:harden_plan (lines 170-229) — the
    closed-loop "render previous output + critique → call LLM with
    both → re-parse fixed-shape JSON" pattern that Stage 4 follows
  - mirofish_lab/rollout.py:extract_json — JSON extraction with
    fenced-block fallback

Data contract preserved: Stage 4 output dict has all 10 keys that
downstream consumers (verify_smt, timeline_chaos, score_feature_plan,
cli_feature renderer) read. See _validate_final_plan in
feature_planning.py.
"""

from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

from mirofish_lab.agent import Agent
from mirofish_lab.feature_planning import (
    FEATURE_SEQUENCERS,
    FEATURE_STAKEHOLDER_PERSONAS,
    FeatureConstraint,
)
from mirofish_lab.personas import Persona
from mirofish_lab.rollout import extract_json
from mirofish_lab.simulation import parallel_run


# --- dataclasses ----------------------------------------------------------


@dataclass
class StrategyDecision:
    launch_strategy: str  # feature_flag | gradual_rollout | dark_launch | beta_program | full_release
    strategy_reasoning: str
    beta_program_needed: bool
    regulated_path_required: bool
    raw: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "launch_strategy": self.launch_strategy,
            "strategy_reasoning": self.strategy_reasoning,
            "beta_program_needed": self.beta_program_needed,
            "regulated_path_required": self.regulated_path_required,
        }


@dataclass
class PersonaFlag:
    owner: str
    step_id: str  # may be "" if the flag is plan-level
    flag_type: str  # blocker | missing | wrong_strategy | slip_risk | other
    issue: str
    suggested_change: str

    def as_dict(self) -> dict:
        return {
            "owner": self.owner,
            "step_id": self.step_id,
            "flag_type": self.flag_type,
            "issue": self.issue,
            "suggested_change": self.suggested_change,
        }


# --- Stage 1: Strategy decider --------------------------------------------


_STRATEGY_DECIDER_SYSTEM = (
    "You are a launch-strategy decider for a feature-shipping pipeline. "
    "Given an intent and merged stakeholder constraints, you pick ONE "
    "launch strategy and explain why. You output ONLY a JSON object "
    "wrapped in a ```json fenced block.\n\n"
    "Strategies:\n"
    "  - feature_flag: additive backend/API behind an admin toggle\n"
    "  - gradual_rollout: ramp by % of users with monitoring\n"
    "  - dark_launch: ship code path, no user exposure\n"
    "  - beta_program: closed cohort with feedback loop, then GA\n"
    "  - full_release: ship to 100% at once\n\n"
    "Anchor heuristics (apply firmly):\n"
    "  - regulated / compliance / audit features whose acceptance "
    "requires FULL coverage → full_release (partial rollout leaves "
    "audit scope ambiguous).\n"
    "  - mobile parity / new UX surfaces / risky cross-stakeholder "
    "change → beta_program first, then gradual_rollout.\n"
    "  - additive backend / API behind admin toggle → feature_flag.\n"
    "  - pure backend instrumentation with no user-visible change → "
    "dark_launch.\n"
    "  - if two heuristics conflict, pick the SAFER strategy and say "
    "so in strategy_reasoning.\n\n"
    "Output schema:\n"
    "{\n"
    '  "launch_strategy": "feature_flag|gradual_rollout|dark_launch|beta_program|full_release",\n'
    '  "strategy_reasoning": "<= 240 chars. Cite the feature kind, '
    "regulated/non-regulated, the failure mode you're guarding against, "
    "OR the stakeholder constraint that drove the pick. Saying "
    '\\\"feature_flag because feature flag\\\" is INVALID.",\n'
    '  "beta_program_needed": true|false,\n'
    '  "regulated_path_required": true|false\n'
    "}"
)


STRATEGY_DECIDER = Persona(
    name="StrategyDecider",
    role="launch-strategy decider",
    system_prompt=_STRATEGY_DECIDER_SYSTEM,
)


def _run_stage_1_strategy(
    intent: str,
    constraints: list[FeatureConstraint],
    cfg,
) -> StrategyDecision:
    constraints_json = json.dumps([c.raw for c in constraints], indent=2)
    prompt = (
        "# Feature intent\n\n"
        f"{intent.strip()}\n\n"
        f"# Stakeholder constraints (merged)\n\n```json\n{constraints_json}\n```\n\n"
        "Pick the launch_strategy and output the JSON per your schema."
    )
    agent = Agent(STRATEGY_DECIDER, cfg)
    resp = agent.respond(prompt)
    parsed = extract_json(resp.content) or {}
    if not isinstance(parsed, dict):
        parsed = {}
    strategy = str(parsed.get("launch_strategy", "feature_flag")).strip().lower()
    valid = {"feature_flag", "gradual_rollout", "dark_launch",
             "beta_program", "full_release"}
    if strategy not in valid:
        strategy = "feature_flag"
    return StrategyDecision(
        launch_strategy=strategy,
        strategy_reasoning=str(parsed.get("strategy_reasoning", ""))[:300],
        beta_program_needed=bool(parsed.get("beta_program_needed", False)),
        regulated_path_required=bool(parsed.get("regulated_path_required", False)),
        raw=parsed,
    )


# --- Stage 2: Step decomposition (per variant) ----------------------------


def _strategy_brief_for_prompt(strategy: StrategyDecision) -> str:
    return (
        "# Stage-1 strategy decision (already made; do NOT re-decide)\n\n"
        f"- launch_strategy: **{strategy.launch_strategy}**\n"
        f"- strategy_reasoning: {strategy.strategy_reasoning}\n"
        f"- beta_program_needed: {strategy.beta_program_needed}\n"
        f"- regulated_path_required: {strategy.regulated_path_required}\n\n"
        "Honour this strategy in every step's `launch_strategy` field. "
        "If a step is internal-only (spec, sign-off, internal review) "
        "use `not_applicable`.\n"
    )


def _run_stage_2_decompose(
    intent: str,
    constraints: list[FeatureConstraint],
    strategy: StrategyDecision,
    sequencer_persona: Persona,
    cfg,
) -> dict:
    constraints_json = json.dumps([c.raw for c in constraints], indent=2)
    prompt = (
        f"# Feature intent\n\n{intent.strip()}\n\n"
        f"# Stakeholder constraints (merged)\n\n```json\n{constraints_json}\n```\n\n"
        + _strategy_brief_for_prompt(strategy)
        + "\nProduce the feature plan as JSON per your schema."
    )
    agent = Agent(sequencer_persona, cfg)
    resp = agent.respond(prompt)
    plan = extract_json(resp.content) or {}
    if isinstance(plan, list):
        plan = {"summary": "", "steps": plan,
                "open_questions": [], "conflicts": []}
    if not isinstance(plan, dict):
        plan = {"summary": "", "steps": [],
                "open_questions": [], "conflicts": []}
    return plan


# --- Stage 3: Stakeholder verification (parallel review) ------------------


_REVIEWER_PROMPT_TEMPLATE = """\
You are reviewing a draft feature plan as your stakeholder persona.
Find concrete issues IN YOUR AXIS — do not speak for other personas.

# Feature intent

{intent}

# Stakeholder constraints (merged)

```json
{constraints_json}
```

# Stage-1 strategy decision (already final)

- launch_strategy: {strategy_label}
- reasoning: {strategy_reasoning}

# DRAFT PLAN to review

```json
{draft_json}
```

Output ONLY a JSON array of flag objects (wrap in a ```json fence). \
Each flag is:

{{
  "step_id": "<step id this flag points at, or empty for plan-level>",
  "flag_type": "blocker|missing|wrong_strategy|slip_risk|other",
  "issue": "<= 160 chars: concrete problem in YOUR axis",
  "suggested_change": "<= 160 chars: what should change. Be specific."
}}

Rules:
- ONLY flag issues in your axis. If a step is fine in your axis, skip it.
- Be specific about WHICH step. "S3 misses our security review" is good;
  "more security needed" is bad.
- If everything looks fine in your axis, output [].
- Wrap the JSON ARRAY in a ```json fenced block.
"""


def _run_stage_3_review(
    draft: dict,
    intent: str,
    constraints: list[FeatureConstraint],
    strategy: StrategyDecision,
    cfg,
) -> list[PersonaFlag]:
    constraints_json = json.dumps([c.raw for c in constraints], indent=2)
    draft_json = json.dumps(draft, indent=2)[:6000]
    prompt = _REVIEWER_PROMPT_TEMPLATE.format(
        intent=intent.strip()[:3000],
        constraints_json=constraints_json,
        strategy_label=strategy.launch_strategy,
        strategy_reasoning=strategy.strategy_reasoning,
        draft_json=draft_json,
    )
    agents = [Agent(p, cfg) for p in FEATURE_STAKEHOLDER_PERSONAS]
    responses = parallel_run(agents, prompt, max_workers=6)
    flags: list[PersonaFlag] = []
    for r in responses:
        parsed = extract_json(r.content)
        if not isinstance(parsed, list):
            continue
        for item in parsed:
            if not isinstance(item, dict):
                continue
            issue = str(item.get("issue", "")).strip()
            if not issue:
                continue
            flags.append(PersonaFlag(
                owner=r.agent_name,
                step_id=str(item.get("step_id", "")).strip(),
                flag_type=str(item.get("flag_type", "other")).strip().lower(),
                issue=issue[:300],
                suggested_change=str(item.get("suggested_change", "")).strip()[:300],
            ))
    return flags


# --- Stage 4: Finalise under feedback (per variant) -----------------------


def _render_flags(flags: list[PersonaFlag]) -> str:
    if not flags:
        return "_(no review flags raised — plan can ship as-is)_"
    lines = ["| Owner | Step | Type | Issue | Suggested change |",
             "|---|---|---|---|---|"]
    for f in flags:
        lines.append(
            f"| {f.owner} | {f.step_id or '-'} | {f.flag_type} | "
            f"{f.issue} | {f.suggested_change} |"
        )
    return "\n".join(lines)


def _run_stage_4_finalise(
    draft: dict,
    flags: list[PersonaFlag],
    sequencer_persona: Persona,
    intent: str,
    constraints: list[FeatureConstraint],
    strategy: StrategyDecision,
    cfg,
) -> tuple[dict, list[str]]:
    """Returns (final_plan, changed_keys). Falls back to draft on
    parse/validate failure."""
    constraints_json = json.dumps([c.raw for c in constraints], indent=2)
    draft_json = json.dumps(draft, indent=2)[:6000]
    flags_md = _render_flags(flags)
    prompt = (
        f"# Feature intent\n\n{intent.strip()[:3000]}\n\n"
        f"# Stakeholder constraints (merged)\n\n```json\n{constraints_json}\n```\n\n"
        + _strategy_brief_for_prompt(strategy)
        + f"\n# Your DRAFT plan\n\n```json\n{draft_json}\n```\n\n"
        f"# Persona review flags\n\n{flags_md}\n\n"
        "Produce the FINAL plan as JSON per your schema. Address each "
        "blocker / wrong_strategy / slip_risk flag concretely. You may "
        "add steps, edit step actions, change owners, adjust depends_on, "
        "or update success_criterion / definition_of_done — but the "
        "launch_strategy MUST match the Stage-1 decision (or "
        "`not_applicable` for internal steps). Do NOT regress the DAG: "
        "every depends_on must reference an earlier step id.\n\n"
        "Output the same shape as your draft (full JSON object with "
        "summary, steps, open_questions, conflicts). Wrap in a ```json "
        "fenced block."
    )
    agent = Agent(sequencer_persona, cfg)
    resp = agent.respond(prompt)
    parsed = extract_json(resp.content)
    # Lazy import to avoid circular dependency at module load
    from mirofish_lab.feature_planning import _validate_final_plan
    if isinstance(parsed, dict) and _validate_final_plan(parsed):
        changed = _diff_changed_keys(draft, parsed)
        return parsed, changed
    # Fallback: return draft (degrade gracefully)
    return draft, ["__fallback_to_draft__"]


def _diff_changed_keys(draft: dict, final: dict) -> list[str]:
    """Best-effort list of which step keys differ between draft and final."""
    out: list[str] = []
    draft_steps = {s.get("id"): s for s in (draft.get("steps") or [])
                   if isinstance(s, dict) and s.get("id")}
    final_steps = {s.get("id"): s for s in (final.get("steps") or [])
                   if isinstance(s, dict) and s.get("id")}
    added = set(final_steps) - set(draft_steps)
    removed = set(draft_steps) - set(final_steps)
    for sid in added:
        out.append(f"+{sid}")
    for sid in removed:
        out.append(f"-{sid}")
    for sid in set(final_steps) & set(draft_steps):
        for k in ("action", "owner", "depends_on", "launch_strategy",
                  "estimated_days"):
            if draft_steps[sid].get(k) != final_steps[sid].get(k):
                out.append(f"{sid}.{k}")
    return out


# --- Orchestrator ---------------------------------------------------------


@dataclass
class SynthesisResult:
    strategy: StrategyDecision
    plans: dict[str, dict]                  # label -> final plan
    drafts: dict[str, dict]                  # label -> Stage-2 draft
    flags: dict[str, list[PersonaFlag]]      # label -> Stage-3 flags
    changed_keys: dict[str, list[str]]       # label -> Stage-4 diff list

    def as_audit_dict(self) -> dict:
        return {
            "strategy_decision": self.strategy.as_dict(),
            "drafts": self.drafts,
            "review_flags": {
                label: [f.as_dict() for f in flag_list]
                for label, flag_list in self.flags.items()
            },
            "finalised_changed_keys": self.changed_keys,
        }


def synthesize_all(
    intent: str,
    constraints: list[FeatureConstraint],
    cfg,
) -> SynthesisResult:
    """Run the full 4-stage pipeline and return final plans + audit data.

    Stage 1 runs once (shared). Stages 2+3+4 fan out across the 3
    sequencer variants in parallel.
    """
    print("[stage 1] strategy decision (shared)", file=sys.stderr)
    strategy = _run_stage_1_strategy(intent, constraints, cfg)
    print(f"[stage 1]   strategy={strategy.launch_strategy} "
          f"regulated={strategy.regulated_path_required}",
          file=sys.stderr)

    def _per_variant(label: str, persona: Persona) -> tuple[str, dict, dict, list[PersonaFlag], list[str]]:
        print(f"[{label}] stage 2 decompose", file=sys.stderr)
        draft = _run_stage_2_decompose(intent, constraints, strategy, persona, cfg)
        print(f"[{label}] stage 3 review (6 personas in parallel)", file=sys.stderr)
        flags = _run_stage_3_review(draft, intent, constraints, strategy, cfg)
        print(f"[{label}] stage 3   {len(flags)} flags raised", file=sys.stderr)
        print(f"[{label}] stage 4 finalise", file=sys.stderr)
        final, changed = _run_stage_4_finalise(
            draft, flags, persona, intent, constraints, strategy, cfg,
        )
        return label, draft, final, flags, changed

    plans: dict[str, dict] = {}
    drafts: dict[str, dict] = {}
    flags_by_label: dict[str, list[PersonaFlag]] = {}
    changed_keys: dict[str, list[str]] = {}

    with ThreadPoolExecutor(max_workers=3) as pool:
        futs = [pool.submit(_per_variant, label, p)
                for label, p in FEATURE_SEQUENCERS.items()]
        for fut in as_completed(futs):
            label, draft, final, flags, changed = fut.result()
            plans[label] = final
            drafts[label] = draft
            flags_by_label[label] = flags
            changed_keys[label] = changed

    # Stable label order matches FEATURE_SEQUENCERS dict order
    ordered = list(FEATURE_SEQUENCERS.keys())
    plans = {l: plans[l] for l in ordered if l in plans}
    drafts = {l: drafts[l] for l in ordered if l in drafts}
    flags_by_label = {l: flags_by_label[l] for l in ordered if l in flags_by_label}
    changed_keys = {l: changed_keys[l] for l in ordered if l in changed_keys}

    return SynthesisResult(
        strategy=strategy,
        plans=plans,
        drafts=drafts,
        flags=flags_by_label,
        changed_keys=changed_keys,
    )
