"""Counterfactual / chaos probe of a rollout plan.

For each plan, the Chaos agent receives the plan plus a target step
that "fails at its gate" and predicts the cascade: which downstream
steps are blocked, whether the rollback chain holds, and whether the
plan can recover within the same window.

We sample N non-rollback steps per plan and aggregate the cascade
predictions into a fragility score:

  fragility = avg over samples of (downstream_blocked_count / total_downstream)

A plan with high fragility is one where a single mid-stage failure
cascades to most of the remainder. This is the Counterfactual
Simulation Training (arXiv 2602.20710) angle applied to engineering
rollout plans rather than chain-of-thought traces.
"""

from __future__ import annotations

import json
import random
import re
from dataclasses import dataclass, field

from mirofish_lab.agent import Agent
from mirofish_lab.config import Config
from mirofish_lab.personas import Persona
from mirofish_lab.rollout import extract_json


CHAOS_PERSONA = Persona(
    name="ChaosEngineer",
    role="rollout failure-mode analyst",
    system_prompt=(
        "You are a chaos engineer evaluating a rollout plan's robustness. "
        "Given the plan and a target step that fails at its gate, predict "
        "the cascade: which downstream steps are blocked, whether the "
        "rollback chain successfully restores prior state, and whether the "
        "plan can recover within the same window without a complete redo.\n\n"
        "Output ONLY a JSON object (wrap in ```json fence):\n"
        "{\n"
        '  "blocked_downstream": ["S3","S4",...],\n'
        '  "rollback_holds": true|false,\n'
        '  "rollback_failure_reason": "..." (empty if rollback_holds),\n'
        '  "recovery_path": "describe how to recover or empty if not possible",\n'
        '  "severity": "low" | "medium" | "high" | "critical"\n'
        "}\n\n"
        "Be concrete: cite the actual step IDs and gate types from the plan. "
        "Do not invent steps that aren't in the plan."
    ),
)


@dataclass
class CascadeProbe:
    target_id: str
    target_action: str
    blocked_downstream: list[str]
    rollback_holds: bool
    rollback_failure_reason: str
    recovery_path: str
    severity: str


@dataclass
class ChaosResult:
    plan_id: str
    probes: list[CascadeProbe] = field(default_factory=list)
    fragility: float = 0.0
    avg_severity: float = 0.0
    rollback_failure_rate: float = 0.0


_SEVERITY_NUM = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _downstream_set(plan: dict, start_id: str) -> set[str]:
    steps = plan.get("steps") or []
    by_id = {s.get("id"): s for s in steps if isinstance(s, dict)}
    children: dict[str, list[str]] = {}
    for s in steps:
        if not isinstance(s, dict):
            continue
        for d in (s.get("depends_on") or []):
            children.setdefault(d, []).append(s.get("id"))
    out: set[str] = set()
    stack = [start_id]
    while stack:
        n = stack.pop()
        for c in children.get(n, ()):
            if c and c not in out:
                out.add(c)
                stack.append(c)
    return out


def _sample_targets(plan: dict, n: int) -> list[dict]:
    steps = plan.get("steps") or []
    # Avoid trivial roots and trivial leaves; prefer mid-graph steps.
    by_id = {s.get("id"): s for s in steps if isinstance(s, dict)}
    incoming = {sid: 0 for sid in by_id}
    for s in steps:
        if not isinstance(s, dict):
            continue
        for d in (s.get("depends_on") or []):
            if d in by_id:
                incoming[s.get("id")] = incoming.get(s.get("id"), 0) + 1
    candidates = [
        s for s in steps
        if isinstance(s, dict)
        and incoming.get(s.get("id"), 0) >= 1
        and len(_downstream_set(plan, s.get("id"))) >= 1
    ]
    if len(candidates) < n:
        candidates = [s for s in steps if isinstance(s, dict)]
    random.shuffle(candidates)
    return candidates[:n]


def _parse_probe(raw: object, target_id: str, target_action: str) -> CascadeProbe:
    if not isinstance(raw, dict):
        raw = {}
    return CascadeProbe(
        target_id=target_id,
        target_action=target_action,
        blocked_downstream=[
            str(x) for x in (raw.get("blocked_downstream") or []) if x
        ],
        rollback_holds=bool(raw.get("rollback_holds", False)),
        rollback_failure_reason=str(raw.get("rollback_failure_reason", "")).strip(),
        recovery_path=str(raw.get("recovery_path", "")).strip(),
        severity=str(raw.get("severity", "medium")).lower().strip(),
    )


def chaos_probe(
    plan: dict,
    *,
    cfg: Config,
    plan_id: str,
    intent: str,
    n_samples: int = 3,
    seed: int = 1337,
) -> ChaosResult:
    random.seed(f"{plan_id}:{seed}")
    targets = _sample_targets(plan, n_samples)
    if not targets:
        return ChaosResult(plan_id=plan_id)

    chaos_agent = Agent(CHAOS_PERSONA, cfg)
    probes: list[CascadeProbe] = []
    cumulative_fragility: list[float] = []
    severity_nums: list[int] = []
    rollback_fails = 0

    plan_json = json.dumps(plan, indent=2)

    for t in targets:
        tid = t.get("id", "?")
        all_downstream = _downstream_set(plan, tid)
        prompt = (
            f"# Migration intent\n\n{intent.strip()}\n\n"
            f"# Plan under test\n\n```json\n{plan_json}\n```\n\n"
            f"# Failure scenario\n\n"
            f"Step `{tid}` ({t.get('action','')}) fails at its gate "
            f"(`{t.get('gate','')}`). Predict the cascade per your schema."
        )
        resp = chaos_agent.respond(prompt)
        parsed = extract_json(resp.content) or {}
        probe = _parse_probe(parsed, tid, t.get("action", ""))
        probes.append(probe)

        # Fragility for this sample = how much of the downstream is blocked.
        if all_downstream:
            blocked_in_downstream = len(
                set(probe.blocked_downstream) & all_downstream
            )
            cumulative_fragility.append(blocked_in_downstream / len(all_downstream))
        severity_nums.append(_SEVERITY_NUM.get(probe.severity, 2))
        if not probe.rollback_holds:
            rollback_fails += 1

    fragility = (
        sum(cumulative_fragility) / len(cumulative_fragility)
        if cumulative_fragility else 0.0
    )
    avg_sev = (
        sum(severity_nums) / len(severity_nums) if severity_nums else 0.0
    )

    return ChaosResult(
        plan_id=plan_id,
        probes=probes,
        fragility=round(fragility, 3),
        avg_severity=round(avg_sev, 2),
        rollback_failure_rate=round(rollback_fails / max(1, len(probes)), 3),
    )
