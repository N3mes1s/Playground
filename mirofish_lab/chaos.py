"""Counterfactual / chaos probe of a rollout plan.

Comprehensive failure analysis with three sampling regimes:

1. **Exhaustive single-step** -- every non-trivial step is probed once
   for "fails at its gate". This replaces the original 3-sample
   random subset.
2. **Multi-failure pairs** -- K randomly chosen step pairs probe
   simultaneous failures, surfacing failure-correlated weaknesses
   that exhaustive single-step can't see.
3. **Failure-budget curve** -- aggregate fragility computed at budgets
   B in {1, 2} concurrent failures, so the user sees how robustness
   degrades as the failure budget grows.

Plus three derived signals beyond the original fragility score:

- **Achilles-heel ranking**: per-step contribution to fragility, sorted.
  Identifies the single steps whose individual failure cascades worst.
- **Rollback-chain integrity**: distinct from cascade fragility. Counts
  probes where the Chaos agent reports the rollback path itself broke.
- **Recovery taxonomy**: bucketed across 'redo full', 'manual ops',
  'recoverable in window', 'unrecoverable'.

References:
  - Counterfactual Simulation Training, arXiv 2602.20710
  - Chaos Engineering for LLM-MAS, arXiv 2505.03096
  - LLM-Powered Fully Automated Chaos Engineering, arXiv 2511.07865
  - OWASP ASI 2026 framework (agent-specific risk taxonomy)
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
        "Given the plan and one or more target steps that 'fail at their gates' "
        "simultaneously, predict the cascade: which downstream steps are "
        "blocked, whether the rollback chain successfully restores prior "
        "state, whether the plan can recover within the same window without "
        "a complete redo, and how you would categorise the recovery effort.\n\n"
        "Output ONLY a JSON object (wrap in ```json fence):\n"
        "{\n"
        '  "blocked_downstream": ["S3","S4",...],\n'
        '  "rollback_holds": true|false,\n'
        '  "rollback_failure_reason": "..." (empty if rollback_holds),\n'
        '  "recovery_path": "describe how to recover or empty if not possible",\n'
        '  "recovery_class": "redo_full" | "manual_ops" | "recoverable_in_window" | "unrecoverable",\n'
        '  "severity": "low" | "medium" | "high" | "critical"\n'
        "}\n\n"
        "Be concrete: cite the actual step IDs and gate types from the plan. "
        "Do not invent steps that aren't in the plan. When multiple steps "
        "fail simultaneously, blocked_downstream should be the UNION of what "
        "each failure blocks, deduped."
    ),
)


@dataclass
class CascadeProbe:
    target_ids: list[str]            # one for single-failure, two+ for multi
    target_actions: list[str]
    failure_type: str                # "gate_violation" | "rollback_failure" | "owner_unavailable"
    blocked_downstream: list[str]
    rollback_holds: bool
    rollback_failure_reason: str
    recovery_path: str
    recovery_class: str
    severity: str


@dataclass
class FragilityCurve:
    """fragility(k) for k in {1,2,...} concurrent failures."""
    points: dict[int, float] = field(default_factory=dict)


@dataclass
class ChaosResult:
    plan_id: str
    probes: list[CascadeProbe] = field(default_factory=list)
    fragility: float = 0.0
    fragility_curve: FragilityCurve = field(default_factory=FragilityCurve)
    avg_severity: float = 0.0
    rollback_failure_rate: float = 0.0
    achilles_heel: list[tuple[str, float]] = field(default_factory=list)
    recovery_distribution: dict[str, int] = field(default_factory=dict)


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


def _step_metadata(plan: dict) -> tuple[dict[str, dict], dict[str, int], dict[str, set[str]]]:
    steps = plan.get("steps") or []
    by_id = {s.get("id"): s for s in steps if isinstance(s, dict) and s.get("id")}
    incoming = {sid: 0 for sid in by_id}
    for s in by_id.values():
        for d in s.get("depends_on") or []:
            if d in by_id:
                incoming[s["id"]] = incoming.get(s["id"], 0) + 1
    downstream = {sid: _downstream_set(plan, sid) for sid in by_id}
    return by_id, incoming, downstream


def _exhaustive_single_targets(plan: dict, *, max_targets: int) -> list[dict]:
    """Every step that has at least one descendant is a candidate. Capped."""
    by_id, _incoming, downstream = _step_metadata(plan)
    cands = [s for sid, s in by_id.items() if downstream[sid]]
    if not cands:
        cands = list(by_id.values())
    return cands[:max_targets]


def _multi_failure_targets(
    plan: dict, *, k_pairs: int, seed: int
) -> list[tuple[dict, dict]]:
    """Sample k random PAIRS of mid-graph steps for simultaneous-failure probes."""
    by_id, incoming, downstream = _step_metadata(plan)
    mids = [s for sid, s in by_id.items() if incoming[sid] >= 1 and downstream[sid]]
    if len(mids) < 2:
        return []
    rng = random.Random(seed)
    pairs: list[tuple[dict, dict]] = []
    seen: set[tuple[str, str]] = set()
    while len(pairs) < k_pairs and len(seen) < len(mids) * (len(mids) - 1) // 2:
        a, b = rng.sample(mids, 2)
        key = tuple(sorted([a["id"], b["id"]]))
        if key in seen:
            continue
        seen.add(key)
        pairs.append((a, b))
    return pairs


def _parse_probe(raw: object, target_ids: list[str], target_actions: list[str], failure_type: str) -> CascadeProbe:
    if not isinstance(raw, dict):
        raw = {}
    return CascadeProbe(
        target_ids=target_ids,
        target_actions=target_actions,
        failure_type=failure_type,
        blocked_downstream=[str(x) for x in (raw.get("blocked_downstream") or []) if x],
        rollback_holds=bool(raw.get("rollback_holds", False)),
        rollback_failure_reason=str(raw.get("rollback_failure_reason", "")).strip(),
        recovery_path=str(raw.get("recovery_path", "")).strip(),
        recovery_class=str(raw.get("recovery_class", "manual_ops")).lower().strip(),
        severity=str(raw.get("severity", "medium")).lower().strip(),
    )


def _scenario_prompt(intent: str, plan_json: str, targets: list[dict], failure_type: str) -> str:
    if failure_type == "gate_violation":
        scenario = "fail at their gates simultaneously" if len(targets) > 1 else "fails at its gate"
    elif failure_type == "rollback_failure":
        scenario = "fail and their rollback step also fails to restore prior state"
    elif failure_type == "owner_unavailable":
        scenario = "the owners are unavailable when the gate fires (e.g. on-call out)"
    else:
        scenario = "fail"
    targets_md = "\n".join(
        f"- `{t.get('id','?')}`: {t.get('action','')} (gate `{t.get('gate','')}`)"
        for t in targets
    )
    return (
        f"# Migration intent\n\n{intent.strip()}\n\n"
        f"# Plan under test\n\n```json\n{plan_json}\n```\n\n"
        f"# Failure scenario ({failure_type})\n\n"
        f"The following step(s) {scenario}:\n\n{targets_md}\n\n"
        f"Predict the cascade per your schema."
    )


def chaos_probe(
    plan: dict,
    *,
    cfg: Config,
    plan_id: str,
    intent: str,
    n_samples: int = 0,                # 0 means exhaustive single-step
    multi_failure_pairs: int = 3,
    extra_failure_types: tuple[str, ...] = ("rollback_failure",),
    seed: int = 1337,
) -> ChaosResult:
    """Comprehensive chaos probing.

    n_samples=0 -> exhaustive single-step probes (one per non-leaf step)
    multi_failure_pairs -> additional simultaneous-failure pair probes
    extra_failure_types -> per-step probes for each failure_type beyond
                           gate_violation. Each adds N more LLM calls.
    """
    by_id, _incoming, downstream = _step_metadata(plan)
    if not by_id:
        return ChaosResult(plan_id=plan_id)

    plan_json = json.dumps(plan, indent=2)
    chaos_agent = Agent(CHAOS_PERSONA, cfg)

    # Decide single-step targets.
    if n_samples == 0:
        single_targets = _exhaustive_single_targets(plan, max_targets=12)
    else:
        random.seed(f"{plan_id}:{seed}")
        cands = list(by_id.values())
        random.shuffle(cands)
        single_targets = cands[:n_samples]

    pair_targets = _multi_failure_targets(
        plan, k_pairs=multi_failure_pairs, seed=hash((plan_id, seed)) & 0xFFFF
    )

    probes: list[CascadeProbe] = []
    fragility_per_budget: dict[int, list[float]] = {1: [], 2: []}
    severity_nums: list[int] = []
    rollback_fails = 0
    recovery_dist: dict[str, int] = {}
    per_step_fragility: dict[str, list[float]] = {}

    def _record(targets: list[dict], failure_type: str, budget: int) -> None:
        nonlocal rollback_fails
        prompt = _scenario_prompt(intent, plan_json, targets, failure_type)
        resp = chaos_agent.respond(prompt)
        parsed = extract_json(resp.content) or {}
        probe = _parse_probe(
            parsed,
            target_ids=[t.get("id", "?") for t in targets],
            target_actions=[t.get("action", "") for t in targets],
            failure_type=failure_type,
        )
        probes.append(probe)

        # Cascade size relative to UNION of downstream sets.
        union_downstream: set[str] = set()
        for t in targets:
            union_downstream |= downstream.get(t.get("id"), set())
        if union_downstream:
            blocked_in_downstream = len(set(probe.blocked_downstream) & union_downstream)
            score = blocked_in_downstream / len(union_downstream)
            fragility_per_budget[budget].append(score)
            for t in targets:
                per_step_fragility.setdefault(t.get("id", "?"), []).append(score)
        severity_nums.append(_SEVERITY_NUM.get(probe.severity, 2))
        if not probe.rollback_holds:
            rollback_fails += 1
        rc = probe.recovery_class or "manual_ops"
        recovery_dist[rc] = recovery_dist.get(rc, 0) + 1

    # Single-step gate violations (the original failure mode).
    for t in single_targets:
        _record([t], failure_type="gate_violation", budget=1)

    # Extra failure types per step (subset of single_targets to cap cost).
    extra_targets = single_targets[: max(2, len(single_targets) // 3)]
    for ft in extra_failure_types:
        for t in extra_targets:
            _record([t], failure_type=ft, budget=1)

    # Multi-failure pairs.
    for a, b in pair_targets:
        _record([a, b], failure_type="gate_violation", budget=2)

    # Aggregate metrics.
    def _mean(xs: list[float]) -> float:
        return sum(xs) / len(xs) if xs else 0.0

    fragility = _mean(fragility_per_budget[1] + fragility_per_budget[2])
    curve = FragilityCurve(points={k: round(_mean(v), 3) for k, v in fragility_per_budget.items() if v})

    achilles = sorted(
        ((sid, round(_mean(scores), 3)) for sid, scores in per_step_fragility.items()),
        key=lambda kv: kv[1],
        reverse=True,
    )

    return ChaosResult(
        plan_id=plan_id,
        probes=probes,
        fragility=round(fragility, 3),
        fragility_curve=curve,
        avg_severity=round(_mean([float(x) for x in severity_nums]), 2),
        rollback_failure_rate=round(rollback_fails / max(1, len(probes)), 3),
        achilles_heel=achilles[:5],
        recovery_distribution=recovery_dist,
    )
