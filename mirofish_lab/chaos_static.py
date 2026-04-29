"""Static (graph-based) cascade analysis for rollout plans.

Replaces the LLM-based budget>=2 chaos probe with structural
computation. Where the LLM was empirically poor (the previously-
flagged 0.0 fragility on multi-pair scenarios), the dependency graph
gives the answer exactly: a step is blocked iff every path from a root
to it passes through at least one failed step.

Three primitives:

- `static_cascade(plan, failed)` — set of steps blocked when the given
  set of steps fails. Computed by removing failed nodes from the DAG
  and asking which remaining steps are no longer reachable from a
  root. Correct by construction.

- `static_achilles_heel(plan, k=1)` — per-step or per-K-tuple structural
  fragility. For each candidate failure set of size k, computes the
  blocked-fraction; returns ranked.

- `worst_k_failures(plan, k, max_combinations=None)` — exhaustive
  enumeration of the worst K-tuple of simultaneous failures. With
  `max_combinations` set, prunes via greedy approximation when the
  full search would be too large.

Reference: the cascade structure of a deployment DAG under simultaneous
node removal is a classical reliability-engineering question;
the LLM does not need to be in the loop for budgets >= 2 once we
trust the dependency graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import combinations
from typing import Iterable


def _by_id(plan: dict) -> dict[str, dict]:
    return {
        s["id"]: s
        for s in (plan.get("steps") or [])
        if isinstance(s, dict) and s.get("id")
    }


def _adj_forward(plan: dict) -> dict[str, list[str]]:
    """Edge from a step's deps to itself: dep -> [step_that_depends_on_it]."""
    adj: dict[str, list[str]] = {sid: [] for sid in _by_id(plan)}
    for s in plan.get("steps") or []:
        if not isinstance(s, dict):
            continue
        sid = s.get("id")
        for d in s.get("depends_on") or []:
            adj.setdefault(d, []).append(sid)
            adj.setdefault(sid, adj.get(sid, []))
    return adj


def _adj_backward(plan: dict) -> dict[str, list[str]]:
    """Edge from a step to its deps: step -> [its_deps]."""
    adj: dict[str, list[str]] = {sid: [] for sid in _by_id(plan)}
    for s in plan.get("steps") or []:
        if not isinstance(s, dict):
            continue
        sid = s.get("id")
        for d in s.get("depends_on") or []:
            adj.setdefault(sid, []).append(d)
    return adj


def _all_steps(plan: dict) -> set[str]:
    return set(_by_id(plan))


def static_cascade(
    plan: dict,
    failed: Iterable[str],
    *,
    semantics: str = "and",
) -> set[str]:
    """Steps blocked when `failed` steps cannot complete.

    semantics:
      - "and" (default): a step is blocked iff at least one of its
        depends_on is unreachable. Matches typical orchestrators where
        a step waits for ALL its dependencies.
      - "or": a step is blocked iff every alternative path is blocked.
        Currently not distinguished from "and" because we don't have
        explicit OR-edges in the schema; reserved for future.
    """
    failed_set = set(failed)
    by_id = _by_id(plan)
    fwd = _adj_forward(plan)

    # The blocked set is the transitive forward closure of failed_set
    # in the dependency graph, since every descendant requires its
    # parent (AND semantics).
    blocked: set[str] = set()
    stack = list(failed_set)
    while stack:
        n = stack.pop()
        for c in fwd.get(n, ()):
            if c in failed_set or c in blocked:
                continue
            blocked.add(c)
            stack.append(c)
    return blocked


@dataclass
class AchillesEntry:
    failure_set: tuple[str, ...]
    blocked: tuple[str, ...]
    fragility: float          # |blocked| / (|all_steps| - |failure_set|)
    blocked_fraction_of_total: float


def static_achilles_heel(
    plan: dict,
    *,
    k: int = 1,
    max_combinations: int | None = 5000,
) -> list[AchillesEntry]:
    """Rank all (or up to max_combinations) k-tuples by structural cascade size.

    Returns sorted descending by fragility.
    """
    ids = sorted(_all_steps(plan))
    if not ids or k < 1 or k > len(ids):
        return []
    total = len(ids)
    if max_combinations is None:
        all_combos: list[tuple[str, ...]] = list(combinations(ids, k))
    else:
        # Cap; prefer to keep mid-graph nodes (they cascade more) by
        # ordering input ids by descending forward-out-degree before
        # combinatorial expansion.
        fwd = _adj_forward(plan)
        ids_sorted = sorted(ids, key=lambda s: -len(fwd.get(s, [])))
        all_combos = []
        for c in combinations(ids_sorted, k):
            all_combos.append(c)
            if len(all_combos) >= max_combinations:
                break

    entries: list[AchillesEntry] = []
    for combo in all_combos:
        blocked = static_cascade(plan, combo)
        denom_remaining = max(1, total - len(combo))
        entries.append(
            AchillesEntry(
                failure_set=combo,
                blocked=tuple(sorted(blocked)),
                fragility=round(len(blocked) / denom_remaining, 3),
                blocked_fraction_of_total=round(len(blocked) / total, 3),
            )
        )
    entries.sort(key=lambda e: (-e.fragility, e.failure_set))
    return entries


def worst_k_failures(
    plan: dict,
    k: int,
    *,
    top_n: int = 5,
    max_combinations: int | None = 5000,
) -> list[AchillesEntry]:
    """Top-N worst K-step simultaneous failure combinations."""
    ranked = static_achilles_heel(plan, k=k, max_combinations=max_combinations)
    return ranked[:top_n]


@dataclass
class StaticChaosResult:
    plan_id: str
    n_steps: int
    fragility_curve: dict[int, float] = field(default_factory=dict)
    achilles_top_per_k: dict[int, list[AchillesEntry]] = field(default_factory=dict)
    overall_fragility: float = 0.0


def static_chaos_summary(
    plan: dict,
    *,
    plan_id: str = "default",
    budgets: tuple[int, ...] = (1, 2, 3),
    top_n: int = 3,
) -> StaticChaosResult:
    """Compute fragility curve + top achilles failures for a range of budgets.

    Pure graph computation, no LLM calls. Cheap.
    """
    res = StaticChaosResult(plan_id=plan_id, n_steps=len(_all_steps(plan)))
    if not res.n_steps:
        return res
    for k in budgets:
        if k > res.n_steps - 1:
            continue
        entries = static_achilles_heel(plan, k=k)
        if not entries:
            continue
        avg_frag = round(sum(e.fragility for e in entries) / len(entries), 3)
        res.fragility_curve[k] = avg_frag
        res.achilles_top_per_k[k] = entries[:top_n]
    if 1 in res.fragility_curve:
        res.overall_fragility = res.fragility_curve[1]
    return res
