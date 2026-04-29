"""Formal verification of rollout plans.

Runs three structural checks over a Sequencer-emitted plan and the
stakeholder-constraint list it was synthesised from:

1. DAG: no cycles in `depends_on` edges.
2. Reachability: every step is reachable from a root step.
3. Coverage: each BLOCKING stakeholder constraint's gate appears as a
   gate or observability hint on at least one step (we match by token
   overlap rather than equality, since the Sequencer paraphrases).

This is the "VeriPlan-style" plan verification layer (arXiv 2502.17898 /
2510.03469) without dragging in Z3. Pure stdlib + a tiny set similarity.

A plan that fails verification is still RUNNABLE; the report flags it so
a human can decide.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]+")


def _tokens(s: str) -> set[str]:
    return {t.lower() for t in _TOKEN_RE.findall(s or "") if len(t) > 2}


@dataclass
class VerificationResult:
    plan_id: str
    is_dag: bool = True
    cycles: list[list[str]] = field(default_factory=list)
    unreachable_steps: list[str] = field(default_factory=list)
    blocking_total: int = 0
    blocking_covered: int = 0
    uncovered_blocking_summaries: list[str] = field(default_factory=list)
    invalid_gates: list[tuple[str, str]] = field(default_factory=list)

    @property
    def coverage_ratio(self) -> float:
        if not self.blocking_total:
            return 1.0
        return self.blocking_covered / self.blocking_total

    @property
    def passes(self) -> bool:
        return (
            self.is_dag
            and not self.unreachable_steps
            and not self.invalid_gates
            and self.coverage_ratio >= 0.8
        )


def _find_cycles(adj: dict[str, list[str]]) -> list[list[str]]:
    """Tarjan-style cycle finder. Returns one representative cycle per SCC."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    counter = [0]
    cycles: list[list[str]] = []

    def strong(v: str) -> None:
        index[v] = low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on_stack.add(v)
        for w in adj.get(v, ()):
            if w not in index:
                strong(w)
                low[v] = min(low[v], low[w])
            elif w in on_stack:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            scc: list[str] = []
            while stack:
                w = stack.pop()
                on_stack.discard(w)
                scc.append(w)
                if w == v:
                    break
            if len(scc) > 1 or v in adj.get(v, ()):
                cycles.append(scc)

    for v in list(adj):
        if v not in index:
            strong(v)
    return cycles


def _gate_is_valid(gate: str) -> bool:
    if not gate:
        return False
    g = gate.strip().lower()
    if g == "none":
        return True
    return any(
        g.startswith(p + ":") or g.startswith(p + " ")
        for p in ("wait_for", "monitor", "approval", "window")
    )


def verify_plan(
    plan: dict,
    constraints: list[dict],
    *,
    plan_id: str = "default",
) -> VerificationResult:
    steps = plan.get("steps") or []
    res = VerificationResult(plan_id=plan_id)

    if not steps:
        res.is_dag = True
        return res

    # Build adjacency depends_on -> step. Edge: dep -> step (dep happens first).
    ids = [s.get("id") for s in steps if isinstance(s, dict) and s.get("id")]
    id_set = set(ids)
    adj: dict[str, list[str]] = {i: [] for i in ids}
    incoming: dict[str, int] = {i: 0 for i in ids}
    for s in steps:
        if not isinstance(s, dict):
            continue
        sid = s.get("id")
        deps = [d for d in (s.get("depends_on") or []) if d in id_set]
        for d in deps:
            adj.setdefault(d, []).append(sid)
            incoming[sid] = incoming.get(sid, 0) + 1

    cycles = _find_cycles(adj)
    res.is_dag = not cycles
    res.cycles = cycles

    # Reachability from roots (incoming==0).
    if res.is_dag:
        roots = [i for i in ids if incoming.get(i, 0) == 0]
        seen: set[str] = set()
        stack = list(roots)
        while stack:
            n = stack.pop()
            if n in seen:
                continue
            seen.add(n)
            stack.extend(adj.get(n, []))
        res.unreachable_steps = [i for i in ids if i not in seen]

    # Gate validity.
    for s in steps:
        if not isinstance(s, dict):
            continue
        sid = s.get("id", "?")
        g = s.get("gate", "")
        if not _gate_is_valid(g):
            res.invalid_gates.append((sid, g))

    # Blocking-constraint coverage by token overlap with any step's gate or
    # observability or action.
    step_blob = " | ".join(
        " ".join(
            str(s.get(k, "") or "") for k in ("action", "gate", "observability")
        )
        for s in steps if isinstance(s, dict)
    )
    step_tokens = _tokens(step_blob)

    for c in constraints:
        if not isinstance(c, dict) or not c.get("blocking"):
            continue
        res.blocking_total += 1
        c_tokens = _tokens(
            " ".join(str(c.get(k, "") or "") for k in ("summary", "scope", "gate"))
        )
        if not c_tokens:
            res.blocking_covered += 1
            continue
        # If at least 30% of the constraint's distinctive tokens appear in plan,
        # treat as covered.
        overlap = len(c_tokens & step_tokens) / max(1, len(c_tokens))
        if overlap >= 0.3:
            res.blocking_covered += 1
        else:
            res.uncovered_blocking_summaries.append(
                str(c.get("summary", "")).strip()
            )

    return res
