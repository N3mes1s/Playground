"""Timeline-risk chaos analysis for feature plans.

Pivot of `mirofish_lab.chaos_static` to feature planning. Where rollout chaos
asks "if step S5 fails, which downstream steps are blocked?", timeline chaos
asks "if step S5 slips by Δ days, how many days does the project slip?"

The mechanism is **critical path**: each step has `estimated_days`; the total
project duration is the longest path through the DAG. A step is on the
critical path iff its slip propagates 1-for-1 to project total. A step off
the critical path has slack — slip up to `slack_days` is absorbed.

Three primitives:

  - `critical_path(plan)` -> ((step_ids), total_days)
      Longest path through the dependency graph by `estimated_days` weight.

  - `slip_total(plan, slipped_step_id, slip_days)` -> new_total_days
      What the project total becomes if a single step slips by N days.

  - `worst_k_slips(plan, k=2, slip_days=5)` -> list of (step_ids, delta_days)
      Adversarial: which K-tuple of simultaneously slipping steps causes the
      worst project-total delta? Same shape as static chaos's `worst_k_failures`
      but with timeline semantics.

Plus a top-level `timeline_chaos_summary(plan)` that returns:
  - critical path
  - per-step slack
  - top-3 single-step slips ranked by impact
  - top-3 worst pair-slips
  - normalised slip_fragility 0..1 for use in `score_feature_plan`
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import combinations


def _steps(plan: dict) -> list[dict]:
    return [s for s in (plan.get("steps") or []) if isinstance(s, dict) and s.get("id")]


def _by_id(plan: dict) -> dict[str, dict]:
    return {s["id"]: s for s in _steps(plan)}


def _depends_on(s: dict) -> list[str]:
    return [d for d in (s.get("depends_on") or []) if isinstance(d, str)]


def _est_days(s: dict) -> int:
    try:
        return max(0, int(s.get("estimated_days", 0) or 0))
    except (TypeError, ValueError):
        return 0


def _topo(plan: dict) -> list[str]:
    """Topological order. Falls back to declared order on cycle (which Z3 catches)."""
    by = _by_id(plan)
    indeg: dict[str, int] = {sid: 0 for sid in by}
    for sid, s in by.items():
        for d in _depends_on(s):
            if d in by:
                indeg[sid] += 1
    queue = [sid for sid, deg in indeg.items() if deg == 0]
    out: list[str] = []
    while queue:
        n = queue.pop(0)
        out.append(n)
        for sid, s in by.items():
            if n in _depends_on(s):
                indeg[sid] -= 1
                if indeg[sid] == 0:
                    queue.append(sid)
    if len(out) != len(by):  # cycle; fall back to declared order
        return list(by.keys())
    return out


def _earliest_finish(plan: dict, *, slip: dict[str, int] | None = None) -> dict[str, int]:
    """Earliest finish time per step, given a per-step slip override (in days)."""
    by = _by_id(plan)
    order = _topo(plan)
    slip = slip or {}
    ef: dict[str, int] = {}
    for sid in order:
        s = by[sid]
        d = _est_days(s) + int(slip.get(sid, 0))
        deps = [ef.get(p, 0) for p in _depends_on(s) if p in by]
        ef[sid] = max(deps, default=0) + d
    return ef


def critical_path(plan: dict) -> tuple[tuple[str, ...], int]:
    """Longest path through the DAG by estimated_days. Returns (path_ids, total_days)."""
    by = _by_id(plan)
    if not by:
        return ((), 0)
    ef = _earliest_finish(plan)
    total = max(ef.values(), default=0)
    # walk backwards from the latest-finishing step picking the predecessor that
    # set its earliest finish.
    end = max(ef, key=lambda k: ef[k])
    path = [end]
    cur = end
    while True:
        s = by[cur]
        deps = _depends_on(s)
        if not deps:
            break
        # pick the dep with the largest ef (the binding constraint).
        best = max(
            (d for d in deps if d in by),
            key=lambda d: ef.get(d, 0),
            default=None,
        )
        if best is None:
            break
        path.append(best)
        cur = best
    return (tuple(reversed(path)), total)


def slack_per_step(plan: dict) -> dict[str, int]:
    """Days of slack each step has — slip up to this without affecting total."""
    by = _by_id(plan)
    if not by:
        return {}
    ef = _earliest_finish(plan)
    total = max(ef.values(), default=0)
    # latest-finish: longest path from each step to the project end.
    # Compute by DFS from each step counting the longest forward chain in days.
    # Simpler: for each step, latest-finish = total - longest-forward-chain
    # rooted at that step including itself. Build forward adjacency.
    fwd: dict[str, list[str]] = {sid: [] for sid in by}
    for sid, s in by.items():
        for d in _depends_on(s):
            if d in by:
                fwd[d].append(sid)

    memo: dict[str, int] = {}

    def lf(sid: str) -> int:
        if sid in memo:
            return memo[sid]
        children = fwd.get(sid, [])
        if not children:
            memo[sid] = total
            return total
        best = min(lf(c) - _est_days(by[c]) for c in children)
        memo[sid] = best
        return best

    return {sid: lf(sid) - ef[sid] for sid in by}


def slip_total(plan: dict, step_id: str, slip_days: int) -> int:
    """Project total when `step_id` slips by `slip_days`."""
    if step_id not in _by_id(plan):
        return -1
    ef = _earliest_finish(plan, slip={step_id: int(slip_days)})
    return max(ef.values(), default=0)


@dataclass
class SlipEntry:
    step_ids: tuple[str, ...]
    slip_days: int
    new_total: int
    delta_days: int


def worst_k_slips(
    plan: dict,
    *,
    k: int = 2,
    slip_days: int = 5,
    max_combinations: int | None = 200,
) -> list[SlipEntry]:
    """Find the K-tuples of steps whose simultaneous slip-by-`slip_days`
    causes the worst project-total slippage.
    """
    ids = list(_by_id(plan).keys())
    if not ids or k < 1 or k > len(ids):
        return []
    base_total = critical_path(plan)[1]
    combos = list(combinations(ids, k))
    if max_combinations is not None and len(combos) > max_combinations:
        combos = combos[:max_combinations]
    out: list[SlipEntry] = []
    for combo in combos:
        ef = _earliest_finish(plan, slip={sid: slip_days for sid in combo})
        total = max(ef.values(), default=0)
        out.append(SlipEntry(
            step_ids=combo,
            slip_days=slip_days,
            new_total=total,
            delta_days=total - base_total,
        ))
    out.sort(key=lambda e: -e.delta_days)
    return out


@dataclass
class TimelineChaosResult:
    plan_id: str
    n_steps: int
    base_total_days: int
    critical_path: tuple[str, ...]
    slack_per_step: dict[str, int]
    top_single_slips: list[SlipEntry] = field(default_factory=list)
    top_pair_slips: list[SlipEntry] = field(default_factory=list)
    slip_fragility: float = 0.0


def timeline_chaos_summary(
    plan: dict,
    *,
    plan_id: str = "default",
    single_slip_days: int = 5,
    pair_slip_days: int = 5,
) -> TimelineChaosResult:
    """End-to-end timeline-risk analysis.

    `slip_fragility` is the average single-step slip impact normalised to
    project total: avg_delta / base_total. 0 means every step has slack
    that absorbs the slip; 1 means every step is on the critical path.
    """
    n = len(_by_id(plan))
    if n == 0:
        return TimelineChaosResult(plan_id=plan_id, n_steps=0,
                                   base_total_days=0, critical_path=())

    cp, base_total = critical_path(plan)
    slack = slack_per_step(plan)

    singles = worst_k_slips(plan, k=1, slip_days=single_slip_days)
    pairs = worst_k_slips(plan, k=2, slip_days=pair_slip_days)

    if singles and base_total > 0:
        avg_delta = sum(e.delta_days for e in singles) / len(singles)
        # Normalise: max possible single-slip delta is single_slip_days;
        # avg_delta / single_slip_days gives a fragility 0..1 where 1 means
        # every step is on the critical path.
        fragility = min(1.0, avg_delta / max(1, single_slip_days))
    else:
        fragility = 0.0

    return TimelineChaosResult(
        plan_id=plan_id,
        n_steps=n,
        base_total_days=base_total,
        critical_path=cp,
        slack_per_step=slack,
        top_single_slips=singles[:3],
        top_pair_slips=pairs[:3],
        slip_fragility=fragility,
    )
