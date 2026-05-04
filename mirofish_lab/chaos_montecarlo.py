"""Probabilistic Monte Carlo robustness simulation for rollout plans.

Replaces the binary "fails or doesn't" view of the LLM probe with a
probabilistic one: each step is assigned a per-step failure
probability based on its gate type, then we run N synthetic
executions of the plan, sampling failures, and report the
distribution of "successful completion" rates.

Per-gate failure prior heuristics (tunable):

  - `monitor:err<X%`             ~ 0.02   (well-defined SLO threshold)
  - `monitor:err<X% for Yh`      ~ 0.04   (long soak; more chances)
  - `wait_for:<event>`            ~ 0.05   (named event must arrive)
  - `approval:<role>`             ~ 0.10   (humans miss things)
  - `window:<schedule>`           ~ 0.07   (schedule miss)
  - `none`                        ~ 0.03   (no gate at all)
  - unrecognised                  ~ 0.10

These priors are not calibrated; they're starting heuristics. The
expected use is to run the simulation, see which steps dominate the
failure rate, and use that to argue for tightening or relaxing
specific gates.

Reference: classical Monte Carlo deployment-risk simulation, applied
to the structural cascade computed by chaos_static.
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass, field

from mirofish_lab.chaos_static import static_cascade


_DEFAULT_GATE_PRIORS = {
    "none": 0.03,
    "approval:": 0.10,
    "window:": 0.07,
    "wait_for:": 0.05,
    "monitor:": 0.04,
}


def gate_failure_prior(gate: str, *, priors: dict | None = None) -> float:
    g = (gate or "").strip().lower()
    p = priors or _DEFAULT_GATE_PRIORS
    if not g or g == "none":
        return p.get("none", 0.03)
    for prefix, prior in p.items():
        if g.startswith(prefix):
            base = prior
            # Soak-window penalty: longer soaks have more chances to fail.
            soak_match = re.search(r"for\s*(\d+)\s*h", g)
            if soak_match:
                hours = int(soak_match.group(1))
                base = base * (1 + hours / 48.0)
            return min(base, 0.5)
    return 0.10


@dataclass
class Execution:
    sample: int
    failed_steps: tuple[str, ...]
    blocked_steps: tuple[str, ...]
    completed_steps: tuple[str, ...]
    success_rate: float


@dataclass
class MonteCarloResult:
    plan_id: str
    n_steps: int
    n_samples: int
    avg_success_rate: float = 0.0
    p50_success_rate: float = 0.0
    p10_success_rate: float = 0.0
    p90_success_rate: float = 0.0
    full_failure_rate: float = 0.0   # fraction where 0 steps completed past failures
    full_success_rate: float = 0.0   # fraction where all steps completed
    per_step_failure_rate: dict[str, float] = field(default_factory=dict)
    histogram: dict[str, int] = field(default_factory=dict)   # bucketed success rate
    representative_runs: list[Execution] = field(default_factory=list)


def montecarlo_simulate(
    plan: dict,
    *,
    plan_id: str = "default",
    n_samples: int = 500,
    seed: int = 1337,
    priors: dict | None = None,
) -> MonteCarloResult:
    rng = random.Random(seed)
    steps = [
        s for s in (plan.get("steps") or [])
        if isinstance(s, dict) and s.get("id")
    ]
    n = len(steps)
    res = MonteCarloResult(plan_id=plan_id, n_steps=n, n_samples=n_samples)
    if not n:
        return res

    step_priors = {s["id"]: gate_failure_prior(s.get("gate", ""), priors=priors)
                   for s in steps}
    per_step_fails = {sid: 0 for sid in step_priors}
    success_rates: list[float] = []

    representative: list[Execution] = []
    for sample in range(n_samples):
        failed: list[str] = []
        for sid, p in step_priors.items():
            if rng.random() < p:
                failed.append(sid)
        for sid in failed:
            per_step_fails[sid] += 1
        blocked = static_cascade(plan, failed)
        completed = [s["id"] for s in steps
                     if s["id"] not in failed and s["id"] not in blocked]
        rate = len(completed) / n
        success_rates.append(rate)
        if sample < 5 or rate in (0.0, 1.0):
            representative.append(
                Execution(
                    sample=sample,
                    failed_steps=tuple(sorted(failed)),
                    blocked_steps=tuple(sorted(blocked)),
                    completed_steps=tuple(sorted(completed)),
                    success_rate=rate,
                )
            )

    success_rates.sort()
    res.avg_success_rate = round(sum(success_rates) / len(success_rates), 3)
    res.p10_success_rate = round(success_rates[int(0.10 * n_samples)], 3)
    res.p50_success_rate = round(success_rates[int(0.50 * n_samples)], 3)
    res.p90_success_rate = round(success_rates[min(int(0.90 * n_samples), n_samples - 1)], 3)
    res.full_failure_rate = round(
        sum(1 for r in success_rates if r == 0.0) / n_samples, 3
    )
    res.full_success_rate = round(
        sum(1 for r in success_rates if r == 1.0) / n_samples, 3
    )
    res.per_step_failure_rate = {
        sid: round(c / n_samples, 3) for sid, c in per_step_fails.items()
    }

    # Bucketed histogram (10 buckets).
    buckets = [0] * 10
    for r in success_rates:
        idx = min(9, int(r * 10))
        buckets[idx] += 1
    res.histogram = {
        f"{i*10}-{(i+1)*10}%": buckets[i] for i in range(10)
    }

    res.representative_runs = representative[:8]
    return res
