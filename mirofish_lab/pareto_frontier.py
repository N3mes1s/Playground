"""Multi-objective Pareto frontier for rollout plans.

Generates N plans with weight tuples spanning the (speed, safety, cost)
simplex, computes the **non-dominated set** (NSGA-II's fast non-dominated
sort, A. Deb 2002), assigns **crowding distance** per point so the
frontier has good spread, and projects to a single recommendation
using user-supplied **utility weights**.

Renders an ASCII Pareto chart (fragility on x-axis, step count on y-axis)
in markdown.

References:
  - NSGA-II: Deb et al., IEEE Trans. Evol. Comp. Vol 6 No 2
  - LLM-NSGA-II variants: ResearchGate fig5/385920440
  - Weighted Sum Sampling: arXiv 2410.03931
  - BAO Pareto frontier: arXiv 2602.11351
  - AI-SearchPlanner: arXiv 2508.20368
"""

from __future__ import annotations

from dataclasses import dataclass, field

from mirofish_lab.personas import Persona


# ---------------------------------------------------------------------------
# Weight-grid utilities
# ---------------------------------------------------------------------------


def _simplex_grid(n: int) -> list[tuple[float, float, float]]:
    """Generate ~n weight triples (speed, safety, cost) on the simplex
    s + sf + c = 1, s,sf,c >= 0. Uses a near-uniform grid; falls back to
    fixed corners + center for small n."""
    if n <= 3:
        return [(1.0, 0.0, 0.0), (0.0, 1.0, 0.0), (1 / 3, 1 / 3, 1 / 3)][:n]
    # Find smallest k such that triangular grid has >= n points.
    k = 1
    while (k + 1) * (k + 2) // 2 < n:
        k += 1
    pts: list[tuple[float, float, float]] = []
    for i in range(k + 1):
        for j in range(k + 1 - i):
            kk = k - i - j
            pts.append((i / k, j / k, kk / k))
    # Trim to n (keep extremes first).
    pts.sort(key=lambda p: (-max(p), -sum(1 for x in p if x == 0)))
    return pts[:n]


def _persona_for_weights(weights: tuple[float, float, float], slot: int) -> Persona:
    """Build a Sequencer persona biased toward the given (speed, safety, cost)
    weight triple. Slot is just used to give the agent a unique name so memory
    layers don't collide."""
    speed, safety, cost = weights
    name = f"Sequencer_W{slot}_s{int(speed*100):02d}sf{int(safety*100):02d}c{int(cost*100):02d}"
    bias_lines = []
    if speed >= 0.4:
        bias_lines.append(
            "- You strongly favour wall-clock speed: parallelise wherever the "
            "dependency graph allows, prefer `monitor:` gates over `approval:` "
            "gates so the plan runs without human checkpoints, keep step count low."
        )
    if safety >= 0.4:
        bias_lines.append(
            "- You strongly favour minimum blast radius: sequentialise risky "
            "paths, add soak windows (`monitor:error_rate<X for 24h`) before "
            "default flips, prefer feature-flag-controlled cutovers, every step "
            "has a single-step concrete inverse rollback."
        )
    if cost >= 0.4:
        bias_lines.append(
            "- You strongly favour low coordination cost: minimise the number "
            "of approval/window gates that block humans, collapse adjacent "
            "human approvals, prefer one-shot deploys over rolling phases."
        )
    if not bias_lines:
        bias_lines.append(
            "- You produce a balanced plan: honour every BLOCKING constraint "
            "without inventing extras; one safety gate per irreversible step."
        )

    bias = "\n".join(bias_lines)
    return Persona(
        name=name,
        role=f"rollout sequencer (weights speed={speed:.2f}, safety={safety:.2f}, cost={cost:.2f})",
        system_prompt=(
            f"You are a rollout plan synthesiser with a multi-objective bias.\n"
            f"Your weights: speed={speed:.2f}, safety={safety:.2f}, cost={cost:.2f}.\n"
            f"Strong biases:\n{bias}\n\n"
            "Your output is a JSON object:\n\n"
            "{\n"
            '  "summary": "<= 200 chars",\n'
            '  "steps": [\n'
            "    {\n"
            '      "id": "S1",\n'
            '      "action": "concrete step description",\n'
            '      "owner": "<persona name>",\n'
            '      "depends_on": ["<earlier step ids>"],\n'
            '      "gate": "wait_for:... | monitor:... | approval:... | window:... | none",\n'
            '      "rollback": "concrete inverse",\n'
            '      "observability": "what to watch during this step"\n'
            "    }\n"
            "  ],\n"
            '  "open_questions": ["unresolved things a human must decide"],\n'
            '  "conflicts": []\n'
            "}\n\n"
            "CRITICAL conflict-detection instruction:\n"
            "- Walk EVERY pair of stakeholder constraints in the input.\n"
            "- A conflict exists whenever two BLOCKING constraints from different "
            "owners pull in opposite directions.\n"
            "- List EVERY such conflict you find. There is NO target count.\n\n"
            "Other rules:\n"
            "- Honour every BLOCKING constraint. If two blockers conflict, raise "
            "  it in conflicts and pick the path that matches your weight priorities.\n"
            "- Each step must have a rollback. 'redeploy_previous' is OK only when "
            "  literally applicable.\n"
            "- Don't invent constraints not in the input.\n"
            "- 5-15 steps. Wrap the JSON in a ```json fenced block."
        ),
    )


@dataclass
class FrontierSlot:
    label: str
    weights: tuple[float, float, float]
    persona: Persona


def build_frontier_slots(n: int) -> list[FrontierSlot]:
    """Return n weight-biased Sequencer personas spanning the simplex."""
    grid = _simplex_grid(n)
    out: list[FrontierSlot] = []
    for i, w in enumerate(grid):
        speed, safety, cost = w
        # Generate a short human label for the dominant axis.
        if speed > max(safety, cost) and speed >= 0.5:
            label = "speed-leaning"
        elif safety > max(speed, cost) and safety >= 0.5:
            label = "safety-leaning"
        elif cost > max(speed, safety) and cost >= 0.5:
            label = "cost-leaning"
        elif max(w) - min(w) < 0.2:
            label = "balanced"
        else:
            top = ["speed", "safety", "cost"][w.index(max(w))]
            label = f"{top}-tilted"
        out.append(FrontierSlot(label=f"{i:02d}-{label}", weights=w, persona=_persona_for_weights(w, slot=i)))
    return out


# ---------------------------------------------------------------------------
# NSGA-II non-dominated sort + crowding distance
# ---------------------------------------------------------------------------


@dataclass
class FrontierPoint:
    label: str
    weights: tuple[float, float, float]
    metrics: dict[str, float]      # name -> value (lower is better, after we flip)
    rank: int = -1                  # 0 = best front
    crowding: float = 0.0


# Lower-is-better metric names. We flip "coverage" since higher is better.
_OBJECTIVES = ("fragility", "avg_severity", "rollback_failure_rate", "steps", "neg_coverage")


def _to_objectives(score: dict) -> dict[str, float]:
    return {
        "fragility": float(score.get("fragility", 1.0)),
        "avg_severity": float(score.get("avg_severity", 4.0)),
        "rollback_failure_rate": float(score.get("rollback_failure_rate", 1.0)),
        "steps": float(score.get("steps", 999)),
        "neg_coverage": -float(score.get("coverage_ratio", 0.0)),
    }


def _dominates(a: dict[str, float], b: dict[str, float]) -> bool:
    """Lower-is-better. a dominates b if a <= b on all and < on at least one."""
    le_all = True
    lt_some = False
    for k in _OBJECTIVES:
        if a[k] > b[k]:
            le_all = False
            break
        if a[k] < b[k]:
            lt_some = True
    return le_all and lt_some


def non_dominated_sort(points: list[FrontierPoint]) -> list[list[FrontierPoint]]:
    """NSGA-II fast non-dominated sort. Returns list of fronts; fronts[0] is
    Pareto-optimal."""
    n = len(points)
    if n == 0:
        return []
    dominated_by: list[list[int]] = [[] for _ in range(n)]
    domination_count = [0] * n
    fronts: list[list[int]] = [[]]
    for i, p in enumerate(points):
        for j, q in enumerate(points):
            if i == j:
                continue
            if _dominates(p.metrics, q.metrics):
                dominated_by[i].append(j)
            elif _dominates(q.metrics, p.metrics):
                domination_count[i] += 1
        if domination_count[i] == 0:
            points[i].rank = 0
            fronts[0].append(i)
    cur = 0
    while fronts[cur]:
        nxt: list[int] = []
        for i in fronts[cur]:
            for j in dominated_by[i]:
                domination_count[j] -= 1
                if domination_count[j] == 0:
                    points[j].rank = cur + 1
                    nxt.append(j)
        cur += 1
        fronts.append(nxt)
    fronts.pop()
    return [[points[i] for i in f] for f in fronts]


def crowding_distance(front: list[FrontierPoint]) -> None:
    """Assigns crowding distance per point in the given front (in place)."""
    n = len(front)
    if n == 0:
        return
    for p in front:
        p.crowding = 0.0
    if n <= 2:
        for p in front:
            p.crowding = float("inf")
        return
    for k in _OBJECTIVES:
        front.sort(key=lambda p: p.metrics[k])
        front[0].crowding = float("inf")
        front[-1].crowding = float("inf")
        rng = front[-1].metrics[k] - front[0].metrics[k]
        if rng <= 0:
            continue
        for i in range(1, n - 1):
            front[i].crowding += (front[i + 1].metrics[k] - front[i - 1].metrics[k]) / rng


# ---------------------------------------------------------------------------
# Utility-weighted pick
# ---------------------------------------------------------------------------


@dataclass
class UtilityWeights:
    """Default weights are deliberately balanced after observing the
    speed-leaning bias: cascade fragility was weighted at 0.40 and
    drove recommendations toward parallel structures regardless of
    operational safety. These rebalanced defaults give rollback-
    failure rate a fair share, since cleaner rollback chains are a
    real safety win that the cascade metric ignores."""
    fragility: float = 0.20
    coverage: float = 0.25
    steps: float = 0.10
    severity: float = 0.20
    rollback_failure: float = 0.25

    @classmethod
    def from_string(cls, s: str | None) -> "UtilityWeights":
        """Parse 'fragility=0.4,coverage=0.3,...' into weights normalised to 1."""
        if not s:
            return cls()
        kv: dict[str, float] = {}
        for part in s.split(","):
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            try:
                kv[k.strip()] = float(v.strip())
            except ValueError:
                pass
        total = sum(kv.values()) or 1.0
        d = cls()
        return cls(
            fragility=kv.get("fragility", d.fragility) / total,
            coverage=kv.get("coverage", d.coverage) / total,
            steps=kv.get("steps", d.steps) / total,
            severity=kv.get("severity", d.severity) / total,
            rollback_failure=kv.get("rollback_failure", d.rollback_failure) / total,
        )

    @classmethod
    def preset(cls, name: str) -> "UtilityWeights":
        """Named presets for --prefer flag.

        - **safety**: rollback-chain integrity matters more than
          parallel cascade. Sequential-but-rollback-clean plans win.
        - **speed**: parallelism wins; default if the user wants the
          original behaviour back.
        - **cost**: minimise step count + approval gates that block
          humans.
        - **balanced**: rebalanced defaults (the new default).
        """
        if name == "safety":
            return cls(
                fragility=0.10,
                coverage=0.20,
                steps=0.05,
                severity=0.20,
                rollback_failure=0.45,
            )
        if name == "speed":
            return cls(
                fragility=0.45,
                coverage=0.20,
                steps=0.15,
                severity=0.15,
                rollback_failure=0.05,
            )
        if name == "cost":
            return cls(
                fragility=0.15,
                coverage=0.20,
                steps=0.40,
                severity=0.10,
                rollback_failure=0.15,
            )
        if name in ("balanced", "default", ""):
            return cls()
        raise ValueError(
            f"unknown preset {name!r}; choose from safety, speed, cost, balanced"
        )


def utility_score(point: FrontierPoint, w: UtilityWeights) -> float:
    """Higher = better."""
    m = point.metrics
    coverage = -m["neg_coverage"]
    # Normalise step count to 0..1 with a soft cap of 20 steps.
    norm_steps = min(m["steps"], 20.0) / 20.0
    norm_severity = (m["avg_severity"] - 1) / 3.0  # 1..4 -> 0..1
    return (
        w.coverage * coverage
        - w.fragility * m["fragility"]
        - w.steps * norm_steps
        - w.severity * norm_severity
        - w.rollback_failure * m["rollback_failure_rate"]
    )


# ---------------------------------------------------------------------------
# ASCII chart
# ---------------------------------------------------------------------------


def render_ascii_chart(
    points: list[FrontierPoint],
    *,
    x: str = "fragility",
    y: str = "steps",
    w: int = 60,
    h: int = 18,
) -> str:
    """Lightweight ASCII scatter, marking front-0 points with '*' and others
    with '.'; labels with rank index."""
    if not points:
        return "_(no points)_"
    xs = [p.metrics[x] for p in points]
    ys = [p.metrics[y] for p in points]
    xmin, xmax = min(xs), max(xs)
    ymin, ymax = min(ys), max(ys)
    if xmax == xmin:
        xmax += 1
    if ymax == ymin:
        ymax += 1
    grid = [[" " for _ in range(w)] for _ in range(h)]
    for p in points:
        cx = int((p.metrics[x] - xmin) / (xmax - xmin) * (w - 1))
        cy = h - 1 - int((p.metrics[y] - ymin) / (ymax - ymin) * (h - 1))
        cy = max(0, min(h - 1, cy))
        cx = max(0, min(w - 1, cx))
        ch = "*" if p.rank == 0 else "."
        grid[cy][cx] = ch
    lines = ["```", f"y={y} (lower is better) ↑    Pareto front: '*'   dominated: '.'"]
    for row in grid:
        lines.append("".join(row))
    lines.append("─" * w)
    lines.append(f"        x={x} (lower is better) →   range [{xmin:.2f}, {xmax:.2f}]")
    lines.append("```")
    return "\n".join(lines)
