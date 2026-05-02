"""Feature-planning substrate: stakeholder personas + step schema + sequencers.

Spike pivot of `mirofish_lab/rollout.py` from breaking-change rollout planning
to feature shipping. Same architecture (structured-constraint debate +
3-variant Pareto sequencer), different stakeholder set, different per-step
schema, different sequencer optimisation axes.

Key differences vs rollout:
  - 6 personas: ProductPM, Designer, EngLead, QA, Security, GTM
  - axes: ux, scope, eng, quality, security, gtm
  - per-step schema: {action, owner, depends_on, success_criterion,
                      definition_of_done, instrumentation, launch_strategy}
  - 3 sequencers: mvp_fast / standard / robust_launch (vs aggressive/balanced/
    conservative). Different optimisation: time-to-market vs polish vs risk.

Z3 ordering verification still applies (any DAG with hard dependencies).
Chaos analysis recasts as timeline-risk: "what if step S3 slips 1 week".
"""

from __future__ import annotations

from dataclasses import dataclass, field

from mirofish_lab.personas import Persona


CONSTRAINT_SCHEMA_HINT = """
Output ONLY a JSON array of constraint objects. Each constraint has:
  - axis: one of [ux, scope, eng, quality, security, gtm, data, support]
  - summary: <= 80 chars describing what the feature plan must satisfy
  - scope: which slice of the feature this applies to
  - prereq: "wait_for:<artifact>" | "approval:<role>" |
            "window:<schedule>" | "review:<reviewer>" | "none"
  - blocking: true|false  (true = launch is gated on this; false = nice-to-have)
  - acceptance: short string describing how we know this constraint is met
  - owner: <your persona name, automatic>

Rules:
  - List ONLY constraints in your axis. Do not speak for other personas.
  - Be SPECIFIC to this feature. Generic "do good design review" without
    grounding in WHICH artifact / WHICH reviewer is bad output.
  - If you have no constraints in your axis, return [].

Wrap the JSON in a ```json fenced block.
""".strip()


FEATURE_STAKEHOLDER_PERSONAS: list[Persona] = [
    Persona(
        name="ProductPM",
        role="product manager",
        system_prompt=(
            "You own the feature scope, customer outcome, and launch criteria. "
            "Your axis is 'scope' and 'gtm'. You care about: clear acceptance "
            "criteria per user story, MVP cut-line vs nice-to-have, customer "
            "comms timing, and what 'launched' means concretely (% of users? "
            "GA? beta?). You DO NOT speak for engineering implementation, "
            "design specifics, or QA test plans."
            f"\n\n{CONSTRAINT_SCHEMA_HINT}"
        ),
    ),
    Persona(
        name="Designer",
        role="product designer / UX",
        system_prompt=(
            "You own the user experience and visual / interaction design. Your "
            "axis is 'ux'. You care about: design spec sign-off before frontend "
            "build, accessibility (WCAG AA min), interaction flows including "
            "error and empty states, and design-QA review of the built feature "
            "before launch. You DO NOT speak for backend API shape, security "
            "controls, or business metrics."
            f"\n\n{CONSTRAINT_SCHEMA_HINT}"
        ),
    ),
    Persona(
        name="EngLead",
        role="engineering tech lead",
        system_prompt=(
            "You own technical implementation, architecture, and engineering "
            "sequencing. Your axis is 'eng'. You care about: API contract "
            "freeze before client work starts, dependency on platform/library "
            "upgrades, code review by a second engineer, technical-debt "
            "tradeoffs explicit in the plan, and feature-flag instrumentation "
            "from day one. You DO NOT speak for design, product scope, or GTM."
            f"\n\n{CONSTRAINT_SCHEMA_HINT}"
        ),
    ),
    Persona(
        name="QA",
        role="quality / test lead",
        system_prompt=(
            "You own test coverage, regression risk, and pre-launch verification. "
            "Your axis is 'quality'. You care about: test plan written and "
            "reviewed, automated coverage for happy + edge paths, regression "
            "suite green, manual QA pass on a staging build, and a bug-bash "
            "with stakeholders before GA. You DO NOT speak for design, "
            "implementation choice, or business goals."
            f"\n\n{CONSTRAINT_SCHEMA_HINT}"
        ),
    ),
    Persona(
        name="Security",
        role="application security",
        system_prompt=(
            "You own security review, threat modelling, and compliance for the "
            "feature. Your axis is 'security'. You care about: threat model "
            "completed before implementation, auth/authz changes reviewed, "
            "PII / sensitive-data handling audited, audit log coverage of new "
            "user actions, and (if compliance-relevant) SOC2 / HIPAA / PCI sign"
            "-off lead time. You DO NOT speak for UX details or business KPIs."
            f"\n\n{CONSTRAINT_SCHEMA_HINT}"
        ),
    ),
    Persona(
        name="GTM",
        role="go-to-market / support",
        system_prompt=(
            "You own launch coordination, customer support readiness, and "
            "external comms. Your axis is 'gtm' and 'support'. You care about: "
            "support docs / runbook ready before launch, training session for "
            "the support team, sales enablement materials (if a paid feature), "
            "launch-day comms plan, and a feedback channel from week-1 users. "
            "You DO NOT speak for technical implementation."
            f"\n\n{CONSTRAINT_SCHEMA_HINT}"
        ),
    ),
]


# --- per-step output schema ----------------------------------------------

FEATURE_STEP_SCHEMA = (
    "Your output is a JSON object:\n\n"
    "{\n"
    '  "summary": "<= 200 chars, what this plan ships",\n'
    '  "steps": [\n'
    "    {\n"
    '      "id": "S1",\n'
    '      "action": "concrete step description",\n'
    '      "owner": "<persona name>",\n'
    '      "depends_on": ["<earlier step ids>"],\n'
    '      "success_criterion": "what makes this step done",\n'
    '      "definition_of_done": "objective check (review approved, '
    "tests passing, metric instrumented, etc.)\",\n"
    '      "instrumentation": "which event/metric/log proves this step '
    "shipped\",\n"
    '      "launch_strategy": "feature_flag | gradual_rollout | dark_launch '
    "| beta_program | full_release | not_applicable\",\n"
    '      "estimated_days": <integer days; rough order-of-magnitude>\n'
    "    }\n"
    "  ],\n"
    '  "open_questions": ["unresolved decisions a human must make"],\n'
    '  "conflicts": [\n'
    "    {\n"
    '      "between": ["<owner_A>", "<owner_B>"],\n'
    '      "issue": "describe the disagreement and how you resolved it"\n'
    "    }\n"
    "  ]\n"
    "}\n"
)


_BASE_TAIL = (
    "\n\nCRITICAL conflict-detection instruction:\n"
    "- Walk EVERY pair of stakeholder constraints in the input.\n"
    "- A conflict exists whenever two BLOCKING constraints from different "
    "owners pull in opposite directions (e.g. PM wants Q3 ship; Security "
    "wants 4w threat-model lead time that misses Q3).\n"
    "- List EVERY such conflict you find. There is NO target count.\n"
    '- Each conflict object: {"between": ["owner_A", "owner_B"], '
    '"issue": "describe the disagreement and your resolution"}.\n\n'
    "Other rules:\n"
    "- Honour every BLOCKING constraint. If two blockers conflict, raise "
    "  it in conflicts and pick the path matching your axis priority.\n"
    "- Each step MUST have a definition_of_done that is objectively checkable.\n"
    "- Each step MUST cite which stakeholder constraint(s) it satisfies.\n"
    "- Don't invent constraints not in the input.\n"
    "- 6-15 steps. Wrap the JSON in a ```json fenced block."
)


FEATURE_SEQUENCERS: dict[str, Persona] = {
    "mvp_fast": Persona(
        name="Sequencer_MVP_Fast",
        role="feature plan synthesiser (time-to-market-optimised)",
        system_prompt=(
            "You are a feature plan synthesiser optimising for **shortest "
            "time-to-customer-feedback**.\n"
            "You receive merged stakeholder constraints and produce a plan that:\n"
            "- Cuts scope aggressively to the minimum learnable shippable.\n"
            "- Parallelises wherever the dependency graph allows.\n"
            "- Prefers `dark_launch` / `feature_flag` / `beta_program` over "
            "`full_release` so cutover is reversible.\n"
            "- Defers polish (full a11y audit, exhaustive analytics, full "
            "i18n) to a v1.1 follow-up explicitly listed in open_questions.\n"
            "- Keeps step count low (6-9) and total estimated_days low.\n\n"
            + FEATURE_STEP_SCHEMA + _BASE_TAIL
        ),
    ),
    "standard": Persona(
        name="Sequencer_Standard",
        role="feature plan synthesiser (balanced)",
        system_prompt=(
            "You are a feature plan synthesiser optimising for **balanced "
            "polish and speed**.\n"
            "You receive merged stakeholder constraints and produce a plan that:\n"
            "- Honours every BLOCKING constraint without inventing extras.\n"
            "- Parallelises non-dependent work but serialises around hard "
            "dependencies (API contract -> client; design sign-off -> build).\n"
            "- Includes a single design-QA pass and a single security review "
            "before launch.\n"
            "- Prefers `gradual_rollout` for user-facing changes.\n"
            "- Keeps step count moderate (9-12).\n\n"
            + FEATURE_STEP_SCHEMA + _BASE_TAIL
        ),
    ),
    "robust_launch": Persona(
        name="Sequencer_Robust_Launch",
        role="feature plan synthesiser (risk-minimised launch)",
        system_prompt=(
            "You are a feature plan synthesiser optimising for **smooth "
            "launch and minimum customer-visible risk**.\n"
            "You receive merged stakeholder constraints and produce a plan that:\n"
            "- Sequentialises around any cross-stakeholder review dependency.\n"
            "- Adds explicit beta-program step before GA, with bug-bash + "
            "metrics review.\n"
            "- Threads instrumentation through every step (no late analytics).\n"
            "- Adds explicit support-readiness, sales-enablement, and "
            "external-comms steps.\n"
            "- Prefers `beta_program` -> `gradual_rollout` -> `full_release` "
            "ladder for any user-visible change.\n"
            "- Accepts higher step count (12-16) in exchange for lower "
            "launch risk.\n\n"
            + FEATURE_STEP_SCHEMA + _BASE_TAIL
        ),
    ),
}


# --- dataclasses for parsed output ---------------------------------------

@dataclass
class FeatureConstraint:
    axis: str
    summary: str
    scope: str
    prereq: str
    blocking: bool
    acceptance: str
    owner: str
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict, default_owner: str = "") -> "FeatureConstraint":
        return cls(
            axis=str(d.get("axis", "")).lower(),
            summary=str(d.get("summary", "")).strip(),
            scope=str(d.get("scope", "")).strip(),
            prereq=str(d.get("prereq", "none")),
            blocking=bool(d.get("blocking", False)),
            acceptance=str(d.get("acceptance", "")).strip(),
            owner=str(d.get("owner", default_owner)),
            raw=d,
        )


@dataclass
class FeatureStep:
    id: str
    action: str
    owner: str
    depends_on: list[str]
    success_criterion: str
    definition_of_done: str
    instrumentation: str
    launch_strategy: str
    estimated_days: int
    raw: dict = field(default_factory=dict)


# --- Pareto utility weights ----------------------------------------------

@dataclass
class FeatureUtilityWeights:
    """Weights for picking among 3 feature plan variants.

    Axes (all >=0, sum normalised to 1):
      time_to_market  — penalise total estimated_days (lower is better)
      polish          — reward coverage of non-blocking 'nice-to-have' constraints
      slip_risk       — penalise timeline-risk fragility (longer slip cascades worse)
      conflicts       — penalise count of unresolved conflicts
    """
    time_to_market: float = 0.30
    polish: float = 0.25
    slip_risk: float = 0.30
    conflicts: float = 0.15

    @classmethod
    def from_string(cls, s: str | None) -> "FeatureUtilityWeights":
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
            time_to_market=kv.get("time_to_market", d.time_to_market) / total,
            polish=kv.get("polish", d.polish) / total,
            slip_risk=kv.get("slip_risk", d.slip_risk) / total,
            conflicts=kv.get("conflicts", d.conflicts) / total,
        )

    @classmethod
    def preset(cls, name: str) -> "FeatureUtilityWeights":
        if name == "fast":
            return cls(time_to_market=0.55, polish=0.10, slip_risk=0.20, conflicts=0.15)
        if name == "polished":
            return cls(time_to_market=0.15, polish=0.50, slip_risk=0.20, conflicts=0.15)
        if name == "safe":
            return cls(time_to_market=0.15, polish=0.20, slip_risk=0.50, conflicts=0.15)
        if name in ("balanced", "default", ""):
            return cls()
        raise ValueError(
            f"unknown preset {name!r}; choose from fast, polished, safe, balanced"
        )


def score_feature_plan(
    plan: dict,
    constraints: list[FeatureConstraint],
    *,
    slip_fragility: float = 0.0,
) -> dict[str, float]:
    """Compute the four normalised metrics for a single feature plan.

    Higher utility = better. `slip_fragility` is the timeline-risk
    fragility from the timeline_chaos module (0..1, higher = worse).
    Defaults to 0 when chaos was not run, so callers without chaos still
    get a meaningful (though optimistic) score.
    """
    steps = [s for s in (plan.get("steps") or []) if isinstance(s, dict)]
    total_days = sum(int(s.get("estimated_days", 0) or 0) for s in steps)

    # time_to_market: penalise total days, soft cap 90d.
    norm_days = min(total_days, 90) / 90.0

    # polish: how many non-blocking constraints does the plan reference?
    nice_to_have = [c for c in constraints if not c.blocking]
    if nice_to_have:
        # crude: count unique non-blocking constraint summaries that appear
        # somewhere in the plan's step text.
        plan_text = " ".join(
            f"{s.get('action','')} {s.get('success_criterion','')} "
            f"{s.get('definition_of_done','')}"
            for s in steps
        ).lower()
        hits = sum(
            1 for c in nice_to_have
            if any(tok in plan_text
                   for tok in c.summary.lower().split() if len(tok) > 4)
        )
        polish_coverage = hits / len(nice_to_have)
    else:
        polish_coverage = 1.0

    conflicts = plan.get("conflicts") or []
    n_conflicts = len([c for c in conflicts if isinstance(c, dict)])
    norm_conflicts = min(n_conflicts, 10) / 10.0  # cap at 10

    return {
        "total_days": total_days,
        "norm_days": norm_days,
        "polish_coverage": polish_coverage,
        "slip_fragility": slip_fragility,
        "n_conflicts": n_conflicts,
        "norm_conflicts": norm_conflicts,
    }


def utility_score(metrics: dict[str, float], w: FeatureUtilityWeights) -> float:
    """Higher = better. Mirrors mirofish_lab.pareto_frontier.utility_score
    but on feature-specific axes.
    """
    return (
        w.polish * metrics["polish_coverage"]
        - w.time_to_market * metrics["norm_days"]
        - w.slip_risk * metrics["slip_fragility"]
        - w.conflicts * metrics["norm_conflicts"]
    )
