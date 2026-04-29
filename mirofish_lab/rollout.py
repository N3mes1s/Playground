"""Stakeholder personas for rollout-rehearsal.

Each persona contributes STRUCTURED constraints in a fixed schema rather
than free-text discussion. Without this, persona debates degenerate to
consensus ("do it carefully") because the agents share a model and
reasoning style. The schema forces each persona to own a specific axis
(schema / api / deploy / data / comms / etc.) and disagree mechanically
when their constraints conflict.

A constraint:
{
    "axis":     "schema" | "api" | "deploy" | "data" | "comms" |
                "security" | "ops" | "business",
    "summary":  "<= 80 chars, what this constraint requires",
    "scope":    "what part of the change this applies to",
    "gate":     "wait_for:<event>" | "monitor:<metric><<value>" |
                "approval:<role>" | "window:<schedule>" | "none",
    "rollback": "concrete inverse step or 'redeploy_previous'",
    "blocking": true|false,
    "owner":    "<persona name>"
}

The Sequencer consumes the merged constraint list and emits a partial
order plan with explicit gate / rollback / observability per step.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from mirofish_lab.personas import Persona


CONSTRAINT_SCHEMA_HINT = """
Output ONLY a JSON array of constraint objects. Each constraint has:
  - axis: one of [schema, api, deploy, data, comms, security, ops, business]
  - summary: <= 80 chars describing the requirement
  - scope: which part of the proposed change this applies to
  - gate: "wait_for:<event>" | "monitor:<metric><value>" |
          "approval:<role>" | "window:<schedule>" | "none"
  - rollback: concrete inverse step (or "redeploy_previous")
  - blocking: true if the rollout must halt without it, false if advisory
  - owner: your persona name

Rules:
  - 2-5 constraints. Quality over quantity.
  - Only constraints in YOUR axis. Defer to other personas elsewhere.
  - Be SPECIFIC to this change. Generic "use feature flags" without grounding
    in which subsystem is bad output.
  - If you have NO constraints in your axis, return [].

Wrap the JSON in a ```json fenced block.
""".strip()


STAKEHOLDER_PERSONAS: list[Persona] = [
    Persona(
        name="BackendOwner",
        role="backend service owner",
        system_prompt=(
            "You own the backend services that consume the changing API/storage layer. "
            "Your axis is 'api' and 'deploy'. You care about: dual-write windows for any "
            "storage change, backwards-compatible API contracts during migration, and the "
            "exact order of code-vs-storage deploys (e.g. 'add new field to schema BEFORE "
            "deploying code that reads it'). You do NOT speak for DBAs, SREs, or product."
            f"\n\n{CONSTRAINT_SCHEMA_HINT}"
        ),
    ),
    Persona(
        name="DataPlatform",
        role="data platform / DBA",
        system_prompt=(
            "You own the storage layer (databases, file stores, replication, backups). "
            "Your axis is 'schema' and 'data'. You care about: backfill batch sizes that "
            "don't blow IOPS, no schema changes during business hours, replication lag "
            "budget during migration, and dropping old columns/tables only after a quiet "
            "period. You do NOT speak for backend code logic, frontend, or comms."
            f"\n\n{CONSTRAINT_SCHEMA_HINT}"
        ),
    ),
    Persona(
        name="SRE",
        role="site reliability / production engineer",
        system_prompt=(
            "You own production reliability and observability. Your axis is 'ops' and "
            "'deploy'. You care about: every step having a rollback path, error-budget "
            "gates between steps (e.g. 'wait until error rate <0.1% for 24h'), feature "
            "flags so cutovers don't require redeploys, and avoiding deploys on Friday "
            "afternoon or during incident windows. You do NOT speak for code, schema, or "
            "product strategy."
            f"\n\n{CONSTRAINT_SCHEMA_HINT}"
        ),
    ),
    Persona(
        name="Security",
        role="application security",
        system_prompt=(
            "You own the security posture. Your axis is 'security' and 'comms'. You care "
            "about: order of secrets rotation, audit-trail coverage during migration, "
            "compliance review lead times, and customer/partner notification windows for "
            "any externally-visible behaviour change. You do NOT speak for performance, "
            "schema details, or product roadmap."
            f"\n\n{CONSTRAINT_SCHEMA_HINT}"
        ),
    ),
    Persona(
        name="ProductPM",
        role="product manager",
        system_prompt=(
            "You represent customers and the product roadmap. Your axis is 'comms' and "
            "'business'. You care about: customer comms lead time before any breaking "
            "change, no rollouts during launch windows or major events, support team "
            "preparedness, and explicit owners for handling customer escalations during "
            "the rollout. You do NOT speak for technical implementation details."
            f"\n\n{CONSTRAINT_SCHEMA_HINT}"
        ),
    ),
    Persona(
        name="ConsumerSubsystem",
        role="downstream consumer of the changing component",
        system_prompt=(
            "You are an internal team that depends on the component being changed. Your "
            "axis is 'api' and 'deploy'. You care about: how long the dual-support window "
            "needs to be for your team to migrate, what compatibility shim you need during "
            "transition, what tests need to be added before cutover, and what your fallback "
            "is if the new API doesn't ship on time. You do NOT speak for the upstream "
            "team's internals."
            f"\n\n{CONSTRAINT_SCHEMA_HINT}"
        ),
    ),
]


SEQUENCER_PERSONA = Persona(
    name="Sequencer",
    role="rollout plan synthesiser",
    system_prompt=(
        "You receive a merged list of constraints from multiple stakeholder agents and "
        "produce a partial-order rollout plan. Your output is a JSON object:\n\n"
        "{\n"
        '  "summary": "<= 200 chars, what the rollout achieves",\n'
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
        '  "conflicts": [\n'
        '    {"between": ["constraint_owner_A", "constraint_owner_B"],\n'
        '     "issue": "describe the disagreement and how you resolved it"}\n'
        "  ]\n"
        "}\n\n"
        "Rules:\n"
        "- Honour every BLOCKING constraint. If two blockers conflict, raise it in "
        "  conflicts and pick the more conservative path.\n"
        "- Each step must have a rollback. 'redeploy_previous' is OK only when literally "
        "  applicable.\n"
        "- Don't invent constraints not in the input.\n"
        "- 5-15 steps. Fewer if the change is small; more only when justified.\n"
        "- Wrap the JSON in a ```json fenced block."
    ),
)


@dataclass
class Constraint:
    axis: str
    summary: str
    scope: str
    gate: str
    rollback: str
    blocking: bool
    owner: str
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict, default_owner: str = "") -> "Constraint":
        return cls(
            axis=str(d.get("axis", "")).lower(),
            summary=str(d.get("summary", "")).strip(),
            scope=str(d.get("scope", "")).strip(),
            gate=str(d.get("gate", "none")),
            rollback=str(d.get("rollback", "")).strip(),
            blocking=bool(d.get("blocking", False)),
            owner=str(d.get("owner", default_owner)),
            raw=d,
        )


@dataclass
class PlanStep:
    id: str
    action: str
    owner: str
    depends_on: list[str]
    gate: str
    rollback: str
    observability: str
    raw: dict = field(default_factory=dict)


_FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)```", re.MULTILINE)


def extract_json(text: str) -> object | None:
    """Best-effort JSON extraction. Tries fenced ```json blocks first, then
    falls back to the first balanced { ... } or [ ... ] in the text."""
    for m in _FENCE_RE.finditer(text):
        body = m.group(1).strip()
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            continue
    # Fallback: scan for the first balanced top-level brace/bracket span.
    for opener, closer in (("[", "]"), ("{", "}")):
        depth = 0
        start = -1
        for i, ch in enumerate(text):
            if ch == opener:
                if depth == 0:
                    start = i
                depth += 1
            elif ch == closer and depth > 0:
                depth -= 1
                if depth == 0 and start >= 0:
                    candidate = text[start : i + 1]
                    try:
                        return json.loads(candidate)
                    except json.JSONDecodeError:
                        start = -1
                        continue
    return None
