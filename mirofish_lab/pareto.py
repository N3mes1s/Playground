"""Pareto-frontier sequencer variants for verified-rollout.

Same input constraint set, three different Sequencer system prompts
each pushing on a different optimisation axis. The result is three
candidate plans on a fast-vs-safe trade-off frontier rather than one
synthesised plan.

This is the BAO-style behavioural Pareto exploration (arXiv 2602.11351)
applied to migration-plan synthesis.

## Runtime prompt extension (added for GEPA-friendly experiments)

Two complementary mechanisms append additional instructions to the
Sequencer BASE_TAIL without modifying this file:

  1. Environment variable `MIROFISH_PARETO_TAIL_EXTRA` — set to a raw
     string. Used by `gepa_optimizer.py` when running candidate
     bench evaluations: the candidate's text is set in the env, the
     bench subprocess inherits it, and pareto.py picks it up at
     module-import time. The next subprocess (without the env var)
     gets the unmodified prompt.

  2. Persistent file `mirofish_lab/pareto_extra.txt` — when present,
     its contents are appended to BASE_TAIL by default. This is
     where GEPA's `--apply` writes a winning candidate's text so it
     survives across processes without source-code modification.

Both can be active simultaneously; the env var wins when set so
ad-hoc experiments do not bleed into persisted defaults.
"""

from __future__ import annotations

import os
from pathlib import Path

from mirofish_lab.personas import Persona


_PARETO_EXTRA_FILE = Path(__file__).parent / "pareto_extra.txt"


def _load_runtime_tail_extra() -> str:
    """Resolve the runtime extension text in priority order:
    1. MIROFISH_PARETO_TAIL_EXTRA env var (if set, even to empty string).
    2. mirofish_lab/pareto_extra.txt file contents (if present).
    3. Empty string.
    """
    env_val = os.environ.get("MIROFISH_PARETO_TAIL_EXTRA")
    if env_val is not None:
        return env_val
    if _PARETO_EXTRA_FILE.exists():
        try:
            return _PARETO_EXTRA_FILE.read_text()
        except Exception:
            return ""
    return ""


_BASE_TAIL_CORE = (
    "\n\nCRITICAL conflict-detection instruction:\n"
    "- Walk EVERY pair of stakeholder constraints in the input.\n"
    "- A conflict exists whenever two BLOCKING constraints from different owners "
    "pull in opposite directions.\n"
    "- List EVERY such conflict you find. There is NO target count.\n"
    '- Each conflict object: {"between": ["owner_A", "owner_B"], '
    '"issue": "describe the disagreement and how you resolved it"}.\n\n'
    "Other rules:\n"
    "- Honour every BLOCKING constraint. If two blockers conflict, raise it in "
    "  conflicts and pick the path that matches your axis priority.\n"
    "- Each step must have a rollback. 'redeploy_previous' is OK only when literally "
    "  applicable.\n"
    "- Don't invent constraints not in the input.\n"
    "- 5-15 steps. Wrap the JSON in a ```json fenced block."
)

_BASE_TAIL = _BASE_TAIL_CORE + _load_runtime_tail_extra()


_SCHEMA = (
    "Your output is a JSON object:\n\n"
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
    '  "conflicts": []\n'
    "}\n"
)


PARETO_SEQUENCERS: dict[str, Persona] = {
    "aggressive": Persona(
        name="Sequencer_Aggressive",
        role="rollout plan synthesiser (speed-optimised)",
        system_prompt=(
            "You are a rollout plan synthesiser optimising for **wall-clock speed**.\n"
            "You receive merged stakeholder constraints and produce a plan that:\n"
            "- Parallelises wherever the dependency graph allows.\n"
            "- Collapses sequential gates that can run concurrently.\n"
            "- Prefers `monitor:` gates over `approval:` gates so the plan is "
            "self-driving.\n"
            "- Accepts more aggressive rollback complexity in exchange for fewer "
            "checkpoints.\n"
            "- Keeps step count low (5-9 if possible).\n\n" + _SCHEMA + _BASE_TAIL
        ),
    ),
    "balanced": Persona(
        name="Sequencer_Balanced",
        role="rollout plan synthesiser (default)",
        system_prompt=(
            "You are a rollout plan synthesiser optimising for **balanced risk/speed**.\n"
            "You receive merged stakeholder constraints and produce a plan that:\n"
            "- Honours every BLOCKING constraint without inventing extras.\n"
            "- Adds a single safety gate after each major irreversible step.\n"
            "- Keeps step count moderate (8-12).\n\n" + _SCHEMA + _BASE_TAIL
        ),
    ),
    "conservative": Persona(
        name="Sequencer_Conservative",
        role="rollout plan synthesiser (safety-optimised)",
        system_prompt=(
            "You are a rollout plan synthesiser optimising for **minimum blast "
            "radius and easy rollback**.\n"
            "You receive merged stakeholder constraints and produce a plan that:\n"
            "- Sequentialises wherever there is any risk of cross-step interaction.\n"
            "- Adds explicit checkpoint gates between every irreversible step.\n"
            "- Prefers feature-flag-controlled rollouts so cutover is a config flip.\n"
            "- Adds soak windows (e.g. 24h monitor:error_rate<X) before each "
            "default change.\n"
            "- Keeps every rollback to a single concrete inverse step; no compound "
            "rollbacks.\n"
            "- Accepts higher step count (12-18) in exchange for safety.\n\n"
            + _SCHEMA + _BASE_TAIL
        ),
    ),
}
