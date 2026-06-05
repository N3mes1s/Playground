"""A reproducible environment with hidden user preferences.

This is the testbed that lets us *prove* continual learning works. It follows
the setup of "Aligning LLM Agents by Learning Latent Preference from User Edits"
(Gao et al., 2024): there is a ground-truth latent preference per domain that the
agent does NOT know. When the agent's output violates it, the simulated user
silently *edits* the output to fix it -- producing exactly the EDIT telemetry our
engine learns from.

The agent can only succeed by mining those edits into lessons and reusing them.
Nothing about the hidden rules is visible to the policy backend.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from schema import Message, SignalKind, TelemetrySignal, Trajectory


# Hidden ground-truth: each domain requires a set of features. The policy must
# discover these purely from user edits.
HIDDEN_PREFERENCES: dict[str, set[str]] = {
    "email":        {"formal_greeting", "signoff_best_regards", "no_emoji"},
    "slack":        {"concise", "casual_tone", "bullet_points"},
    "commit_msg":   {"imperative_mood", "no_trailing_period", "concise"},
    "code_review":  {"reference_lines", "suggest_fix", "constructive_tone"},
    "research_qa":  {"cite_sources", "step_by_step"},
}

# A few example queries per domain so retrieval must generalize across unseen
# wordings within a domain rather than memorize exact strings.
QUERIES: dict[str, list[str]] = {
    "email":       ["draft a note to the team", "reply to the client", "ask for an extension"],
    "slack":       ["share the deploy status", "summarize the standup", "ping about the bug"],
    "commit_msg":  ["message for the auth fix", "message for the refactor", "message for the docs"],
    "code_review": ["review this PR", "comment on the diff", "feedback on the patch"],
    "research_qa": ["explain transformers", "what causes forgetting", "compare DPO and PPO"],
}

# Held-out queries never shown during training -- used to prove the engine
# generalizes (retrieves the right lessons for *unseen* wordings in a domain)
# rather than memorizing exact training strings.
HOLDOUT_QUERIES: dict[str, list[str]] = {
    "email":       ["write a follow-up to the vendor", "decline the meeting politely"],
    "slack":       ["announce the release", "ask who owns the pipeline"],
    "commit_msg":  ["message for the perf tuning", "message for the test suite"],
    "code_review": ["assess the new module", "thoughts on this refactor"],
    "research_qa": ["explain LoRA", "why does RLHF need a reward model"],
}


@dataclass
class Outcome:
    trajectory: Trajectory
    reward: float
    satisfied: int
    required: int


class PreferenceEnvironment:
    """Generates tasks and acts as the user oracle that edits bad outputs."""

    def __init__(self, seed: int = 0):
        self._rng = random.Random(seed)
        self.domains = list(HIDDEN_PREFERENCES.keys())

    def sample_task(self) -> tuple[str, str]:
        domain = self._rng.choice(self.domains)
        query = self._rng.choice(QUERIES[domain])
        return domain, query

    def evaluate(self, context: str, query: str, response: Message) -> Outcome:
        """Score the response and, if imperfect, emit an EDIT (the user's fix)."""
        required = HIDDEN_PREFERENCES[context]
        produced = set(response.features or [])
        satisfied = produced & required
        reward = len(satisfied) / len(required)

        traj = Trajectory(context=context, query=query, response=response,
                          reward=reward)

        if satisfied == required:
            # user is happy, takes it as-is -> positive signal
            traj.add_signal(TelemetrySignal(kind=SignalKind.ACCEPT))
        else:
            # user edits the draft to satisfy the (hidden) preference. The
            # corrected output carries the full required feature set; the diff
            # vs `produced` is what the miner turns into lessons.
            fixed = sorted(produced | required)
            traj.add_signal(TelemetrySignal(
                kind=SignalKind.EDIT,
                edited_content=f"[{context}] user-corrected: applied {fixed}",
                edited_features=fixed,
            ))
        return Outcome(trajectory=traj, reward=reward,
                       satisfied=len(satisfied), required=len(required))
