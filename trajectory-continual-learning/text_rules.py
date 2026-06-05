"""Objective, code-checkable rules over REAL natural-language text.

The offline proof (environment.py) scores structured feature flags. To prove the
engine works on *actual LLM text*, we need rules that can be checked mechanically
on free-form strings -- no human, no judge model, no ambiguity. That is this file.

Each domain has hidden preferences expressed as `(feature, checker, fixer)`:
  * checker(text) -> bool : is the preference satisfied in this text?
  * the feature id is what the miner turns into a lesson and the policy applies.

This doubles as the user-edit oracle for experiment_real.py: when a real model's
output fails a rule, the oracle records the violated features (the "edit"
signal), which the engine mines into lessons. Because the rules are pure code,
the resulting learning curve is fully reproducible.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from schema import Message, SignalKind, TelemetrySignal, Trajectory

# Matches the common emoji unicode blocks (emoticons, symbols, transport, etc.)
_EMOJI = re.compile(
    "[\U0001F300-\U0001FAFF\U00002600-\U000027BF\U0001F000-\U0001F0FF←-⇿⬀-⯿]"
)


def _word_count(text: str) -> int:
    return len(re.findall(r"\b[\w'-]+\b", text))


def _bullet_lines(text: str) -> int:
    return len(re.findall(r"(?m)^\s*[-*•]\s+\S", text))


@dataclass
class Rule:
    feature: str
    lesson: str                     # natural-language guideline the policy receives
    check: Callable[[str], bool]    # objective predicate on the text


# --- Hidden, context-specific preferences over real text --------------------
# These are deliberately IDIOSYNCRATIC, user-specific quirks that a strong model
# does NOT produce by default (verified live: Claude's default emails already use
# "Subject:" and "Best regards", so generic rules prove nothing). The only way to
# satisfy them is to learn *this user's* preferences from their edits -- which is
# exactly the gap trajectory.ai targets: a frozen model with good defaults still
# doesn't match a specific user until it learns from usage.
RULES: dict[str, list[Rule]] = {
    "email": [
        Rule("no_placeholders",
             "do not use bracketed placeholders like [Name] or [Your Name]; use concrete, plausible details instead",
             lambda t: re.search(r"\[[^\]\n]{1,40}\]", t) is None),
        Rule("signoff_onwards",
             "sign off with exactly 'Onwards,' (not 'Best regards' or 'Sincerely')",
             lambda t: "onwards," in t.lower()),
        Rule("has_ps",
             "end the email with a 'P.S.' line",
             lambda t: re.search(r"(?i)p\.\s?s\.", t) is not None),
        Rule("concise_70",
             "keep the whole email under 70 words",
             lambda t: _word_count(t) <= 70),
    ],
    "slack": [
        Rule("has_bullets",
             "format the update as a bulleted list (lines starting with '-')",
             lambda t: _bullet_lines(t) >= 2),
        Rule("has_emoji",
             "include at least one emoji",
             lambda t: _EMOJI.search(t) is not None),
        Rule("no_greeting",
             "do not open with a greeting like 'Hi' or 'Hey team'; jump straight to the point",
             lambda t: re.match(r"(?i)\s*(hi|hey|hello|greetings|good\s+(morning|afternoon|evening))\b", t) is None),
        Rule("mentions_oncall",
             "mention '@oncall' so the on-call engineer is notified",
             lambda t: "@oncall" in t.lower()),
    ],
}


def features_of(context: str) -> set[str]:
    return {r.feature for r in RULES[context]}


def lessons_for(context: str) -> dict[str, str]:
    return {r.feature: r.lesson for r in RULES[context]}


def check_text(context: str, text: str) -> set[str]:
    """Return the set of satisfied features for a piece of real text."""
    return {r.feature for r in RULES[context] if r.check(text)}


def evaluate_text(context: str, query: str, response: Message) -> tuple[Trajectory, float]:
    """Score real text and emit EDIT telemetry for any violated rules.

    The oracle's "edit" lists the full desired feature set; the diff vs what the
    text satisfied is exactly what the miner needs -- same contract as
    environment.py, but driven by objective checks on real strings.
    """
    required = features_of(context)
    satisfied = check_text(context, response.content)
    reward = len(satisfied & required) / len(required)

    traj = Trajectory(context=context, query=query, response=response, reward=reward)
    if satisfied >= required:
        traj.add_signal(TelemetrySignal(kind=SignalKind.ACCEPT))
    else:
        traj.add_signal(TelemetrySignal(
            kind=SignalKind.EDIT,
            edited_content="(user revised the draft to satisfy their preferences)",
            edited_features=sorted(required),
        ))
    # the miner reads response.features to compute the diff; fill from the check
    response.features = sorted(satisfied)
    return traj, reward
