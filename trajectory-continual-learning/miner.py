"""Understand: mine learning signals out of trajectories.

Two products come out of mining, matching the two ways trajectory.ai turns
usage into improvement:

  1. Lessons          -- natural-language insights extracted from corrections,
                         used by the non-parametric memory backend (no GPU).
  2. Preference pairs -- (chosen, rejected) examples for the *parametric* path
                         (DPO / RLHF offline fine-tuning), exported separately.

The richest signal is an EDIT: the diff between what the agent produced and what
the user changed it to. That diff localizes exactly what was wrong, which is far
more informative than a thumbs-down. This is the core insight of "Aligning LLM
Agents by Learning Latent Preference from User Edits" (Gao et al., 2024).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from memory import Lesson
from schema import SignalKind, Trajectory


# Human-readable rendering for known structured features. Falls back to a
# generic template for unknown features so the miner also works on real data.
_FEATURE_PHRASING = {
    "formal_greeting": "open with a formal greeting",
    "signoff_best_regards": "close with 'Best regards'",
    "no_emoji": "do not use emoji",
    "bullet_points": "format the answer as bullet points",
    "concise": "keep it concise (a few lines at most)",
    "casual_tone": "use a casual, friendly tone",
    "imperative_mood": "write the subject line in the imperative mood",
    "no_trailing_period": "do not end the subject line with a period",
    "reference_lines": "reference specific line numbers",
    "suggest_fix": "include a concrete suggested fix",
    "constructive_tone": "phrase feedback constructively",
    "cite_sources": "cite sources for factual claims",
    "step_by_step": "show the reasoning step by step",
}


def _phrase(feature: str, context: str) -> str:
    base = _FEATURE_PHRASING.get(feature, f"apply '{feature}'")
    return f"In the '{context}' context, {base}."


@dataclass
class PreferencePair:
    """A (chosen > rejected) example for offline preference optimization."""

    prompt: str
    chosen: str
    rejected: str
    context: str
    source: str


def mine_lessons(traj: Trajectory) -> list[Lesson]:
    """Extract lessons from a single trajectory's corrections.

    A lesson is created for every feature the user *added* in their edit that
    the agent had failed to produce -- i.e. the concrete fixes the user made.
    """
    lessons: list[Lesson] = []
    produced = set(traj.response.features or [])
    signature = f"{traj.context} {traj.query}"

    for sig in traj.telemetry:
        if sig.kind != SignalKind.EDIT or sig.edited_features is None:
            continue
        desired = set(sig.edited_features)
        # features the user added == what was missing == the correction
        added = desired - produced
        for feature in sorted(added):
            lessons.append(Lesson(
                text=_phrase(feature, traj.context),
                feature=feature,
                context=traj.context,
                signature=signature,
                source_trajectories=[traj.id],
            ))
    return lessons


def mine_preference_pairs(traj: Trajectory) -> list[PreferencePair]:
    """Turn corrections/rejections into (chosen, rejected) pairs for DPO."""
    pairs: list[PreferencePair] = []
    prompt = f"[{traj.context}] {traj.query}"
    rejected = traj.response.content
    for sig in traj.telemetry:
        if sig.kind == SignalKind.EDIT and sig.edited_content:
            pairs.append(PreferencePair(
                prompt=prompt, chosen=sig.edited_content,
                rejected=rejected, context=traj.context, source=traj.id,
            ))
    return pairs


def mine_batch(trajectories: Iterable[Trajectory]):
    """Convenience: mine lessons + preference pairs from many trajectories."""
    all_lessons: list[Lesson] = []
    all_pairs: list[PreferencePair] = []
    for t in trajectories:
        all_lessons.extend(mine_lessons(t))
        all_pairs.extend(mine_preference_pairs(t))
    return all_lessons, all_pairs
