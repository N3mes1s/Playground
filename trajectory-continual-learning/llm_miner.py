"""LLM-based preference inference -- the intelligent "Understand" step.

The structural miner (miner.py) needs the oracle to hand it the exact violated
feature ids. That is a shortcut. The real trajectory.ai / CIPHER idea is harder
and more useful: look at how the user *edited* a draft (before -> after) and
INFER, in natural language, the latent preference they revealed -- with no access
to any rule list. See "Aligning LLM Agents by Learning Latent Preference from
User Edits" (Gao et al., 2024, arXiv:2404.15269).

This module asks an LLM to do exactly that. The inferred guidelines are stored as
lessons and reused; we then prove they actually help (the code oracle scores the
resulting drafts), which is the real test of inference quality -- the lesson does
not need to match the hidden rule's wording, only to be useful.
"""

from __future__ import annotations

import hashlib
import re

from memory import Lesson

_INFER_SYSTEM = (
    "You compare an AI assistant's draft (BEFORE) with the user's edited version "
    "(AFTER) and infer the user's general, reusable writing preferences for this "
    "context. Output up to 4 short imperative guidelines, ONE per line, each "
    "capturing a single preference the edit reveals and worth applying to future "
    "drafts. Be specific and concrete (e.g. exact sign-off, formatting, length). "
    "Output ONLY the guideline lines, no numbering, no preamble, no commentary."
)


def _slug(text: str) -> str:
    """Stable id for a lesson so identical inferences reinforce, not duplicate."""
    norm = re.sub(r"[^a-z0-9 ]", "", text.lower()).strip()
    norm = re.sub(r"\s+", " ", norm)
    return "inf_" + hashlib.sha1(norm.encode()).hexdigest()[:10]


def _clean(line: str) -> str:
    return re.sub(r"^\s*(?:[-*•]|\d+[.)])\s*", "", line).strip().rstrip(".")


_CONSOLIDATE_SYSTEM = (
    "You are consolidating a messy list of preference guidelines that were inferred "
    "one-at-a-time for a single writing context. Produce a clean, canonical set: "
    "merge duplicates and near-duplicates, DROP vague, one-off, or contradictory "
    "items, and keep only specific, concrete, reusable guidelines (exact sign-offs, "
    "formatting, length, required mentions). Output up to 6 short imperative "
    "guidelines, ONE per line, no numbering, no preamble."
)


def consolidate(backend, context: str, lessons: list[Lesson]) -> list[Lesson]:
    """Reflection/consolidation pass over accumulated lessons.

    Online inference is noisy -- it produces duplicates and the occasional
    off-target guideline that pollutes memory. Periodically consolidating the
    store into a canonical set is the memory analogue of reflection in Generative
    Agents (Park et al., 2023) and A-MEM-style note merging. It is also the
    governance lever trajectory.ai stresses: curate before it reaches production.
    """
    if not lessons:
        return []
    listing = "\n".join(f"- {l.text}" for l in lessons)
    raw = backend.complete(
        f"Context: {context}\nInferred guidelines so far:\n{listing}\n\n"
        f"Consolidate them.", _CONSOLIDATE_SYSTEM)
    out: list[Lesson] = []
    for line in raw.splitlines():
        text = _clean(line)
        if len(text) < 5:
            continue
        out.append(Lesson(text=text, feature=_slug(text), context=context,
                          signature=context))
        if len(out) >= 6:
            break
    return out


def _parse_lessons(raw: str, context: str, signature: str,
                   max_lessons: int) -> list[Lesson]:
    lessons: list[Lesson] = []
    for line in raw.splitlines():
        text = _clean(line)
        if len(text) < 5:
            continue
        lessons.append(Lesson(text=text, feature=_slug(text), context=context,
                              signature=signature, source_trajectories=[]))
        if len(lessons) >= max_lessons:
            break
    return lessons


def infer_lessons(backend, context: str, query: str,
                  before: str, after: str, max_lessons: int = 4) -> list[Lesson]:
    """Infer reusable lessons from a single before/after edit."""
    prompt = (
        f"Context: {context}\nTask: {query}\n\n"
        f"BEFORE (assistant draft):\n{before}\n\n"
        f"AFTER (user's edited version):\n{after}\n\n"
        f"What general preferences did the user reveal? List the guidelines."
    )
    raw = backend.complete(prompt, _INFER_SYSTEM)
    return _parse_lessons(raw, context, f"{context} {query}", max_lessons)


_INFER_BATCH_SYSTEM = (
    "You infer a user's CONSISTENT writing preferences for one context by comparing "
    "several drafts (BEFORE) with the user's edits (AFTER). Identify only the "
    "preferences that RECUR across the examples -- concrete, reusable rules (exact "
    "sign-offs, formatting, length limits, required mentions, things to avoid). "
    "Ignore one-off changes specific to a single message. Output up to 6 short "
    "imperative guidelines, ONE per line, no numbering, no preamble."
)


def infer_lessons_aggregate(backend, context: str, pairs, max_lessons: int = 6):
    """CIPHER-style aggregation: infer preferences from ALL of a context's edits.

    `pairs` is a list of (query, before, after). Seeing the full history at once
    makes recurring preferences stand out and washes out one-off noise -- far more
    robust than inferring per-edit and merging afterwards. (Gao et al., 2024.)
    """
    blocks = []
    for i, (q, before, after) in enumerate(pairs, 1):
        blocks.append(f"--- Example {i} (task: {q}) ---\n"
                      f"BEFORE:\n{before}\n\nAFTER:\n{after}\n")
    prompt = (f"Context: {context}\n\n" + "\n".join(blocks) +
              "\nList the user's consistent preferences for this context.")
    raw = backend.complete(prompt, _INFER_BATCH_SYSTEM)
    return _parse_lessons(raw, context, context, max_lessons)
