"""A non-parametric continual-learning memory (retrieval-augmented).

This is the "Learn" backend that needs no GPU and works with any closed model.
It is the small-scale analogue of what trajectory.ai does to model *weights*:
instead of changing parameters, we accumulate learned lessons and retrieve the
relevant ones at inference time, injecting them into the policy's context.

Why this is a legitimate form of continual learning:
  * ExpeL (Zhao et al., 2024) -- agents extract natural-language insights from
    experience and reuse them as in-context guidance, no weight updates.
  * CIPHER / PRELUDE (Gao et al., 2024) -- infer latent user preferences from
    edits, store them, and retrieve from the k-closest contexts at test time.

Retrieval here is a dependency-free Jaccard over context signatures, which is
enough to demonstrate generalization: a never-before-seen query in an already
learned domain still retrieves that domain's lessons.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field, asdict
from typing import Iterable


_WORD = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> set[str]:
    return set(_WORD.findall(text.lower()))


@dataclass
class Lesson:
    """A learned, reusable piece of knowledge."""

    text: str                      # human-readable insight (what the model "learned")
    feature: str                   # structured handle the policy can act on
    context: str                   # domain it was learned in
    signature: str                 # context + query tokens it was learned from
    support: int = 1               # how many corrections reinforced this lesson
    source_trajectories: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def key(self) -> tuple[str, str]:
        return (self.context, self.feature)


class LessonMemory:
    """Append/merge store of lessons with similarity retrieval."""

    def __init__(self) -> None:
        self._lessons: dict[tuple[str, str], Lesson] = {}

    def __len__(self) -> int:
        return len(self._lessons)

    def all(self) -> list[Lesson]:
        return list(self._lessons.values())

    def upsert(self, lesson: Lesson) -> bool:
        """Add a lesson, or reinforce an existing one. Returns True if new."""
        k = lesson.key()
        if k in self._lessons:
            existing = self._lessons[k]
            existing.support += 1
            existing.source_trajectories.extend(lesson.source_trajectories)
            return False
        self._lessons[k] = lesson
        return True

    def retrieve(self, context: str, query: str, k: int = 5) -> list[Lesson]:
        """Top-k lessons by signature similarity to the current context.

        Domain match dominates the signature, so lessons learned in a domain
        transfer to unseen queries in that same domain -- the property that
        makes this generalize rather than memorize.
        """
        sig = _tokens(context + " " + query)
        scored: list[tuple[float, Lesson]] = []
        for lesson in self._lessons.values():
            ls = _tokens(lesson.signature)
            if not ls:
                continue
            inter = len(sig & ls)
            union = len(sig | ls) or 1
            jaccard = inter / union
            # strong boost for exact domain match (the dominant retrieval cue)
            domain_bonus = 1.0 if lesson.context == context else 0.0
            score = domain_bonus + jaccard
            if score > 0:
                scored.append((score, lesson))
        scored.sort(key=lambda x: (-x[0], -x[1].support))
        return [l for _, l in scored[:k]]

    # -- persistence --------------------------------------------------------
    def save(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump([asdict(l) for l in self._lessons.values()], f, indent=2)

    @staticmethod
    def load(path: str) -> "LessonMemory":
        m = LessonMemory()
        with open(path) as f:
            for d in json.load(f):
                lesson = Lesson(**d)
                m._lessons[lesson.key()] = lesson
        return m
