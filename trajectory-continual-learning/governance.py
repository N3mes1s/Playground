"""Steer / govern: human-in-the-loop approval and a full audit trail.

trajectory.ai stresses that nothing reaches production without approval, and
that every change is auditable -- you can see exactly what changed, why, and the
performance impact. This module is that control surface.

Every candidate lesson passes through an ApprovalGate before it can enter the
live memory, and every decision is written to an append-only audit log.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

from memory import Lesson


class Decision(str, Enum):
    APPROVED = "approved"
    REJECTED = "rejected"
    HELD = "held"


@dataclass
class AuditEntry:
    timestamp: float
    decision: Decision
    lesson_text: str
    feature: str
    context: str
    support: int
    reason: str
    source_trajectories: list[str] = field(default_factory=list)

    def to_json(self) -> str:
        d = self.__dict__.copy()
        d["decision"] = self.decision.value
        return json.dumps(d)


# A policy decides ACCEPT/REJECT/HOLD for a candidate lesson.
ApprovalPolicy = Callable[[Lesson], tuple[Decision, str]]


def min_support_policy(threshold: int = 1) -> ApprovalPolicy:
    """Auto-approve lessons reinforced at least `threshold` times.

    Raising the threshold trades faster learning for fewer spurious updates
    (a lesson learned from a single noisy edit may be a fluke; one seen 3x is
    probably a real preference).
    """
    def policy(lesson: Lesson) -> tuple[Decision, str]:
        if lesson.support >= threshold:
            return Decision.APPROVED, f"support {lesson.support} >= {threshold}"
        return Decision.HELD, f"support {lesson.support} < {threshold}"
    return policy


class ApprovalGate:
    """Gate candidate lessons into production, with an audit log."""

    def __init__(self, policy: Optional[ApprovalPolicy] = None,
                 audit_path: Optional[str] = None):
        self.policy = policy or min_support_policy(1)
        self.audit_path = audit_path
        self.log: list[AuditEntry] = []

    def review(self, lesson: Lesson) -> Decision:
        decision, reason = self.policy(lesson)
        entry = AuditEntry(
            timestamp=time.time(),
            decision=decision,
            lesson_text=lesson.text,
            feature=lesson.feature,
            context=lesson.context,
            support=lesson.support,
            reason=reason,
            source_trajectories=list(lesson.source_trajectories),
        )
        self.log.append(entry)
        if self.audit_path:
            with open(self.audit_path, "a") as f:
                f.write(entry.to_json() + "\n")
        return decision

    def summary(self) -> dict:
        out = {d.value: 0 for d in Decision}
        for e in self.log:
            out[e.decision.value] += 1
        return out
