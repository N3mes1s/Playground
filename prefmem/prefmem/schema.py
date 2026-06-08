"""Core types for the preference-memory layer.

A `Trajectory` is one agent interaction (trace) plus how the user reacted
(telemetry). Edits are the strongest signal -- they tell us not just *that* an
output was wrong but *how* the user wanted it. A `Preference` is a learned,
reusable guideline mined from those edits; it carries a governance `status` so
nothing reaches production without review.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class Signal(str, Enum):
    ACCEPT = "accept"   # used as-is        (positive)
    EDIT = "edit"       # user fixed it     (richest)
    REJECT = "reject"   # discarded         (negative)
    RERUN = "rerun"     # asked again       (negative)


class Status(str, Enum):
    PENDING = "pending"     # mined, awaiting review
    APPROVED = "approved"   # live -- injected into prompts
    REJECTED = "rejected"   # reviewer declined


def _id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


@dataclass
class Trajectory:
    user: str
    task: str                     # the context/agent/tool name, e.g. "email"
    query: str
    response: str
    project: str = "default"
    signal: Optional[Signal] = None
    edited_text: Optional[str] = None
    rating: Optional[float] = None
    id: str = field(default_factory=lambda: _id("trj"))
    created_at: float = field(default_factory=time.time)
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        if self.signal is not None:
            d["signal"] = self.signal.value
        return d


@dataclass
class Preference:
    user: str
    task: str
    text: str                      # the learned guideline (natural language)
    project: str = "default"
    status: Status = Status.PENDING
    support: int = 1               # how many edits reinforced it
    source_ids: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: _id("pref"))
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d
