"""Core data primitives for the continual-learning engine.

The central object is the ``Trajectory`` -- mirroring trajectory.ai's design,
a trajectory fuses two things that are usually kept apart:

    trace      -> what the agent did   (messages, tool calls, the response)
    telemetry  -> how the user reacted (accept / edit / reject / rerun / rating)

Most observability stacks log only the trace and throw the telemetry away.
The telemetry is the learning signal. Keeping them together in one typed
record is what makes continual learning possible.

Everything here is stdlib-only so the engine runs with zero installs.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Iterable


class SignalKind(str, Enum):
    """The kinds of user telemetry we can learn from."""

    ACCEPT = "accept"   # user took the output as-is        -> positive signal
    EDIT = "edit"       # user fixed the output             -> richest signal (a correction)
    REJECT = "reject"   # user discarded the output         -> negative signal
    RERUN = "rerun"     # user asked again (implicit reject)-> negative signal
    RATING = "rating"   # explicit thumbs / score           -> scalar signal


@dataclass
class Message:
    role: str  # "system" | "user" | "assistant" | "tool"
    content: str
    # Structured features the response exhibits. For natural-language outputs
    # this can be empty; the simulated environment uses it to make learning
    # measurable and deterministic (see environment.py).
    features: list[str] = field(default_factory=list)


@dataclass
class ToolCall:
    name: str
    args: dict[str, Any] = field(default_factory=dict)
    result: Any = None


@dataclass
class TelemetrySignal:
    """A single user reaction attached to a trajectory."""

    kind: SignalKind
    # For EDIT signals: the corrected content the user produced. The diff
    # between the agent's output and this is the most valuable training signal.
    edited_content: str | None = None
    edited_features: list[str] | None = None
    rating: float | None = None  # for RATING signals, typically in [-1, 1]
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Trajectory:
    """trace + telemetry, the unit of continual learning."""

    # --- trace ---
    context: str                       # the domain / situation, e.g. "email"
    query: str                         # the user's request
    response: Message                  # the agent's output (the action taken)
    messages: list[Message] = field(default_factory=list)
    tool_calls: list[ToolCall] = field(default_factory=list)

    # --- telemetry ---
    telemetry: list[TelemetrySignal] = field(default_factory=list)
    reward: float | None = None        # scalar outcome in [0, 1] if known

    # --- bookkeeping ---
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    trace_id: str | None = None        # caller-owned id linking trace<->telemetry
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    # -- convenience --------------------------------------------------------
    def add_signal(self, signal: TelemetrySignal) -> "Trajectory":
        self.telemetry.append(signal)
        return self

    @property
    def has_correction(self) -> bool:
        return any(s.kind == SignalKind.EDIT for s in self.telemetry)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Trajectory":
        resp = d.get("response") or {}
        traj = Trajectory(
            context=d["context"],
            query=d["query"],
            response=Message(**resp) if not isinstance(resp, Message) else resp,
            messages=[Message(**m) for m in d.get("messages", [])],
            tool_calls=[ToolCall(**t) for t in d.get("tool_calls", [])],
            reward=d.get("reward"),
            id=d.get("id", uuid.uuid4().hex[:12]),
            trace_id=d.get("trace_id"),
            timestamp=d.get("timestamp", time.time()),
            metadata=d.get("metadata", {}),
        )
        for s in d.get("telemetry", []):
            traj.telemetry.append(
                TelemetrySignal(
                    kind=SignalKind(s["kind"]),
                    edited_content=s.get("edited_content"),
                    edited_features=s.get("edited_features"),
                    rating=s.get("rating"),
                    timestamp=s.get("timestamp", time.time()),
                    metadata=s.get("metadata", {}),
                )
            )
        return traj


# --- JSONL store helpers ---------------------------------------------------

def write_jsonl(path: str, trajectories: Iterable[Trajectory]) -> int:
    n = 0
    with open(path, "w") as f:
        for t in trajectories:
            f.write(t.to_json() + "\n")
            n += 1
    return n


def read_jsonl(path: str) -> list[Trajectory]:
    out: list[Trajectory] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(Trajectory.from_dict(json.loads(line)))
    return out
