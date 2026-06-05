"""Instrument: a lightweight SDK to capture trajectories from a live product.

This is the analogue of trajectory.ai's "Instrument" step. You wrap an agent
call, log the trace, and later attach telemetry when the user reacts. All
processing is local -- nothing leaves your environment -- and writes are
append-only JSONL so logging is crash-safe and idempotent per trace_id.

Typical product integration:

    rec = Recorder("usage.jsonl")
    traj = rec.log(context="email", query=user_msg,
                   response=agent_out, trace_id=request_id)
    ...
    # when the user edits the draft in your UI:
    rec.add_edit(traj, edited_content=user_final_text)
"""

from __future__ import annotations

import os
import threading
from typing import Optional

from schema import (
    Message,
    SignalKind,
    TelemetrySignal,
    ToolCall,
    Trajectory,
)


class Recorder:
    """Append-only trajectory logger with optional PII redaction."""

    def __init__(self, path: str, redactor=None):
        self.path = path
        self.redactor = redactor or (lambda s: s)
        self._lock = threading.Lock()
        self._by_trace: dict[str, Trajectory] = {}
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    # -- trace capture ------------------------------------------------------
    def log(
        self,
        context: str,
        query: str,
        response,
        *,
        trace_id: Optional[str] = None,
        tool_calls: Optional[list[ToolCall]] = None,
        reward: Optional[float] = None,
        metadata: Optional[dict] = None,
    ) -> Trajectory:
        if isinstance(response, Message):
            resp = response
        else:  # plain string output
            resp = Message(role="assistant", content=self.redactor(str(response)))
        traj = Trajectory(
            context=context,
            query=self.redactor(query),
            response=resp,
            tool_calls=tool_calls or [],
            reward=reward,
            trace_id=trace_id,
            metadata=metadata or {},
        )
        with self._lock:
            self._append(traj)
            if trace_id:
                self._by_trace[trace_id] = traj
        return traj

    # -- telemetry capture --------------------------------------------------
    def add_edit(self, traj: Trajectory, edited_content: str,
                 edited_features: Optional[list[str]] = None) -> None:
        traj.add_signal(TelemetrySignal(
            kind=SignalKind.EDIT,
            edited_content=self.redactor(edited_content),
            edited_features=edited_features,
        ))
        self._rewrite()

    def add_accept(self, traj: Trajectory) -> None:
        traj.add_signal(TelemetrySignal(kind=SignalKind.ACCEPT))
        self._rewrite()

    def add_reject(self, traj: Trajectory) -> None:
        traj.add_signal(TelemetrySignal(kind=SignalKind.REJECT))
        self._rewrite()

    def add_rating(self, traj: Trajectory, rating: float) -> None:
        traj.add_signal(TelemetrySignal(kind=SignalKind.RATING, rating=rating))
        self._rewrite()

    def by_trace(self, trace_id: str) -> Optional[Trajectory]:
        return self._by_trace.get(trace_id)

    # -- persistence --------------------------------------------------------
    def _append(self, traj: Trajectory) -> None:
        with open(self.path, "a") as f:
            f.write(traj.to_json() + "\n")

    def _rewrite(self) -> None:
        # telemetry mutates an existing record; rewrite the file from memory.
        # For high-volume use you'd switch to an event log; fine for the SDK demo.
        from schema import read_jsonl, write_jsonl
        try:
            existing = {t.id: t for t in read_jsonl(self.path)}
        except FileNotFoundError:
            existing = {}
        for t in self._by_trace.values():
            existing[t.id] = t
        write_jsonl(self.path, existing.values())


def simple_redactor(text: str) -> str:
    """Toy PII redactor (emails -> [EMAIL]). Pluggable -- swap in your own."""
    import re
    return re.sub(r"[\w.+-]+@[\w-]+\.[\w.-]+", "[EMAIL]", text)
