"""The control-plane brain: ingest -> learn -> govern -> serve guidance.

Wraps the store and a preference miner. Used directly by the SDK in local mode,
and wrapped by the FastAPI server in hosted mode -- same logic either way.
"""

from __future__ import annotations

from typing import Optional

from .miner import Backend, default_backend, heuristic_preferences, infer_preferences
from .schema import Preference, Signal, Status, Trajectory
from .store import Store


def format_guidance(prefs: list[str]) -> str:
    if not prefs:
        return ""
    body = "\n".join(f"- {p}" for p in prefs)
    return ("Learned preferences for this user (follow them exactly):\n" + body)


class Engine:
    def __init__(self, store: Store, backend: Optional[Backend] = None,
                 project: str = "default", auto_approve: bool = False,
                 min_support: int = 1):
        self.store = store
        self.backend = backend if backend is not None else default_backend()
        self.project = project
        self.auto_approve = auto_approve
        self.min_support = min_support
        self.store.ensure_project(project)

    # -- ingest -------------------------------------------------------------
    def log(self, user: str, task: str, query: str, response: str,
            meta: Optional[dict] = None) -> Trajectory:
        return self.store.add_trajectory(Trajectory(
            user=user, task=task, query=query, response=response,
            project=self.project, meta=meta or {}))

    def record_edit(self, traj_id: str, edited_text: str) -> None:
        self.store.set_signal(traj_id, Signal.EDIT, edited_text=edited_text)

    def record_accept(self, traj_id: str) -> None:
        self.store.set_signal(traj_id, Signal.ACCEPT)

    def record_reject(self, traj_id: str) -> None:
        self.store.set_signal(traj_id, Signal.REJECT)

    # -- serve (inference time) --------------------------------------------
    def guidance(self, user: str, task: str) -> str:
        prefs = self.store.preferences(self.project, user, task, Status.APPROVED)
        return format_guidance([p.text for p in prefs])

    def approved_preferences(self, user: str, task: str) -> list[Preference]:
        return self.store.preferences(self.project, user, task, Status.APPROVED)

    # -- learn --------------------------------------------------------------
    def learn(self, user: str, task: str) -> list[Preference]:
        """Infer preferences from this user's edits and stage them for review."""
        edits = self.store.edits(self.project, user, task)
        if not edits:
            return []
        if self.backend is not None:
            try:
                texts = infer_preferences(self.backend, task, edits)
            except Exception:
                texts = heuristic_preferences(edits)
        else:
            texts = heuristic_preferences(edits)

        result: list[Preference] = []
        for txt in texts:
            pref = Preference(user=user, task=task, text=txt, project=self.project,
                              source_ids=[e.id for e in edits],
                              status=Status.PENDING)
            stored, is_new = self.store.upsert_preference(pref)
            # auto-approve path (self-host convenience): promote once supported
            if self.auto_approve:
                fresh = self._find(stored.id) or stored
                if fresh.support >= self.min_support and fresh.status == Status.PENDING:
                    self.store.set_status(fresh.id, Status.APPROVED, by="auto")
            result.append(stored)
        return result

    def learn_all(self) -> int:
        n = 0
        for user, task in self.store.tasks_with_edits(self.project):
            n += len(self.learn(user, task))
        return n

    # -- govern -------------------------------------------------------------
    def pending(self) -> list[Preference]:
        return self.store.pending(self.project)

    def approve(self, pref_id: str, by: str = "reviewer") -> None:
        self.store.set_status(pref_id, Status.APPROVED, by=by)

    def reject(self, pref_id: str, by: str = "reviewer") -> None:
        self.store.set_status(pref_id, Status.REJECTED, by=by)

    def audit(self, limit: int = 100):
        return self.store.audit_log(self.project, limit)

    def _find(self, pref_id: str) -> Optional[Preference]:
        for p in self.store.pending(self.project):
            if p.id == pref_id:
                return p
        return None
