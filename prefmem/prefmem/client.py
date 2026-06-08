"""The PrefMem SDK -- the developer surface. Dependency-free (stdlib only).

Wrap your agent in ~4 lines:

    pm = PrefMem(store="prefmem.db")            # local, or PrefMem(api_url=..., api_key=...)
    ctx = pm.context(user="u1", task="email")

    prompt = ctx.guidance() + "\n\n" + your_user_message   # inject learned prefs
    response = your_llm(prompt)
    turn = ctx.log(query=your_user_message, response=response)

    turn.edit(user_final_text)   # capture the signal when the user edits
    pm.learn(user="u1", task="email")            # mine preferences (-> pending review)

Local mode talks straight to a SQLite store + the inference engine. Hosted mode
sends the same calls to a PrefMem control-plane over HTTP.
"""

from __future__ import annotations

import json
from typing import Optional
from urllib import error, request


class Turn:
    def __init__(self, client: "PrefMem", traj_id: str):
        self.client = client
        self.id = traj_id

    def edit(self, final_text: str) -> None:
        self.client._signal(self.id, "edit", edited_text=final_text)

    def accept(self) -> None:
        self.client._signal(self.id, "accept")

    def reject(self) -> None:
        self.client._signal(self.id, "reject")


class Context:
    def __init__(self, client: "PrefMem", user: str, task: str):
        self.client = client
        self.user = user
        self.task = task

    def guidance(self) -> str:
        """Approved learned preferences, ready to drop into your system prompt."""
        return self.client._guidance(self.user, self.task)

    def preferences(self) -> list[str]:
        return self.client._approved(self.user, self.task)

    def log(self, query: str, response: str, meta: Optional[dict] = None) -> Turn:
        tid = self.client._log(self.user, self.task, query, response, meta or {})
        return Turn(self.client, tid)


class PrefMem:
    def __init__(self, store: str = "prefmem.db", project: str = "default",
                 backend=None, auto_approve: bool = False,
                 api_url: Optional[str] = None, api_key: Optional[str] = None):
        self.project = project
        self.api_url = api_url.rstrip("/") if api_url else None
        self.api_key = api_key
        if self.api_url is None:               # local mode
            from .engine import Engine
            from .store import Store
            self._engine = Engine(Store(store), backend=backend, project=project,
                                  auto_approve=auto_approve)
        else:
            self._engine = None                 # hosted mode

    # -- public API ---------------------------------------------------------
    def context(self, user: str, task: str) -> Context:
        return Context(self, user, task)

    def learn(self, user: str, task: str) -> list[dict]:
        if self._engine:
            return [p.to_dict() for p in self._engine.learn(user, task)]
        return self._post("/v1/learn", {"user": user, "task": task})["preferences"]

    def pending(self) -> list[dict]:
        if self._engine:
            return [p.to_dict() for p in self._engine.pending()]
        return self._get("/v1/preferences/pending")["preferences"]

    def approve(self, pref_id: str) -> None:
        if self._engine:
            self._engine.approve(pref_id)
        else:
            self._post(f"/v1/preferences/{pref_id}/approve", {})

    def reject(self, pref_id: str) -> None:
        if self._engine:
            self._engine.reject(pref_id)
        else:
            self._post(f"/v1/preferences/{pref_id}/reject", {})

    def audit(self, limit: int = 100) -> list[dict]:
        if self._engine:
            return self._engine.audit(limit)
        return self._get(f"/v1/audit?limit={limit}")["audit"]

    # -- internal (used by Context/Turn) ------------------------------------
    def _log(self, user, task, query, response, meta) -> str:
        if self._engine:
            return self._engine.log(user, task, query, response, meta).id
        return self._post("/v1/trajectories",
                          {"user": user, "task": task, "query": query,
                           "response": response, "meta": meta})["id"]

    def _signal(self, traj_id, kind, edited_text=None, rating=None) -> None:
        if self._engine:
            if kind == "edit":
                self._engine.record_edit(traj_id, edited_text)
            elif kind == "accept":
                self._engine.record_accept(traj_id)
            elif kind == "reject":
                self._engine.record_reject(traj_id)
        else:
            self._post(f"/v1/trajectories/{traj_id}/signal",
                       {"kind": kind, "edited_text": edited_text, "rating": rating})

    def _guidance(self, user, task) -> str:
        if self._engine:
            return self._engine.guidance(user, task)
        return self._get(f"/v1/guidance?user={user}&task={task}")["guidance"]

    def _approved(self, user, task) -> list[str]:
        if self._engine:
            return [p.text for p in self._engine.approved_preferences(user, task)]
        return self._get(f"/v1/preferences?user={user}&task={task}&status=approved")["preferences"]

    # -- http helpers -------------------------------------------------------
    def _headers(self):
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def _post(self, path, body) -> dict:
        req = request.Request(self.api_url + path, data=json.dumps(body).encode(),
                              headers=self._headers(), method="POST")
        return self._send(req)

    def _get(self, path) -> dict:
        req = request.Request(self.api_url + path, headers=self._headers())
        return self._send(req)

    @staticmethod
    def _send(req) -> dict:
        try:
            with request.urlopen(req, timeout=30) as r:
                return json.loads(r.read())
        except error.HTTPError as e:
            raise RuntimeError(f"PrefMem API error {e.code}: {e.read().decode()[:200]}")
