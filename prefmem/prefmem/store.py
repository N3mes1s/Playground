"""SQLite persistence for the control-plane. Stdlib only.

Holds trajectories, learned preferences (with governance status), and an
append-only audit log. Swappable for Postgres later; the interface is small.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Optional

from .schema import Preference, Signal, Status, Trajectory

_SCHEMA = """
CREATE TABLE IF NOT EXISTS trajectories (
  id TEXT PRIMARY KEY, project TEXT, user TEXT, task TEXT,
  query TEXT, response TEXT, signal TEXT, edited_text TEXT, rating REAL,
  created_at REAL, meta TEXT
);
CREATE INDEX IF NOT EXISTS ix_trj ON trajectories(project, user, task, signal);
CREATE TABLE IF NOT EXISTS preferences (
  id TEXT PRIMARY KEY, project TEXT, user TEXT, task TEXT, text TEXT,
  status TEXT, support INTEGER, source_ids TEXT, created_at REAL
);
CREATE INDEX IF NOT EXISTS ix_pref ON preferences(project, user, task, status);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, project TEXT, ts REAL,
  action TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS projects (name TEXT PRIMARY KEY, api_key TEXT);
"""


class Store:
    def __init__(self, path: str = "prefmem.db"):
        self.path = path
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(_SCHEMA)
        self._db.commit()

    # -- projects / auth ----------------------------------------------------
    def ensure_project(self, name: str, api_key: Optional[str] = None) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR IGNORE INTO projects(name, api_key) VALUES(?,?)",
                (name, api_key))
            self._db.commit()

    def project_for_key(self, api_key: str) -> Optional[str]:
        row = self._db.execute(
            "SELECT name FROM projects WHERE api_key=?", (api_key,)).fetchone()
        return row["name"] if row else None

    # -- trajectories -------------------------------------------------------
    def add_trajectory(self, t: Trajectory) -> Trajectory:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO trajectories VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (t.id, t.project, t.user, t.task, t.query, t.response,
                 t.signal.value if t.signal else None, t.edited_text, t.rating,
                 t.created_at, json.dumps(t.meta)))
            self._db.commit()
        return t

    def set_signal(self, traj_id: str, signal: Signal,
                   edited_text: Optional[str] = None,
                   rating: Optional[float] = None) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE trajectories SET signal=?, edited_text=?, rating=? WHERE id=?",
                (signal.value, edited_text, rating, traj_id))
            self._db.commit()

    def edits(self, project: str, user: str, task: str, limit: int = 50) -> list[Trajectory]:
        rows = self._db.execute(
            "SELECT * FROM trajectories WHERE project=? AND user=? AND task=? "
            "AND signal=? ORDER BY created_at DESC LIMIT ?",
            (project, user, task, Signal.EDIT.value, limit)).fetchall()
        return [self._row_to_traj(r) for r in rows]

    def tasks_with_edits(self, project: str) -> list[tuple[str, str]]:
        rows = self._db.execute(
            "SELECT DISTINCT user, task FROM trajectories WHERE project=? AND signal=?",
            (project, Signal.EDIT.value)).fetchall()
        return [(r["user"], r["task"]) for r in rows]

    # -- preferences --------------------------------------------------------
    def upsert_preference(self, p: Preference) -> tuple[Preference, bool]:
        """Insert, or reinforce an existing identical preference. (pref, is_new)."""
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM preferences WHERE project=? AND user=? AND task=? "
                "AND text=?", (p.project, p.user, p.task, p.text)).fetchone()
            if row:
                self._db.execute(
                    "UPDATE preferences SET support=support+1 WHERE id=?", (row["id"],))
                self._db.commit()
                return self._row_to_pref(row), False
            self._db.execute(
                "INSERT INTO preferences VALUES(?,?,?,?,?,?,?,?,?)",
                (p.id, p.project, p.user, p.task, p.text, p.status.value,
                 p.support, json.dumps(p.source_ids), p.created_at))
            self._db.commit()
            return p, True

    def preferences(self, project: str, user: str, task: str,
                    status: Optional[Status] = None) -> list[Preference]:
        q = "SELECT * FROM preferences WHERE project=? AND user=? AND task=?"
        args: list = [project, user, task]
        if status:
            q += " AND status=?"; args.append(status.value)
        q += " ORDER BY support DESC, created_at DESC"
        return [self._row_to_pref(r) for r in self._db.execute(q, args).fetchall()]

    def pending(self, project: str) -> list[Preference]:
        rows = self._db.execute(
            "SELECT * FROM preferences WHERE project=? AND status=? ORDER BY created_at",
            (project, Status.PENDING.value)).fetchall()
        return [self._row_to_pref(r) for r in rows]

    def set_status(self, pref_id: str, status: Status, by: str = "reviewer") -> None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM preferences WHERE id=?", (pref_id,)).fetchone()
            if not row:
                return
            self._db.execute("UPDATE preferences SET status=? WHERE id=?",
                             (status.value, pref_id))
            self._audit(row["project"], f"preference.{status.value}",
                        {"id": pref_id, "text": row["text"], "by": by})
            self._db.commit()

    # -- audit --------------------------------------------------------------
    def _audit(self, project: str, action: str, detail: dict) -> None:
        self._db.execute(
            "INSERT INTO audit(project, ts, action, detail) VALUES(?,?,?,?)",
            (project, time.time(), action, json.dumps(detail)))

    def audit_log(self, project: str, limit: int = 100) -> list[dict]:
        rows = self._db.execute(
            "SELECT * FROM audit WHERE project=? ORDER BY ts DESC LIMIT ?",
            (project, limit)).fetchall()
        return [{"ts": r["ts"], "action": r["action"], "detail": json.loads(r["detail"])}
                for r in rows]

    # -- helpers ------------------------------------------------------------
    @staticmethod
    def _row_to_traj(r) -> Trajectory:
        return Trajectory(
            user=r["user"], task=r["task"], query=r["query"], response=r["response"],
            project=r["project"], signal=Signal(r["signal"]) if r["signal"] else None,
            edited_text=r["edited_text"], rating=r["rating"], id=r["id"],
            created_at=r["created_at"], meta=json.loads(r["meta"] or "{}"))

    @staticmethod
    def _row_to_pref(r) -> Preference:
        return Preference(
            user=r["user"], task=r["task"], text=r["text"], project=r["project"],
            status=Status(r["status"]), support=r["support"],
            source_ids=json.loads(r["source_ids"] or "[]"), id=r["id"],
            created_at=r["created_at"])
