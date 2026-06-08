"""PrefMem control-plane: a hosted HTTP API + a minimal review dashboard.

Run:  prefmem-server            (or: python -m prefmem.server)
Env:  PREFMEM_DB, PREFMEM_PROJECT, PREFMEM_API_KEY (optional bearer auth)

The dashboard at / lets a human review and approve/reject the preferences the
engine has learned before they go live -- the governance surface teams need to
trust an agent that changes itself.
"""

from __future__ import annotations

import html
import os
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel

from .engine import Engine
from .store import Store

DB = os.environ.get("PREFMEM_DB", "prefmem.db")
PROJECT = os.environ.get("PREFMEM_PROJECT", "default")
API_KEY = os.environ.get("PREFMEM_API_KEY")  # if set, required on /v1/*

app = FastAPI(title="PrefMem control-plane", version="0.1.0")
_engine = Engine(Store(DB), project=PROJECT, auto_approve=False)


def auth(authorization: Optional[str] = Header(None)):
    if API_KEY and authorization != f"Bearer {API_KEY}":
        raise HTTPException(401, "invalid or missing API key")
    return True


# --- request models ---------------------------------------------------------
class TrajIn(BaseModel):
    user: str; task: str; query: str; response: str; meta: dict = {}


class SignalIn(BaseModel):
    kind: str; edited_text: Optional[str] = None; rating: Optional[float] = None


class LearnIn(BaseModel):
    user: str; task: str


# --- API --------------------------------------------------------------------
@app.post("/v1/trajectories")
def add_traj(t: TrajIn, _=Depends(auth)):
    return {"id": _engine.log(t.user, t.task, t.query, t.response, t.meta).id}


@app.post("/v1/trajectories/{traj_id}/signal")
def signal(traj_id: str, s: SignalIn, _=Depends(auth)):
    if s.kind == "edit":
        _engine.record_edit(traj_id, s.edited_text or "")
    elif s.kind == "accept":
        _engine.record_accept(traj_id)
    elif s.kind == "reject":
        _engine.record_reject(traj_id)
    else:
        raise HTTPException(400, "unknown signal kind")
    return {"ok": True}


@app.get("/v1/guidance")
def guidance(user: str, task: str, _=Depends(auth)):
    return {"guidance": _engine.guidance(user, task)}


@app.get("/v1/preferences")
def prefs(user: str, task: str, status: str = "approved", _=Depends(auth)):
    from .schema import Status
    ps = _engine.store.preferences(PROJECT, user, task, Status(status))
    return {"preferences": [p.text for p in ps]}


@app.post("/v1/learn")
def learn(b: LearnIn, _=Depends(auth)):
    return {"preferences": [p.to_dict() for p in _engine.learn(b.user, b.task)]}


@app.get("/v1/preferences/pending")
def pending(_=Depends(auth)):
    return {"preferences": [p.to_dict() for p in _engine.pending()]}


@app.post("/v1/preferences/{pref_id}/approve")
def approve(pref_id: str, _=Depends(auth)):
    _engine.approve(pref_id); return {"ok": True}


@app.post("/v1/preferences/{pref_id}/reject")
def reject(pref_id: str, _=Depends(auth)):
    _engine.reject(pref_id); return {"ok": True}


@app.get("/v1/audit")
def audit(limit: int = 100, _=Depends(auth)):
    return {"audit": _engine.audit(limit)}


# --- dashboard --------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def dashboard():
    pend = _engine.pending()
    rows = ""
    for p in pend:
        rows += (
            f"<tr><td>{html.escape(p.user)}</td><td>{html.escape(p.task)}</td>"
            f"<td>{html.escape(p.text)}</td><td>{p.support}</td>"
            f"<td><form method=post action='/dashboard/{p.id}/approve' style='display:inline'>"
            f"<button class=ok>approve</button></form> "
            f"<form method=post action='/dashboard/{p.id}/reject' style='display:inline'>"
            f"<button class=no>reject</button></form></td></tr>")
    if not pend:
        rows = "<tr><td colspan=5 style='color:#888'>nothing pending review 🎉</td></tr>"
    audit = "".join(
        f"<li><code>{html.escape(a['action'])}</code> — {html.escape(str(a['detail'].get('text','')))}</li>"
        for a in _engine.audit(15))
    return f"""<!doctype html><meta charset=utf-8><title>PrefMem</title>
<style>
body{{font:15px system-ui;margin:40px;max-width:900px}}
h1{{font-size:20px}} table{{border-collapse:collapse;width:100%}}
td,th{{border-bottom:1px solid #eee;padding:8px;text-align:left;vertical-align:top}}
button{{border:0;border-radius:6px;padding:5px 10px;cursor:pointer;color:#fff}}
.ok{{background:#16a34a}} .no{{background:#dc2626}}
code{{background:#f3f4f6;padding:1px 4px;border-radius:4px}}
</style>
<h1>PrefMem — preferences pending review (project: {html.escape(PROJECT)})</h1>
<table><tr><th>user</th><th>task</th><th>learned preference</th><th>support</th><th></th></tr>
{rows}</table>
<h2 style='font-size:16px;margin-top:32px'>recent activity</h2><ul>{audit}</ul>"""


@app.post("/dashboard/{pref_id}/approve")
def dash_approve(pref_id: str):
    _engine.approve(pref_id, by="dashboard")
    return RedirectResponse("/", status_code=303)


@app.post("/dashboard/{pref_id}/reject")
def dash_reject(pref_id: str):
    _engine.reject(pref_id, by="dashboard")
    return RedirectResponse("/", status_code=303)


def main():
    import uvicorn
    uvicorn.run(app, host=os.environ.get("HOST", "127.0.0.1"),
                port=int(os.environ.get("PORT", "8000")))


if __name__ == "__main__":
    main()
