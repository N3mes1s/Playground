"""Offline tests for PrefMem. Runnable with pytest OR `python tests/test_prefmem.py`
(no network, no LLM -- a fake backend supplies the inferred preferences)."""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prefmem import PrefMem, Status          # noqa: E402
from prefmem.schema import Preference, Signal, Trajectory  # noqa: E402
from prefmem.store import Store               # noqa: E402


class FakeBackend:
    """Deterministic stand-in for the LLM preference miner."""
    def __init__(self, prefs): self.prefs = prefs
    def complete(self, prompt, system=""): return "\n".join(self.prefs)


def _db():
    return os.path.join(tempfile.mkdtemp(), "t.db")


def test_store_and_governance():
    s = Store(_db())
    s.ensure_project("default")
    t = Trajectory(user="u1", task="email", query="q", response="r")
    s.add_trajectory(t)
    s.set_signal(t.id, Signal.EDIT, edited_text="r2")
    assert len(s.edits("default", "u1", "email")) == 1
    p, new = s.upsert_preference(Preference(user="u1", task="email", text="be concise"))
    assert new
    _, again = s.upsert_preference(Preference(user="u1", task="email", text="be concise"))
    assert not again  # reinforced, not duplicated
    assert s.preferences("default", "u1", "email")[0].support == 2
    s.set_status(p.id, Status.APPROVED)
    assert s.preferences("default", "u1", "email", Status.APPROVED)
    assert any(a["action"] == "preference.approved" for a in s.audit_log("default"))
    print("ok  test_store_and_governance")


def test_learn_then_approve_changes_guidance():
    pm = PrefMem(store=_db(),
                 backend=FakeBackend(["Sign off with 'Onwards, Sam'",
                                      "Keep replies under 50 words"]))
    ctx = pm.context(user="u1", task="email")
    assert ctx.guidance() == ""                     # nothing learned yet

    turn = ctx.log(query="reply to the refund ask",
                   response="Hello, ... Best regards, Support")
    turn.edit("Hi — sorted, refund is on its way. Onwards, Sam")

    learned = pm.learn(user="u1", task="email")
    assert len(learned) == 2
    assert ctx.guidance() == ""                     # still pending review (governed)

    pending = pm.pending()
    assert len(pending) == 2
    for p in pending:
        pm.approve(p["id"])

    g = ctx.guidance()
    assert "Onwards, Sam" in g and "under 50 words" in g
    assert any(a["action"] == "preference.approved" for a in pm.audit())
    print("ok  test_learn_then_approve_changes_guidance")


def test_reject_keeps_guidance_clean():
    pm = PrefMem(store=_db(), backend=FakeBackend(["Use ALL CAPS"]))
    ctx = pm.context(user="u2", task="slack")
    ctx.log("status?", "all good").edit("ALL GOOD")
    pm.learn(user="u2", task="slack")
    [p] = pm.pending()
    pm.reject(p["id"])
    assert ctx.guidance() == ""                      # rejected -> never served
    print("ok  test_reject_keeps_guidance_clean")


if __name__ == "__main__":
    test_store_and_governance()
    test_learn_then_approve_changes_guidance()
    test_reject_keeps_guidance_clean()
    print("\nall prefmem tests passed")
