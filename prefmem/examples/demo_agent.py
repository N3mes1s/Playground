"""End-to-end demo: an internal support agent that learns from edits.

Scenario: a team runs a support-reply agent. A human agent (Sam) keeps editing
the drafts the same way -- shorter, signs off "Onwards, Sam". PrefMem captures
those edits, learns the preference, a reviewer approves it, and the next draft
follows it automatically -- with nothing changed in the app's own code.

Runs locally with no API key (uses the `claude` CLI if present for both the
agent and the inference; falls back to heuristics otherwise).

    python examples/demo_agent.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prefmem import PrefMem
from prefmem.miner import ClaudeCLIBackend, default_backend


def make_agent():
    """The team's existing agent. Here, a thin wrapper over the claude CLI."""
    try:
        cli = ClaudeCLIBackend() if os.environ.get("CLAUDE_CODE_EXECPATH") else None
    except Exception:
        cli = None

    def agent(system_addon, user_msg):
        sys_prompt = ("You are a customer-support reply assistant. Write only the "
                      "reply, no preamble.")
        if system_addon:
            sys_prompt += "\n\n" + system_addon
        if cli:
            return cli.complete(user_msg, sys_prompt)
        return f"[mock reply to: {user_msg}]"     # offline fallback
    return agent


def main():
    db = "/tmp/prefmem_demo.db"
    if os.path.exists(db):
        os.remove(db)
    backend = default_backend()  # claude CLI here -> real inference
    pm = PrefMem(store=db, backend=backend)
    agent = make_agent()
    ctx = pm.context(user="sam", task="support-reply")

    requests = [
        "Customer asks for a refund on order 8841; it's eligible.",
        "Customer says the app keeps crashing on login.",
        "Customer wants to change their subscription to annual.",
    ]
    # how Sam actually likes replies (the hidden preference he keeps applying)
    sam_edit = lambda r, c: f"Hey! {c} Sorted for you. Onwards, Sam"

    print("=" * 70)
    print("BEFORE LEARNING — agent drafts, Sam keeps editing them the same way")
    print("=" * 70)
    for req in requests[:2]:
        draft = agent(ctx.guidance(), req)            # guidance is empty at first
        turn = ctx.log(query=req, response=draft)
        gist = "here's what you need."
        turn.edit(sam_edit(draft, gist))              # Sam's edit = the signal
        print(f"\nrequest : {req}")
        print(f"agent   : {draft[:120]}")
        print(f"Sam edit: {sam_edit(draft, gist)}")

    print("\n" + "=" * 70)
    print("LEARN — PrefMem infers Sam's preferences from his edits")
    print("=" * 70)
    pm.learn(user="sam", task="support-reply")
    pend = pm.pending()
    for p in pend:
        print(f"  • (pending) {p['text']}")
    print("\nreviewer approves them in the dashboard...")
    for p in pend:
        pm.approve(p["id"])

    print("\n" + "=" * 70)
    print("AFTER LEARNING — a NEW request, no app code changed")
    print("=" * 70)
    new_req = requests[2]
    g = ctx.guidance()
    draft = agent(g, new_req)
    print(f"\ninjected guidance:\n{g}")
    print(f"\nrequest : {new_req}")
    print(f"agent   : {draft}")
    print("\n-> the agent now writes in Sam's style on the first try. That is the")
    print("   product: your agent improves from real usage, with human approval.")


if __name__ == "__main__":
    main()
