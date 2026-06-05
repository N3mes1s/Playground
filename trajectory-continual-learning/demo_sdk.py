"""End-to-end narrative demo of the engine on a single domain.

Shows the full loop the way a product would use it:

  1. A frozen model answers an "email" request -> the user has to fix it (EDIT).
  2. We ingest that trajectory; the engine mines a lesson, the gate approves it.
  3. The next time a *different* email request comes in, the model retrieves the
     lesson and gets it right on the first try.

Run:  python demo_sdk.py
"""

from backends import MockLLM
from governance import ApprovalGate, min_support_policy
from learner import ContinualLearner
from environment import PreferenceEnvironment


def main():
    env = PreferenceEnvironment(seed=1)
    learner = ContinualLearner(
        backend=MockLLM(slip=0.0, seed=1),
        gate=ApprovalGate(policy=min_support_policy(threshold=1)),
    )

    print("=" * 68)
    print("BEFORE LEARNING — the model is frozen and knows no preferences")
    print("=" * 68)
    seen = []
    # Feed a few email requests; the user keeps having to edit the drafts.
    for q in ["draft a note to the team", "reply to the client", "ask for an extension"]:
        resp = learner.act("email", q)
        out = env.evaluate("email", q, resp)
        print(f"\nrequest : {q}")
        print(f"model   : {resp.content}")
        print(f"reward  : {out.reward:.2f}   telemetry: {[s.kind.value for s in out.trajectory.telemetry]}")
        res = learner.ingest(out.trajectory)
        if res["approved"]:
            print(f"learned : {res['approved']} new lesson(s) approved into memory")
        seen.append(q)

    print("\n" + "=" * 68)
    print("WHAT THE MODEL LEARNED (retrievable memory)")
    print("=" * 68)
    for l in learner.memory.all():
        print(f"  [{l.context}] {l.text}  (support={l.support})")

    print("\n" + "=" * 68)
    print("AFTER LEARNING — a brand-new email request it never saw")
    print("=" * 68)
    q = "write a thank-you note to a partner"   # unseen wording
    resp = learner.act("email", q)
    out = env.evaluate("email", q, resp)
    print(f"\nrequest : {q}  (NEW, never trained on)")
    print(f"model   : {resp.content}")
    print(f"reward  : {out.reward:.2f}   telemetry: {[s.kind.value for s in out.trajectory.telemetry]}")
    print("\n-> The model applied the learned email preferences on the first try,")
    print("   on a request it had never seen. That is continual learning.")


if __name__ == "__main__":
    main()
