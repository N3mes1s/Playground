"""Sanity / regression tests for the engine. Pure stdlib, run: python tests.py"""

from backends import MockLLM
from environment import HIDDEN_PREFERENCES, PreferenceEnvironment
from governance import ApprovalGate, Decision, min_support_policy
from learner import ContinualLearner
from memory import Lesson, LessonMemory
from miner import mine_lessons, mine_preference_pairs
from schema import Message, SignalKind, TelemetrySignal, Trajectory

passed = 0


def check(name, cond):
    global passed
    assert cond, f"FAILED: {name}"
    passed += 1
    print(f"  ok  {name}")


def test_schema_roundtrip():
    t = Trajectory(context="email", query="hi",
                   response=Message("assistant", "x", features=["a"]))
    t.add_signal(TelemetrySignal(kind=SignalKind.EDIT,
                                 edited_content="y", edited_features=["a", "b"]))
    t2 = Trajectory.from_dict(t.to_dict())
    check("trajectory roundtrips through dict", t2.context == "email" and t2.has_correction)


def test_miner_extracts_added_features():
    t = Trajectory(context="email", query="hi",
                   response=Message("assistant", "x", features=["formal_greeting"]))
    t.add_signal(TelemetrySignal(kind=SignalKind.EDIT, edited_content="y",
                 edited_features=["formal_greeting", "no_emoji", "signoff_best_regards"]))
    lessons = mine_lessons(t)
    feats = {l.feature for l in lessons}
    check("miner extracts only the user-added features",
          feats == {"no_emoji", "signoff_best_regards"})
    pairs = mine_preference_pairs(t)
    check("miner builds a preference pair from the edit", len(pairs) == 1)


def test_memory_retrieval_generalizes():
    m = LessonMemory()
    m.upsert(Lesson(text="t", feature="no_emoji", context="email",
                    signature="email draft a note"))
    # unseen query, same domain -> should still retrieve
    got = m.retrieve("email", "some totally different request", k=3)
    check("memory retrieves domain lesson for an unseen query",
          any(l.feature == "no_emoji" for l in got))
    none = m.retrieve("slack", "x", k=3)
    check("memory does not leak email lessons into slack", len(none) == 0)


def test_governance_threshold():
    gate = ApprovalGate(policy=min_support_policy(threshold=2))
    l = Lesson(text="t", feature="f", context="c", signature="c q", support=1)
    check("gate holds an under-supported lesson", gate.review(l) == Decision.HELD)
    l.support = 2
    check("gate approves once support meets threshold", gate.review(l) == Decision.APPROVED)


def test_learning_improves_reward():
    env = PreferenceEnvironment(seed=3)
    learner = ContinualLearner(backend=MockLLM(slip=0.0, seed=3),
                               gate=ApprovalGate(policy=min_support_policy(1)))
    # baseline: frozen model on email gets 0 (knows nothing)
    base = env.evaluate("email", "reply to the client",
                        MockLLM(slip=0.0).generate("email", "reply to the client", [])).reward
    check("frozen baseline reward is 0", base == 0.0)
    # train on email
    for q in ["draft a note to the team", "reply to the client"]:
        out = env.evaluate("email", q, learner.act("email", q))
        learner.ingest(out.trajectory)
    after = env.evaluate("email", "an unseen email request",
                         learner.act("email", "an unseen email request")).reward
    check("reward improves to full after learning", after == 1.0)
    check("learned exactly the hidden email features",
          len(learner.memory) == len(HIDDEN_PREFERENCES["email"]))


def test_control_stays_flat():
    env = PreferenceEnvironment(seed=4)
    backend = MockLLM(slip=0.0, seed=4)
    rs = []
    for _ in range(50):
        ctx, q = env.sample_task()
        rs.append(env.evaluate(ctx, q, backend.generate(ctx, q, [])).reward)
    check("a frozen control never improves", max(rs) == 0.0)


if __name__ == "__main__":
    print("running tests...")
    test_schema_roundtrip()
    test_miner_extracts_added_features()
    test_memory_retrieval_generalizes()
    test_governance_threshold()
    test_learning_improves_reward()
    test_control_stays_flat()
    print(f"\nAll {passed} checks passed.")
