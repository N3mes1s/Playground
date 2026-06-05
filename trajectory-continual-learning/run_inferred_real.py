"""Live proof with INFERRED preferences (the hard, honest version).

Unlike run_claude_real.py -- where the code oracle tells the engine exactly which
rules were violated -- here the engine is NOT told the rules at all. It only sees
how the user edited drafts, and an LLM infers the latent preferences from those
diffs. We then measure whether those *inferred* lessons make future drafts better,
scored by the code oracle on held-out tasks.

Roles, kept strictly separate (the whole point):
  * policy : live Claude, writes drafts. Never told the rules.
  * user   : live Claude given the hidden rules, produces the corrected edit.
             (Simulates a user who knows their own preferences.)
  * miner  : live Claude, sees only (before, after) pairs, infers preferences.
             Never told the rules.
  * scorer : text_rules.py, pure code. The objective judge.

Method: CIPHER-style aggregation (Gao et al., 2024). After each new edit, the
miner re-infers a context's preferences from ALL of that context's edits so far,
so recurring preferences stand out and one-off noise washes out. We track held-out
reward as edits accumulate.

Run:  python run_inferred_real.py
"""

from __future__ import annotations

import json
import os

from backends import ClaudeCLIBackend
from chart import svg_bars, svg_curve
from learner import ContinualLearner
from llm_miner import infer_lessons_aggregate
from memory import Lesson, LessonMemory
from text_rules import RULES, check_text, evaluate_text

ART = os.path.join(os.path.dirname(__file__), "artifacts", "real-llm")

# interleaved so both domains' curves climb over time
TRAIN = [
    ("email", "ask a client for a one-week deadline extension"),
    ("slack", "post the nightly deploy status to the team"),
    ("email", "follow up on an unpaid invoice"),
    ("slack", "summarize today's standup"),
]
EVAL = [  # held-out, never trained on
    ("email", "request a reference letter from a former manager"),
    ("slack", "announce that the staging environment is back up"),
]


def true_rule_lessons(ctx):
    """The user's actual (hidden) preferences -- used ONLY to synthesize the user's
    edit, never shown to the policy or the miner."""
    return [Lesson(text=r.lesson, feature=r.feature, context=ctx, signature=ctx)
            for r in RULES[ctx]]


def build_memory(lessons_by_ctx):
    m = LessonMemory()
    for ls in lessons_by_ctx.values():
        for l in ls:
            m.upsert(l)
    return m


def eval_reward(backend, memory):
    learner = ContinualLearner(backend=backend, memory=memory, retrieve_k=8)
    rewards, details = [], []
    for ctx, q in EVAL:
        msg = backend.generate(ctx, q, learner.policy_context(ctx, q))
        _, r = evaluate_text(ctx, q, msg)
        rewards.append(r)
        details.append({"context": ctx, "query": q, "reward": r,
                        "satisfied": sorted(check_text(ctx, msg.content)),
                        "text": msg.content})
    return sum(rewards) / len(rewards), details


def main():
    os.makedirs(ART, exist_ok=True)
    backend = ClaudeCLIBackend()

    pairs_by_ctx: dict[str, list] = {}
    lessons_by_ctx: dict[str, list] = {}
    curve, transcript = [], []

    print("checkpoint 0 (no lessons yet)...")
    r0, _ = eval_reward(backend, LessonMemory())
    curve.append(r0)
    print(f"   held-out reward = {r0:.2f}")

    for i, (ctx, q) in enumerate(TRAIN, 1):
        print(f"\nexample {i}/{len(TRAIN)}: [{ctx}] {q}")
        before = backend.generate(ctx, q, []).content          # policy, no knowledge
        after = backend.generate(ctx, q, true_rule_lessons(ctx)).content  # user edit
        pairs_by_ctx.setdefault(ctx, []).append((q, before, after))

        # re-infer this context's preferences from ALL its edits so far
        lessons_by_ctx[ctx] = infer_lessons_aggregate(backend, ctx, pairs_by_ctx[ctx])
        print(f"   inferred {len(lessons_by_ctx[ctx])} preference(s) for '{ctx}' "
              f"from {len(pairs_by_ctx[ctx])} edit(s):")
        for l in lessons_by_ctx[ctx]:
            print(f"      • {l.text}")

        memory = build_memory(lessons_by_ctx)
        r, det = eval_reward(backend, memory)
        curve.append(r)
        print(f"   held-out reward now = {r:.2f}  (memory: {len(memory)} lessons)")
        transcript.append({"example": i, "context": ctx, "query": q,
                           "before": before, "after_user_edit": after,
                           "context_lessons_now": [l.text for l in lessons_by_ctx[ctx]],
                           "holdout_reward_after": r})

    final_memory = build_memory(lessons_by_ctx)
    final_reward, final_det = eval_reward(backend, final_memory)

    comparison = {ctx: {"true_hidden_rules": [r.lesson for r in RULES[ctx]],
                        "engine_inferred": [l.text for l in lessons_by_ctx.get(ctx, [])]}
                  for ctx in RULES}

    summary = {
        "policy_model": "live Claude via `claude -p` (no API key)",
        "method": "CIPHER-style aggregation: re-infer from all of a context's edits",
        "preference_source": "INFERRED by LLM from edit diffs (engine never sees the rules)",
        "scorer": "objective rule-checker (text_rules.py)",
        "holdout_curve": curve,
        "baseline_reward": curve[0],
        "final_reward": final_reward,
        "lessons_inferred": len(final_memory),
        "true_vs_inferred": comparison,
        "transcript": transcript,
        "final_holdout_detail": final_det,
    }
    with open(os.path.join(ART, "inferred-run.json"), "w") as f:
        json.dump(summary, f, indent=2)

    svg_curve(curve, [curve[0]] * len(curve),
              os.path.join(ART, "inferred-curve.svg"),
              title="Inferred-preference learning (live Claude): held-out reward")
    svg_bars(["baseline", "after learning"], [curve[0], final_reward],
             os.path.join(ART, "inferred-bars.svg"),
             title="Inferred preferences (engine never told the rules)")
    _write_md(summary)

    print("\n" + "=" * 60)
    print("INFERRED-PREFERENCE RESULT (engine was never told the rules)")
    print("=" * 60)
    print(f"  held-out reward:  {curve[0]:.2f}  ->  {final_reward:.2f}")
    print(f"  lessons inferred: {len(final_memory)}")
    print(f"  artifacts: {ART}/inferred-run.md , inferred-curve.svg, inferred-bars.svg")


def _write_md(s):
    L = ["# Live proof — preferences INFERRED from edits (not given)\n",
         f"- **Policy:** {s['policy_model']}",
         f"- **Method:** {s['method']}",
         f"- **Preference source:** {s['preference_source']}",
         f"- **Scorer:** {s['scorer']}",
         "",
         f"The engine was **never shown the rule list**. It inferred preferences "
         f"purely from how the user edited drafts. Held-out reward "
         f"**{s['baseline_reward']:.2f} → {s['final_reward']:.2f}**.",
         "",
         "![inferred curve](inferred-curve.svg)",
         "",
         "![inferred bars](inferred-bars.svg)",
         "",
         "## True hidden rules vs. what the engine inferred", ""]
    for ctx, cmp in s["true_vs_inferred"].items():
        L.append(f"### `{ctx}`")
        L.append("**True hidden rules (user's, never shown to the engine):**")
        L += [f"- {r}" for r in cmp["true_hidden_rules"]]
        L.append("")
        L.append("**Engine inferred from edits:**")
        L += [f"- {r}" for r in cmp["engine_inferred"]] or ["- (none)"]
        L.append("")
    L += ["## Training transcript (before → user edit → inferred-so-far)", ""]
    for t in s["transcript"]:
        L.append(f"### example {t['example']} — [{t['context']}] {t['query']}")
        L.append(f"*held-out reward after this example: {t['holdout_reward_after']:.2f}*")
        L += ["", "**BEFORE (policy draft, no knowledge):**", "```", t["before"], "```",
              "**AFTER (user's edit):**", "```", t["after_user_edit"], "```",
              f"**Inferred preferences for `{t['context']}` so far:**"]
        L += [f"> - {l}" for l in t["context_lessons_now"]]
        L.append("")
    with open(os.path.join(ART, "inferred-run.md"), "w") as f:
        f.write("\n".join(L))


if __name__ == "__main__":
    main()
