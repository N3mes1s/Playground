"""LIVE proof: the real Claude model in the continual-learning loop, no API key.

This shells out to the `claude` CLI (`claude -p`) using the session's own auth.
Every generation below is produced live by a FRESH Claude instance that has never
seen this file or the hidden rules -- so the baseline is genuinely a model that
does not know *this user's* idiosyncratic preferences. Nothing is hardcoded.

Flow (the real engine drives it):
  1. Baseline: Claude writes each draft with a generic system prompt (no lessons).
  2. A code-based oracle (text_rules.py) checks the draft against the user's hidden
     preferences and emits an EDIT signal for whatever was wrong.
  3. The engine mines those edits into lessons (miner) and stores the approved
     ones (governance + memory).
  4. After learning: Claude writes fresh drafts, now with the mined lessons in its
     system prompt (retrieved by the engine). Scored by the same code oracle.
  5. Held-out: brand-new tasks it never saw, to show generalization.

Run:  python run_claude_real.py
"""

from __future__ import annotations

import json
import os
import sys

from backends import ClaudeCLIBackend
from governance import ApprovalGate, min_support_policy
from learner import ContinualLearner
from memory import LessonMemory
from text_rules import RULES, evaluate_text

ART = os.path.join(os.path.dirname(__file__), "artifacts", "real-llm")

TRAIN = {
    "email": ["ask a client for a one-week deadline extension",
              "decline a meeting invitation politely",
              "follow up on an unpaid invoice"],
    "slack": ["post the nightly deploy status to the team",
              "ask who owns the data pipeline",
              "summarize today's standup"],
}
HOLDOUT = {
    "email": ["request a reference letter from a former manager"],
    "slack": ["announce that the staging environment is back up"],
}


def main():
    os.makedirs(ART, exist_ok=True)
    backend = ClaudeCLIBackend()
    learner = ContinualLearner(backend=backend, memory=LessonMemory(),
                               gate=ApprovalGate(policy=min_support_policy(1)))
    rows = []

    print("Phase 1/3: baseline drafts from a frozen Claude (no learned lessons)...")
    baseline_trajs, base_scores = [], []
    for ctx, queries in TRAIN.items():
        for q in queries:
            msg = backend.generate(ctx, q, [])           # no lessons -> baseline
            traj, r = evaluate_text(ctx, q, msg)
            baseline_trajs.append(traj)
            base_scores.append(r)
            print(f"   [{ctx}] {q[:40]:<40} reward={r:.2f}")
            rows.append({"phase": "baseline", "context": ctx, "query": q,
                         "reward": r, "satisfied": sorted(set(msg.features)),
                         "missing": sorted(set(_req(ctx)) - set(msg.features)),
                         "text": msg.content, "lessons": []})

    # learn from the user's edits
    for traj in baseline_trajs:
        learner.ingest(traj)
    print(f"\nMined {len(learner.memory)} lessons from edits:")
    for l in learner.memory.all():
        print(f"   - [{l.context}] {l.text}")

    print("\nPhase 2/3: fresh drafts WITH the mined lessons injected...")
    after_scores = []
    for ctx, queries in TRAIN.items():
        for q in queries:
            lessons = learner.policy_context(ctx, q)     # real retrieval
            msg = backend.generate(ctx, q, lessons)
            traj, r = evaluate_text(ctx, q, msg)
            after_scores.append(r)
            print(f"   [{ctx}] {q[:40]:<40} reward={r:.2f}")
            rows.append({"phase": "after-learning", "context": ctx, "query": q,
                         "reward": r, "satisfied": sorted(set(msg.features)),
                         "missing": sorted(set(_req(ctx)) - set(msg.features)),
                         "text": msg.content,
                         "lessons": [l.text for l in lessons]})

    print("\nPhase 3/3: held-out, never-seen tasks (generalization)...")
    holdout_scores = []
    for ctx, queries in HOLDOUT.items():
        for q in queries:
            lessons = learner.policy_context(ctx, q)
            msg = backend.generate(ctx, q, lessons)
            traj, r = evaluate_text(ctx, q, msg)
            holdout_scores.append(r)
            print(f"   [{ctx}] {q[:40]:<40} reward={r:.2f}")
            rows.append({"phase": "holdout", "context": ctx, "query": q,
                         "reward": r, "satisfied": sorted(set(msg.features)),
                         "missing": sorted(set(_req(ctx)) - set(msg.features)),
                         "text": msg.content,
                         "lessons": [l.text for l in lessons]})

    base = _mean(base_scores)
    after = _mean(after_scores)
    hold = _mean(holdout_scores)
    summary = {
        "policy_model": "Claude via `claude -p` (live, session auth, no API key)",
        "scorer": "objective rule-checker (text_rules.py)",
        "baseline_mean_reward": round(base, 3),
        "after_learning_mean_reward": round(after, 3),
        "holdout_mean_reward": round(hold, 3),
        "lessons_learned": [f"[{l.context}] {l.text}" for l in learner.memory.all()],
        "rows": rows,
    }
    with open(os.path.join(ART, "claude-run.json"), "w") as f:
        json.dump(summary, f, indent=2)
    _write_md(summary)
    from chart import svg_bars
    svg_bars(["baseline (frozen)", "after learning", "held-out (unseen)"],
             [base, after, hold], os.path.join(ART, "claude-run.svg"),
             title="Live Claude in the loop: hidden-rule satisfaction")

    print("\n" + "=" * 60)
    print("RESULT (live Claude as policy, code as scorer)")
    print("=" * 60)
    print(_bar("baseline", base))
    print(_bar("after", after))
    print(_bar("holdout", hold))
    print(f"\nartifacts: {ART}/claude-run.md , claude-run.json")


def _req(ctx):
    return {r.feature for r in RULES[ctx]}


def _mean(xs):
    return sum(xs) / len(xs) if xs else 0.0


def _bar(label, value, width=26):
    fill = int(round(value * width))
    return f"  {label:<9} |{'#'*fill}{'.'*(width-fill)}| {value:.2f}"


def _write_md(s):
    L = ["# Live proof — Claude in the continual-learning loop\n",
         f"- **Policy model:** {s['policy_model']}",
         f"- **Scorer:** {s['scorer']} — mechanical, re-runnable on any string",
         "",
         "Every draft below was generated **live** by a fresh `claude -p` process "
         "with no knowledge of the hidden rules. The improvement comes only from "
         "lessons the engine mined from the baseline edits.",
         "",
         "| Phase | Mean reward (fraction of the user's hidden rules satisfied) |",
         "|---|---|",
         f"| Baseline — frozen Claude, no lessons | **{s['baseline_mean_reward']:.2f}** |",
         f"| After learning from edits | **{s['after_learning_mean_reward']:.2f}** |",
         f"| Held-out, never-seen tasks | **{s['holdout_mean_reward']:.2f}** |",
         "",
         "## Lessons the engine mined from the user's edits", ""]
    L += [f"- {l}" for l in s["lessons_learned"]]
    L += ["", "## Every generation (verbatim, live), with objective scores", ""]
    for r in s["rows"]:
        L.append(f"### [{r['phase']}] ({r['context']}) {r['query']}")
        L.append(f"*reward {r['reward']:.2f} — satisfied {r['satisfied']} — "
                 f"missing {r['missing']}*")
        if r["lessons"]:
            L.append("")
            L.append("lessons injected into Claude's system prompt:")
            L += [f"> - {l}" for l in r["lessons"]]
        L += ["", "```", r["text"], "```", ""]
    with open(os.path.join(ART, "claude-run.md"), "w") as f:
        f.write("\n".join(L))


if __name__ == "__main__":
    sys.exit(main())
