"""Overcoming the inference gap: an ablation with live Claude.

Proof #2 (run_inferred_real.py) showed self-inferred preferences only reach ~0.50
held-out reward -- inference is lossy and the policy drops rules at apply time.
This script applies three research-grounded fixes and measures each one's
contribution on the SAME held-out tasks:

  A. baseline                         -- frozen Claude, no lessons
  B. naive inference + plain apply    -- single aggregate inference (the old ~0.50)
  C. robust inference + plain apply   -- decomposed analysis + self-consistency
                                         voting (DeCRIM decompose + self-curation)
  D. robust inference + critique-refine -- C, plus a Self-Refine/DeCRIM critic loop
                                         at generation time

The engine is NEVER told the rules (same strict role separation as proof #2);
text_rules.py scores. Writes artifacts/real-llm/robust-run.{json,md,svg}.

Run:  python run_robust_real.py
"""

from __future__ import annotations

import json
import os

from backends import ClaudeCLIBackend
from chart import svg_bars
from learner import ContinualLearner
from llm_miner import infer_lessons_aggregate, infer_lessons_robust
from memory import Lesson, LessonMemory
from refine import generate_refined
from text_rules import RULES, check_text, evaluate_text

ART = os.path.join(os.path.dirname(__file__), "artifacts", "real-llm")

TRAIN = [
    ("email", "ask a client for a one-week deadline extension"),
    ("slack", "post the nightly deploy status to the team"),
    ("email", "follow up on an unpaid invoice"),
    ("slack", "summarize today's standup"),
    ("email", "introduce a new teammate to a client"),
    ("slack", "ask the team for a code review on a PR"),
    ("email", "reschedule a kickoff call"),
    ("slack", "remind the team about the release freeze"),
]
EVAL = [  # 8 held-out tasks, never trained on -> a stable, granular metric
    ("email", "request a reference letter from a former manager"),
    ("email", "ask a manager to approve time off"),
    ("email", "thank a mentor for their advice"),
    ("email", "request feedback on a design doc"),
    ("slack", "announce that the staging environment is back up"),
    ("slack", "report that the incident is mitigated"),
    ("slack", "ask for a deploy window today"),
    ("slack", "share this week's key metrics"),
]


def true_rule_lessons(ctx):
    return [Lesson(text=r.lesson, feature=r.feature, context=ctx, signature=ctx)
            for r in RULES[ctx]]


def mem_from(lessons_by_ctx):
    m = LessonMemory()
    for ls in lessons_by_ctx.values():
        for l in ls:
            m.upsert(l)
    return m


def score(backend, lessons_by_ctx, refine=False):
    learner = ContinualLearner(backend=backend, memory=mem_from(lessons_by_ctx),
                               retrieve_k=8)
    rewards, detail = [], []
    for ctx, q in EVAL:
        lessons = learner.policy_context(ctx, q)
        if refine:
            msg = generate_refined(backend, ctx, q, lessons, max_iters=3)
        else:
            msg = backend.generate(ctx, q, lessons)
        _, r = evaluate_text(ctx, q, msg)
        rewards.append(r)
        detail.append({"context": ctx, "query": q, "reward": r,
                       "satisfied": sorted(check_text(ctx, msg.content)),
                       "text": msg.content})
    return sum(rewards) / len(rewards), detail


def main():
    os.makedirs(ART, exist_ok=True)
    backend = ClaudeCLIBackend()

    # --- collect the user's edits ---
    print("collecting edits...")
    pairs = {}
    for ctx, q in TRAIN:
        before = backend.generate(ctx, q, []).content
        after = backend.generate(ctx, q, true_rule_lessons(ctx)).content
        pairs.setdefault(ctx, []).append((q, before, after))

    # --- infer preferences two ways ---
    print("naive inference (single aggregate)...")
    naive = {c: infer_lessons_aggregate(backend, c, p) for c, p in pairs.items()}
    print("robust inference (decomposed + self-consistency voting)...")
    robust = {c: infer_lessons_robust(backend, c, p, samples=4) for c, p in pairs.items()}

    # --- ablation on held-out tasks ---
    results = {}
    print("A: baseline...");            results["A_baseline"] = score(backend, {})
    print("B: naive + plain apply..."); results["B_naive_plain"] = score(backend, naive)
    print("C: robust + plain apply..."); results["C_robust_plain"] = score(backend, robust)
    print("D: robust + critique-refine..."); results["D_robust_refine"] = score(backend, robust, refine=True)

    labels = {"A_baseline": "baseline", "B_naive_plain": "naive infer",
              "C_robust_plain": "robust infer", "D_robust_refine": "robust+refine"}
    summary = {
        "policy_model": "live Claude via `claude -p` (no API key)",
        "scorer": "objective rule-checker (text_rules.py)",
        "conditions": {k: {"label": labels[k], "reward": round(v[0], 3),
                           "detail": v[1]} for k, v in results.items()},
        "naive_lessons": {c: [l.text for l in ls] for c, ls in naive.items()},
        "robust_lessons": {c: [l.text for l in ls] for c, ls in robust.items()},
        "true_rules": {c: [r.lesson for r in RULES[c]] for c in RULES},
    }
    with open(os.path.join(ART, "robust-run.json"), "w") as f:
        json.dump(summary, f, indent=2)

    order = ["A_baseline", "B_naive_plain", "C_robust_plain", "D_robust_refine"]
    svg_bars([labels[k] for k in order], [results[k][0] for k in order],
             os.path.join(ART, "robust-bars.svg"),
             title="Overcoming the inference gap (held-out reward, live Claude)")
    _write_md(summary, order, labels, results)

    print("\n" + "=" * 60)
    print("ABLATION RESULT (held-out reward, engine never told the rules)")
    print("=" * 60)
    for k in order:
        print(f"  {labels[k]:<16} {results[k][0]:.2f}")
    print(f"\n  artifacts: {ART}/robust-run.md , robust-bars.svg")


def _write_md(s, order, labels, results):
    L = ["# Overcoming the inference gap — live Claude ablation\n",
         f"- **Policy:** {s['policy_model']}",
         f"- **Scorer:** {s['scorer']}",
         "",
         "Each row adds one research-grounded technique. The engine is never told "
         "the rules; it infers them from edits.",
         "",
         "| Condition | Held-out reward | Technique added |",
         "|---|---|---|",
         f"| {labels['A_baseline']} | **{results['A_baseline'][0]:.2f}** | — (frozen model) |",
         f"| {labels['B_naive_plain']} | **{results['B_naive_plain'][0]:.2f}** | single aggregate inference |",
         f"| {labels['C_robust_plain']} | **{results['C_robust_plain'][0]:.2f}** | + decomposed analysis & self-consistency voting |",
         f"| {labels['D_robust_refine']} | **{results['D_robust_refine'][0]:.2f}** | + critique→refine at apply time |",
         "",
         "![ablation](robust-bars.svg)",
         "",
         "## What each condition produced (held-out, per domain)", ""]
    for k in order:
        L.append(f"### {labels[k]} — reward {results[k][0]:.2f}")
        for d in results[k][1]:
            L.append(f"- `{d['context']}` reward {d['reward']:.2f} — satisfied {d['satisfied']}")
        L.append("")
    L += ["## Robust-inferred preferences vs. the true hidden rules", ""]
    for c in s["true_rules"]:
        L.append(f"### `{c}`")
        L.append("**True hidden rules:**")
        L += [f"- {r}" for r in s["true_rules"][c]]
        L.append("")
        L.append("**Robustly inferred (decomposed + voted):**")
        L += [f"- {r}" for r in s["robust_lessons"].get(c, [])] or ["- (none)"]
        L.append("")
    with open(os.path.join(ART, "robust-run.md"), "w") as f:
        f.write("\n".join(L))


if __name__ == "__main__":
    main()
