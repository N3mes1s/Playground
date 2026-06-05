"""Run the continual-learning loop against a REAL LLM (Claude or OpenAI-compatible).

Same engine, same proof design as experiment.py -- but the policy is a real model
generating real natural-language text, and the "user oracle" is the objective
rule-checker in text_rules.py (so scoring stays reproducible, no judge model).

Treatment (learning on) vs control (frozen). Both get the same task stream.
Writes artifacts/real-llm/ : results + a full transcript of every generation.

Usage:
    export ANTHROPIC_API_KEY=sk-ant-...        # uses Claude
    python experiment_real.py --rounds 4 --batch 4

    # or any OpenAI-compatible endpoint:
    export OPENAI_API_KEY=...
    python experiment_real.py --backend openai --model gpt-4o-mini
"""

from __future__ import annotations

import argparse
import json
import os
import statistics

from governance import ApprovalGate, min_support_policy
from learner import ContinualLearner
from memory import LessonMemory
from text_rules import RULES, evaluate_text

ART = os.path.join(os.path.dirname(__file__), "artifacts", "real-llm")

TASKS = {
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


def make_backend(kind: str, model: str | None):
    if kind == "anthropic":
        from backends import AnthropicLLM
        return AnthropicLLM(model=model or "claude-sonnet-4-6")
    if kind == "openai":
        from backends import OpenAILLM
        return OpenAILLM(model=model or "gpt-4o-mini")
    raise ValueError(kind)


def run(kind: str, model: str | None, rounds: int, batch: int, support: int):
    os.makedirs(ART, exist_ok=True)
    policy = make_backend(kind, model)

    learner = ContinualLearner(backend=policy, memory=LessonMemory(),
                               gate=ApprovalGate(policy=min_support_policy(support)))
    domains = list(RULES.keys())
    transcript: list[dict] = []
    treat_curve, ctrl_curve = [], []

    rng_order = [(d, q) for d in domains for q in TASKS[d]]

    for rnd in range(rounds):
        t_rewards, c_rewards = [], []
        for i in range(batch):
            ctx, q = rng_order[(rnd * batch + i) % len(rng_order)]

            # treatment: generate with retrieved lessons, then learn
            lessons = learner.policy_context(ctx, q)
            t_msg = learner.backend.generate(ctx, q, lessons)
            t_traj, t_r = evaluate_text(ctx, q, t_msg)
            learner.ingest(t_traj)
            t_rewards.append(t_r)

            # control: frozen, never sees lessons, never learns
            c_msg = policy.generate(ctx, q, [])
            _, c_r = evaluate_text(ctx, q, c_msg)
            c_rewards.append(c_r)

            transcript.append({
                "round": rnd, "context": ctx, "query": q,
                "lessons_injected": [l.text for l in lessons],
                "treatment_text": t_msg.content, "treatment_reward": t_r,
                "control_text": c_msg.content, "control_reward": c_r,
            })
        treat_curve.append(statistics.mean(t_rewards))
        ctrl_curve.append(statistics.mean(c_rewards))
        print(f"round {rnd+1}/{rounds}: treatment={treat_curve[-1]:.2f} "
              f"control={ctrl_curve[-1]:.2f} lessons={len(learner.memory)}")

    # held-out generalization
    gen = []
    for ctx, qs in HOLDOUT.items():
        for q in qs:
            msg = learner.act(ctx, q)
            _, r = evaluate_text(ctx, q, msg)
            gen.append(r)
            transcript.append({"round": "holdout", "context": ctx, "query": q,
                               "treatment_text": msg.content, "treatment_reward": r})

    results = {
        "backend": f"{kind}:{model or 'default'}", "rounds": rounds, "batch": batch,
        "treatment_curve": treat_curve, "control_curve": ctrl_curve,
        "final_treatment": treat_curve[-1], "final_control": ctrl_curve[-1],
        "holdout_treatment": statistics.mean(gen) if gen else None,
        "lessons_learned": len(learner.memory),
        "learned": [l.text for l in learner.memory.all()],
    }
    with open(os.path.join(ART, "results.json"), "w") as f:
        json.dump(results, f, indent=2)
    with open(os.path.join(ART, "transcript.json"), "w") as f:
        json.dump(transcript, f, indent=2)
    print(f"\nfinal: treatment={results['final_treatment']:.2f} "
          f"control={results['final_control']:.2f} "
          f"holdout={results['holdout_treatment']}")
    print(f"artifacts in {ART}/")
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", choices=["anthropic", "openai"], default="anthropic")
    ap.add_argument("--model", default=None)
    ap.add_argument("--rounds", type=int, default=4)
    ap.add_argument("--batch", type=int, default=6)
    ap.add_argument("--support", type=int, default=1)
    args = ap.parse_args()
    try:
        run(args.backend, args.model, args.rounds, args.batch, args.support)
    except RuntimeError as e:
        print(f"\n[cannot run against a real model] {e}")
        print("The offline proof (python experiment.py) needs no key and still "
              "demonstrates the mechanism.")
        raise SystemExit(2)


if __name__ == "__main__":
    main()
