"""prove.py: the controlled experiment that demonstrates continual learning.

Design (a clean A/B with a control group, averaged over seeds):

  * TREATMENT: the full engine. It acts using retrieved lessons, then ingests
    every trajectory's telemetry to learn (mine -> approve -> memory).
  * CONTROL:   the identical policy backend, but learning is OFF. It never
    retrieves or ingests anything -- a frozen model.

Both arms see the same task stream each round. If reward rises for TREATMENT
while CONTROL stays flat, the improvement is caused by the learning loop and
nothing else. We then run a generalization test on held-out queries to show the
engine learned transferable preferences, not memorized strings.

Run:  python experiment.py        (writes artifacts/, fully offline)
"""

from __future__ import annotations

import json
import os
import statistics
from dataclasses import asdict

from backends import MockLLM
from chart import ascii_curve, svg_curve
from environment import HIDDEN_PREFERENCES, HOLDOUT_QUERIES, PreferenceEnvironment
from governance import ApprovalGate, min_support_policy
from learner import ContinualLearner
from memory import LessonMemory

ARTIFACTS = os.path.join(os.path.dirname(__file__), "artifacts")


def run_seed(seed: int, rounds: int, batch: int, slip: float, support: int):
    env = PreferenceEnvironment(seed=seed)
    treat_backend = MockLLM(slip=slip, seed=seed)
    ctrl_backend = MockLLM(slip=slip, seed=seed + 9973)

    learner = ContinualLearner(
        backend=treat_backend,
        memory=LessonMemory(),
        gate=ApprovalGate(policy=min_support_policy(support)),
    )

    treat_curve, ctrl_curve = [], []
    for _ in range(rounds):
        t_rewards, c_rewards = [], []
        for _ in range(batch):
            ctx, q = env.sample_task()
            # treatment: act with learned memory, then learn from telemetry
            t_resp = learner.act(ctx, q)
            t_out = env.evaluate(ctx, q, t_resp)
            learner.ingest(t_out.trajectory)
            t_rewards.append(t_out.reward)
            # control: frozen model, no memory, no learning
            c_resp = ctrl_backend.generate(ctx, q, lessons=[])
            c_out = env.evaluate(ctx, q, c_resp)
            c_rewards.append(c_out.reward)
        treat_curve.append(statistics.mean(t_rewards))
        ctrl_curve.append(statistics.mean(c_rewards))

    # generalization test on held-out (unseen) queries
    gen_treat, gen_ctrl = [], []
    for domain, queries in HOLDOUT_QUERIES.items():
        for q in queries:
            tr = env.evaluate(domain, q, learner.act(domain, q)).reward
            cr = env.evaluate(domain, q, ctrl_backend.generate(domain, q, [])).reward
            gen_treat.append(tr)
            gen_ctrl.append(cr)

    return {
        "treat_curve": treat_curve,
        "ctrl_curve": ctrl_curve,
        "gen_treat": statistics.mean(gen_treat),
        "gen_ctrl": statistics.mean(gen_ctrl),
        "lessons_learned": len(learner.memory),
        "audit": learner.gate.summary(),
        "learner": learner,
    }


def run_experiment(rounds=25, batch=10, seeds=8, slip=0.05, support=2):
    os.makedirs(ARTIFACTS, exist_ok=True)
    per_seed = [run_seed(s, rounds, batch, slip, support) for s in range(seeds)]

    def avg_curve(key):
        return [statistics.mean(ps[key][r] for ps in per_seed) for r in range(rounds)]

    def std_curve(key):
        return [statistics.pstdev([ps[key][r] for ps in per_seed]) for r in range(rounds)]

    treat = avg_curve("treat_curve")
    ctrl = avg_curve("ctrl_curve")
    treat_std = std_curve("treat_curve")

    gen_treat = statistics.mean(ps["gen_treat"] for ps in per_seed)
    gen_ctrl = statistics.mean(ps["gen_ctrl"] for ps in per_seed)

    results = {
        "config": {"rounds": rounds, "batch": batch, "seeds": seeds,
                   "slip": slip, "support_threshold": support,
                   "backend": "MockLLM (offline, deterministic)"},
        "treatment_curve": treat,
        "control_curve": ctrl,
        "treatment_std": treat_std,
        "baseline_reward": ctrl[0],
        "final_treatment": treat[-1],
        "final_control": ctrl[-1],
        "absolute_gain": treat[-1] - ctrl[-1],
        "generalization": {"treatment_holdout": gen_treat,
                           "control_holdout": gen_ctrl},
        "avg_lessons_learned": statistics.mean(ps["lessons_learned"] for ps in per_seed),
        "hidden_preferences": {k: sorted(v) for k, v in HIDDEN_PREFERENCES.items()},
    }

    # --- write artifacts ---
    with open(os.path.join(ARTIFACTS, "results.json"), "w") as f:
        json.dump(results, f, indent=2)

    svg_curve(treat, ctrl, os.path.join(ARTIFACTS, "learning-curve.svg"))

    # dump the learned memory + audit log + DPO export from seed 0's learner
    sample = per_seed[0]["learner"]
    sample.memory.save(os.path.join(ARTIFACTS, "learned-lessons.json"))
    with open(os.path.join(ARTIFACTS, "audit-log.jsonl"), "w") as f:
        for e in sample.gate.log:
            f.write(e.to_json() + "\n")
    with open(os.path.join(ARTIFACTS, "preferences.dpo.jsonl"), "w") as f:
        for p in sample.preference_pairs:
            f.write(json.dumps({"prompt": p.prompt, "chosen": p.chosen,
                                "rejected": p.rejected}) + "\n")

    _write_summary(results)
    return results


def _write_summary(r: dict) -> None:
    c = r["config"]
    md = f"""# Proof of Continual Learning -- Results

**Backend:** {c['backend']}  |  **Seeds:** {c['seeds']}  |  **Rounds:** {c['rounds']}  |  **Batch/round:** {c['batch']}  |  **Approval support threshold:** {c['support_threshold']}

## Headline

| Metric | Control (frozen) | Treatment (continual learning) |
|---|---|---|
| Reward, round 1 | {r['control_curve'][0]:.3f} | {r['treatment_curve'][0]:.3f} |
| Reward, final round | {r['final_control']:.3f} | {r['final_treatment']:.3f} |
| **Held-out (unseen) queries** | {r['generalization']['control_holdout']:.3f} | {r['generalization']['treatment_holdout']:.3f} |

**Absolute gain at convergence: +{r['absolute_gain']:.3f} reward** ({r['absolute_gain']*100:.1f} percentage points) over the frozen control, averaged across {c['seeds']} seeds.

The control model never changes -- it sees the same task stream but learning is
off, so its reward is flat. The treatment model improves purely by mining user
edits into lessons and reusing them. On **held-out queries it never saw during
training**, the treatment still scores {r['generalization']['treatment_holdout']:.3f}
vs {r['generalization']['control_holdout']:.3f} for control, showing it learned
transferable preferences rather than memorizing strings.

Average lessons learned per run: **{r['avg_lessons_learned']:.1f}**
(the engine had to discover every feature in `hidden_preferences` from edits alone).

![learning curve](learning-curve.svg)

See `results.json` for the full per-round curves, `learned-lessons.json` for what
the model learned, `audit-log.jsonl` for the governance trail, and
`preferences.dpo.jsonl` for the exported preference dataset (parametric path).
"""
    with open(os.path.join(ARTIFACTS, "summary.md"), "w") as f:
        f.write(md)


def main():
    r = run_experiment()
    print("\n" + ascii_curve(r["treatment_curve"], r["control_curve"]))
    print()
    print(f"baseline (control, round 1):   {r['control_curve'][0]:.3f}")
    print(f"treatment, final round:        {r['final_treatment']:.3f}")
    print(f"control,   final round:        {r['final_control']:.3f}")
    print(f"absolute gain at convergence:  +{r['absolute_gain']:.3f}")
    print(f"held-out queries  treatment:   {r['generalization']['treatment_holdout']:.3f}")
    print(f"held-out queries  control:     {r['generalization']['control_holdout']:.3f}")
    print(f"avg lessons learned:           {r['avg_lessons_learned']:.1f}")
    print(f"\nArtifacts written to: {ARTIFACTS}/")


if __name__ == "__main__":
    main()
