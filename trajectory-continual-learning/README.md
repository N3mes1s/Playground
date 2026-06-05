# Trajectory-CL — an open continual-learning engine

A working, **dependency-free** re-implementation of the core idea behind
[trajectory.ai](https://trajectory.ai/): a platform that makes a deployed AI
product **get smarter from being used** instead of staying frozen after training.

> trajectory.ai's thesis: *"The smartest thing we have ever built is the one that
> does not get smarter from being used."* Their core primitive is the **trajectory**
> = **trace** (what the agent did) + **telemetry** (how the user reacted — accepts,
> edits, corrections). Most stacks log the trace and throw the telemetry away. The
> telemetry is the learning signal. ([manifesto](https://trajectory.ai/field-notes/manifesto),
> [docs](https://docs.trajectory.ai/introduction))

This project rebuilds that loop end-to-end from public research, and — crucially —
ships a **reproducible experiment that proves the model measurably improves from
usage**, runnable offline with `python experiment.py`.

## The same four-stage loop trajectory.ai describes

| trajectory.ai stage | this engine | file |
|---|---|---|
| **Instrument** — capture signals from the product | `Recorder` SDK + typed `Trajectory` primitive | `sdk.py`, `schema.py` |
| **Understand** — mine patterns from real usage | edits → natural-language lessons + (chosen,rejected) pairs | `miner.py` |
| **Steer** — approve changes, full auditability | approval gate + append-only audit log | `governance.py` |
| **Learn** — improve continuously, deploy | retrieval memory (non-parametric) + DPO export (parametric) | `memory.py`, `learner.py`, `backends.py` |

```
 product usage                learning engine                       improved product
┌────────────┐   trajectory  ┌──────────┐  lessons  ┌──────────┐   ┌────────────────┐
│ agent acts │──(trace +     │  miner   │──────────▶│ approval │──▶│ retrieval memory│
│ user reacts│   telemetry)─▶│ understand│           │  gate    │   │  injected into  │
│ (edit/accept)              └──────────┘            │ (steer)  │   │  the next call  │
└────────────┘                                       └──────────┘   └────────┬───────┘
       ▲                                                                      │
       └──────────────── the model now applies what it learned ◀─────────────┘
```

## Prove it works (zero installs)

```bash
python experiment.py     # controlled A/B over 8 seeds, writes artifacts/
python tests.py          # 11 sanity/regression checks
python demo_sdk.py       # readable end-to-end walkthrough on one domain
```

`experiment.py` runs a clean **A/B with a control group** in a testbed with
*hidden* per-domain user preferences the model does not know (the setup from
[PRELUDE/CIPHER, Gao et al. 2024](https://arxiv.org/abs/2404.15269)):

- **Treatment** — the full engine: act with retrieved lessons, then learn from telemetry.
- **Control** — the *identical* model, but frozen (no retrieval, no learning).

Both arms see the same task stream. Measured result (averaged over 8 seeds, in
[`artifacts/`](artifacts/)):

| Metric | Control (frozen) | Treatment (continual learning) |
|---|---|---|
| Reward, round 1 | 0.000 | 0.217 |
| Reward, final round | **0.000** | **0.960** |
| Held-out (unseen) queries | 0.000 | 0.915 |

**+0.96 reward** over the frozen control, and **0.915 on queries it never saw in
training** — so it learned transferable preferences, not memorized strings.

![learning curve](artifacts/learning-curve.svg)

### Why the proof is honest, not rigged

The policy backend (`MockLLM`) has **no built-in knowledge** of the hidden
preferences. Its *only* way to satisfy them is to follow lessons handed to it in
context — and those lessons exist *only* if the engine mined them from user edits.
So every point of improvement is causally produced by the learning loop. The
control arm proves the baseline never moves on its own; the held-out test proves
it generalizes. The whole thing is deterministic and seeded, so anyone can
reproduce the exact numbers.

## Two ways "Learn" turns signal into improvement

1. **Non-parametric (default, no GPU):** approved lessons enter a retrieval
   memory and are injected into the model's context at inference time. Works with
   any closed model. Grounded in [ExpeL](https://arxiv.org/abs/2308.10144) and
   [Voyager](https://arxiv.org/abs/2305.16291).
2. **Parametric (export path):** the same edits become `(chosen, rejected)` pairs
   exported to `artifacts/preferences.dpo.jsonl`, ready for offline
   [DPO](https://arxiv.org/abs/2305.18290) fine-tuning — how the signal becomes
   weight updates.

## Run against a real LLM (optional)

```bash
export OPENAI_API_KEY=sk-...
python -c "from backends import OpenAILLM; from learner import ContinualLearner; \
print(ContinualLearner(OpenAILLM()).act('email','reply to the client').content)"
```
The same loop runs with natural-language lessons placed in the system prompt.

## Research foundations

Every design choice is backed by a stored paper. See
[`papers/RESEARCH.md`](papers/RESEARCH.md) for the annotated bibliography — the
PDFs themselves are checked in under [`papers/`](papers/) (continual-learning
survey, PRELUDE/CIPHER, ExpeL, Reflexion, Self-Refine, Voyager, DPO, InstructGPT,
Deep RL from Human Preferences).

## Files

| File | Purpose |
|---|---|
| `schema.py` | The `Trajectory` primitive (trace + telemetry) and JSONL store |
| `sdk.py` | `Recorder` — instrument a product, capture trajectories + telemetry |
| `miner.py` | Mine edits into lessons and (chosen,rejected) preference pairs |
| `governance.py` | Approval gate + append-only audit log (steer + auditability) |
| `memory.py` | Retrieval memory of learned lessons (non-parametric learning) |
| `backends.py` | `MockLLM` (offline, deterministic) and optional `OpenAILLM` |
| `learner.py` | The ingest → mine → govern → learn → retrieve orchestrator |
| `environment.py` | Testbed with hidden preferences + user-edit oracle |
| `experiment.py` | The controlled proof; writes `artifacts/` |
| `tests.py` / `demo_sdk.py` | Regression checks / readable walkthrough |
| `papers/` | Stored research PDFs + `RESEARCH.md` bibliography |

## Limitations (honest scope)

- The reproducible proof uses a simulated user oracle, deliberately, so it runs
  offline and deterministically. It demonstrates the *mechanism*; real deployments
  add LLM-based preference inference (the `OpenAILLM` path) and noisier signals.
- Feature extraction from free-text outputs is mocked structurally in the testbed;
  a production system uses an LLM judge (see `backends.OpenAILLM` notes).
- This is a playground experiment, not the trajectory.ai product — no weight
  hosting, no managed infra. It reproduces the *idea* and proves it works.
