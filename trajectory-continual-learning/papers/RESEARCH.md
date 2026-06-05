# Research foundations

Continual learning from product usage — the idea behind [trajectory.ai](https://trajectory.ai/)
— is not new magic; it sits on a well-developed research literature. This folder
**stores the primary papers** (PDFs, downloaded from arXiv) and maps each one to
the part of this engine it justifies. Read this file first, then open the PDFs.

The thesis trajectory.ai states ("the smartest thing we built is the one that does
not get smarter from being used", their [manifesto](https://trajectory.ai/field-notes/manifesto))
is exactly the *catastrophic-forgetting / frozen-model* problem the continual
learning literature studies.

| # | Paper (stored PDF) | arXiv | What we take from it |
|---|--------------------|-------|----------------------|
| 1 | `2404.16789_continual-learning-LLMs-survey.pdf` | [2404.16789](https://arxiv.org/abs/2404.16789) | **Framing.** Comprehensive survey of continual learning for LLMs (continual pre-training / fine-tuning / alignment; rehearsal, regularization, architecture methods). Defines the problem space and catastrophic forgetting. |
| 2 | `2404.15269_aligning-agents-from-user-edits-PRELUDE-CIPHER.pdf` | [2404.15269](https://arxiv.org/abs/2404.15269) | **Our core method.** "Aligning LLM Agents by Learning Latent Preference from User Edits" (Gao et al., 2024). PRELUDE infers latent preferences from user *edits*; CIPHER retrieves inferred preferences from the k-closest contexts. This is the blueprint for `miner.py` + `memory.py` and for the `environment.py` testbed. |
| 3 | `2308.10144_ExpeL-experiential-learners.pdf` | [2308.10144](https://arxiv.org/abs/2308.10144) | **Non-parametric continual learning.** ExpeL agents extract natural-language insights from experience and reuse successful cases in-context — *no weight updates*, works with closed models. Justifies our lesson-memory "Learn" backend. |
| 4 | `2303.11366_reflexion.pdf` | [2303.11366](https://arxiv.org/abs/2303.11366) | **Verbal reinforcement.** Reflexion converts feedback into reflective text kept in memory to improve later attempts. Basis for turning telemetry into reusable lessons. (ExpeL extends this from intra-task to inter-task.) |
| 5 | `2303.17651_self-refine.pdf` | [2303.17651](https://arxiv.org/abs/2303.17651) | **Feedback → revision loop.** Self-Refine shows a model improving outputs from iterative feedback; conceptual model for the correct→learn→apply cycle. |
| 6 | `2305.16291_voyager.pdf` | [2305.16291](https://arxiv.org/abs/2305.16291) | **Skill library = growing memory.** Voyager accumulates reusable skills over a lifetime and retrieves them — the "memory that compounds over time" trajectory.ai pitches. |
| 7 | `2305.18290_direct-preference-optimization-DPO.pdf` | [2305.18290](https://arxiv.org/abs/2305.18290) | **Parametric path.** DPO (Rafailov et al., 2023) trains directly on (chosen, rejected) pairs with a simple classification loss — exactly the pairs `miner.py` exports to `preferences.dpo.jsonl`. This is how learned signal becomes weight updates. |
| 8 | `2203.02155_instructGPT-RLHF.pdf` | [2203.02155](https://arxiv.org/abs/2203.02155) | **RLHF.** InstructGPT (Ouyang et al., 2022): aligning models to human feedback. The original "learn from human signal" recipe DPO simplifies. |
| 9 | `1706.03741_deep-RL-from-human-preferences.pdf` | [1706.03741](https://arxiv.org/abs/1706.03741) | **Preference learning roots.** Christiano et al. (2017): learning reward models from human preference comparisons — the foundation under RLHF/DPO. |

## How the literature maps to the code

```
trajectory.ai concept          this engine            grounded in
─────────────────────────────────────────────────────────────────────────────
Instrument (capture signals)   sdk.py / schema.py     PRELUDE edit signals [2]
Understand (mine patterns)     miner.py               PRELUDE/CIPHER [2], Reflexion [4]
Steer (approve, audit)         governance.py          RLHF human oversight [8]
Learn — non-parametric         memory.py + learner.py ExpeL [3], Voyager [6]
Learn — parametric (export)    miner.py DPO export     DPO [7], InstructGPT [8], [9]
The "frozen model" problem     environment.py proof   CL survey [1]
```

## Why our proof is a faithful small-scale instance

The survey [1] defines continual learning as retaining and accumulating knowledge
across a stream of experience without forgetting. PRELUDE [2] instantiates that for
*user edits*: a hidden latent preference, discovered only from corrections,
retrieved by context similarity. `environment.py` reproduces that exact setup at a
scale that runs offline and deterministically — so the learning curve in
`../artifacts/` is a reproducible demonstration of the same mechanism, not a mock-up.
