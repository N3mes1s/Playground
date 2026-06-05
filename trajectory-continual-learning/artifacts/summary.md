# Proof of Continual Learning -- Results

**Backend:** MockLLM (offline, deterministic)  |  **Seeds:** 8  |  **Rounds:** 25  |  **Batch/round:** 10  |  **Approval support threshold:** 2

## Headline

| Metric | Control (frozen) | Treatment (continual learning) |
|---|---|---|
| Reward, round 1 | 0.000 | 0.217 |
| Reward, final round | 0.000 | 0.960 |
| **Held-out (unseen) queries** | 0.000 | 0.915 |

**Absolute gain at convergence: +0.960 reward** (96.0 percentage points) over the frozen control, averaged across 8 seeds.

The control model never changes -- it sees the same task stream but learning is
off, so its reward is flat. The treatment model improves purely by mining user
edits into lessons and reusing them. On **held-out queries it never saw during
training**, the treatment still scores 0.915
vs 0.000 for control, showing it learned
transferable preferences rather than memorizing strings.

Average lessons learned per run: **14.0**
(the engine had to discover every feature in `hidden_preferences` from edits alone).

![learning curve](learning-curve.svg)

See `results.json` for the full per-round curves, `learned-lessons.json` for what
the model learned, `audit-log.jsonl` for the governance trail, and
`preferences.dpo.jsonl` for the exported preference dataset (parametric path).
