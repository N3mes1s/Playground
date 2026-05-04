# Chaos primitives ground-truth validation

Synthetic plans with known cascade structure validate FOUR chaos primitives end-to-end:

1. **LLM probe** (chaos_probe) — per-step blocked-downstream    prediction by an LLM; compared to true downstream by Jaccard.
2. **Static cascade** (chaos_static) — graph-based exact    computation; correct by construction.
3. **Adversarial search** (chaos_search) — LLM Attacker proposes    worst-K combinations, scored by static cascade; compared to    exhaustive-static optimum.
4. **Monte Carlo** (chaos_montecarlo) — per-gate failure priors +    N-sample simulation; sanity-checked against topology fragility.

## 1. LLM probe Jaccard

| Topology | Steps | Probes | Avg Jaccard | Underpred. | Overpred. | Empty preds |
|---|---|---|---|---|---|---|
| `linear_chain` | 5 | 4 | 1.0 | 0.0 | 0.0 | 0/4 |
| `diamond` | 4 | 3 | 1.0 | 0.0 | 0.0 | 0/3 |
| `parallel` | 5 | 1 | 1.0 | 0.0 | 0.0 | 0/1 |

**Aggregate LLM Jaccard**: 1.0

## 2. Static cascade exactness

Pure graph computation; should be 100% by construction.

| Topology | Per-step correctness |
|---|---|
| `linear_chain` | 5/5 |
| `diamond` | 4/4 |
| `parallel` | 5/5 |

**All topologies exact?**: YES

## 3. Adversarial search vs exhaustive static

Adversarial search uses LLM proposals scored by static cascade. Ratio = search_best / exhaustive_best. 1.0 means the LLM found the exhaustive optimum; <1.0 means it left worse cases on the table.

| Topology | Rounds | Proposed | Scored | Search best | Exhaustive | Ratio | Search top set | Exhaustive top set |
|---|---|---|---|---|---|---|---|---|
| `linear_chain` | 2 | 12 | 9 | 1.0 | 1.0 | 1.0 | ['S1', 'S2'] | ['S1', 'S2'] |
| `diamond` | 2 | 8 | 6 | 1.0 | 1.0 | 1.0 | ['S1', 'S2'] | ['S1', 'S2'] |
| `parallel` | 2 | 14 | 10 | 1.0 | 1.0 | 1.0 | ['S1', 'S2'] | ['S1', 'S2'] |

**Average ratio (LLM / exhaustive)**: 1.0

## 4. Monte Carlo sanity

Higher-fragility topologies (linear chain) should have LOWER Monte Carlo full-success rates than parallel fan-outs. This is a structural sanity check, not a calibration.

| Topology | Avg success | p10 | Full success | Full failure |
|---|---|---|---|---|
| `linear_chain` | 0.891 | 0.4 | 0.822 | 0.038 |
| `diamond` | 0.917 | 0.5 | 0.852 | 0.028 |
| `parallel` | 0.933 | 0.8 | 0.822 | 0.038 |
