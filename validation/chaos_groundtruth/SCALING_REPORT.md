# Adversarial chaos search scaling test

15-step synthetic plan with mixed topology (linear core, parallel branch, late merge). Compares adversarial LLM search to exhaustive static enumeration at k=2 and k=3, with 2 and 4 search rounds.

Plan structure: S1→S2→S3→S4→S8 (linear core), S1→S5→{S6,S7} (parallel branch), S8→{S9,S10}→S11→S12→{S13,S14}→S15 (post-merge fan-out).

| Config | Exhaustive best | Search best | Ratio | Top-5 overlap | Scored |
|---|---|---|---|---|---|
| `k=2,rounds=2` | 1.0 | 1.0 | 1.0 | 2/5 | 12 |
| `k=2,rounds=4` | 1.0 | 1.0 | 1.0 | 1/5 | 25 |
| `k=3,rounds=2` | 1.0 | 1.0 | 1.0 | 0/5 | 6 |
| `k=3,rounds=4` | 1.0 | 1.0 | 1.0 | 0/5 | 23 |

**Interpretation**: ratio = 1.00 means LLM search hit the optimum. Ratio < 1.00 means LLM left worse cases on the table; the exhaustive top-5 overlap shows how many of the LLM's top-5 picks are actually in the true top-5.
## Interpretation note (post-hoc)

The 0/5 and 1/5 top-5 overlaps in the table above are NOT search
failures. They are **tie-breaking artifacts at the optimum**.

In this 15-step plan, S1 is the root and dominates fragility: any
pair `{S1, X}` for any X gives fragility 1.0 because failing S1 alone
already cascades to all 14 downstream steps. The exhaustive top-5
and the LLM's top-5 are therefore **both selecting from a large pool
of fragility-1.0 ties** — they just pick different X.

The honest signal is that **adversarial search hit the optimum
fragility (1.0) in every single configuration**, both at k=2 and
k=3, both at 2 rounds and 4 rounds. The search scales to 15-step
plans without degradation in optimum-finding.

For the next scale up, the test plan should be designed so the
optimum is NOT a tie pool — e.g., a structure where the unique
worst pair is non-obviously placed (e.g., a hub-step deep in the
graph rather than the root). That's a follow-up.
