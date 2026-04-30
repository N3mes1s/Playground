# Held-out validation of GEPA cycle 4 winner

_n=6 elements, disjoint from cycle-4 eval slice (see `validation/holdout_ids.txt`)._

## A: GEPA winner active (`pareto_extra.txt` loaded)

- useful_rate: **100%**
- caught_rate: 67%
- missed_rate: 0%
- SMT feasibility: 61%
- family share max: 50%

## B: GEPA winner OFF (empty extension)

- useful_rate: **100%**
- caught_rate: 67%
- missed_rate: 0%
- SMT feasibility: 56%
- family share max: 50%

## Verdict

- on **useful_rate**: tie — useful (caught+partial) rate A=100% → B=100%
- on **balanced composite**: A better — composite useful + 0.5*smt - 0.5*family-bias: A=1.056 → B=1.028

**Generalises:** True  
**Regression:** False

> The GEPA winner reproduces a positive signal on a disjoint slice; keep `mirofish_lab/pareto_extra.txt`.