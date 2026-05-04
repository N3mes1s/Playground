# N=30 re-baseline diff: with vs without `pareto_extra.txt`

_Same 29 elements (seed 1337, 5 sources). Comparing the cycle-4 winner directive at scale against the prior baseline._

## Aggregate metrics

| metric | A: no extension | B: with extension | Δ |
|---|---|---|---|
| useful_rate | 97% | 87% | -10pp |
| caught_rate | 33% | 20% | -13pp |
| missed_rate | 3% | 13% | +10pp |
| SMT feasibility | 82% | 82% | +0pp |
| family share max | 47% | 67% | +20pp |

## Per-element verdict transitions

| transition | count |
|---|---|
| partial -> partial | 16 |
| caught -> partial | 4 |
| caught -> caught | 4 |
| partial -> missed | 2 |
| partial -> caught | 1 |
| missed -> missed | 1 |
| caught -> missed | 1 |

## Verdict

- on **useful_rate**: A better — useful (caught+partial) rate A=97% → B=87%
- on **balanced composite**: A better — composite useful + 0.5*smt - 0.5*family-bias: A=1.144 → B=0.944
