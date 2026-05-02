# Feature A/B: balanced vs safe (n=48 matched)

## Aggregate metrics

| metric | A: balanced | B: safe | Δ |
|---|---|---|---|
| literal caught_rate | 52% | 56% | +4pp |
| judge caught_rate | 38% | 40% | +2pp |
| judge useful_rate | 100% | 100% | +0pp |
| max family share | 67% | 58% | -8pp |
| launch_strategy_ok | 71% | 71% | +0pp |

_A: --prefer balanced (default 0.30/0.25/0.30/0.15)._
_B: --prefer safe (0.15/0.20/0.50/0.15)._

## Winner-family distribution

| variant | A: balanced | B: safe |
|---|---|---|
| `mvp_fast` | 32 | 18 |
| `robust_launch` | 0 | 2 |
| `standard` | 16 | 28 |

## Per-element judge-verdict transitions

| transition | count |
|---|---|
| partial -> partial | 21 |
| caught -> caught | 10 |
| partial -> caught | 9 |
| caught -> partial | 8 |

## Verdict

> **TENTATIVE: apply with care.** judge caught_rate up +2pp; family-share down -8pp; both small. Consider a held-out validation before persisting (cycle-4 lesson).