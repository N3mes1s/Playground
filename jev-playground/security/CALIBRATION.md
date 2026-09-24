# Is Jev calibrated? An independent test

Does Jev's probability mean what it says? We score real labelled events (Atomic Red Team malicious + an admin/dev benign corpus) with Jev's malicious probability and check, per probability bin, the fraction that were truly malicious. Ground-truth labels, not a frontier-model reference.

- Events: **241** (150 malicious / 91 benign), eval base rate 0.62, model `jev-latest`
- **Expected Calibration Error 0.165**, Maximum CE 0.449, **Brier 0.139**
- Isotonic recalibration on held-out data: ECE 0.187 → 0.070, Brier 0.149 → 0.107 (recalibration helps)

> Base-rate caveat: this eval set is deliberately near-balanced so every bin has both classes. Real attack traffic is far rarer, so precision at a given threshold in production will be lower than here even if the probability stays calibrated. Calibration is a property of the score; precision also depends on base rate.

## Reliability table

| predicted p | events | malicious | mean predicted | actual fraction | gap |
|---|---|---|---|---|---|
| 0.0-0.1 | 24 | 3 | 0.078 | 0.125 | 0.047 |
| 0.1-0.2 | 59 | 12 | 0.133 | 0.203 | 0.071 |
| 0.2-0.3 | 25 | 13 | 0.237 | 0.520 | 0.283 |
| 0.3-0.4 | 11 | 5 | 0.347 | 0.455 | 0.107 |
| 0.4-0.5 | 14 | 9 | 0.447 | 0.643 | 0.196 |
| 0.5-0.6 | 14 | 14 | 0.551 | 1.000 | 0.449 |
| 0.6-0.7 | 13 | 13 | 0.647 | 1.000 | 0.353 |
| 0.7-0.8 | 25 | 25 | 0.755 | 1.000 | 0.245 |
| 0.8-0.9 | 32 | 32 | 0.849 | 1.000 | 0.151 |
| 0.9-1.0 | 24 | 24 | 0.927 | 1.000 | 0.073 |

## The payoff: threshold recipe

Calibration is what lets you *choose* an operating point instead of guessing. For a target false-positive budget, pick the threshold and get a known recall:

| false-positive budget | threshold | recall | actual FPR | precision (this set) |
|---|---|---|---|---|
| ≤ 1% | 0.50 | 72% | 0.0% | 100% |
| ≤ 5% | 0.45 | 75% | 3.3% | 97% |
| ≤ 10% | 0.35 | 81% | 7.7% | 95% |

## Full sweep

| threshold | recall | FPR | precision |
|---|---|---|---|
| 0.05 | 100% | 100.0% | 62% |
| 0.10 | 98% | 76.9% | 68% |
| 0.15 | 95% | 38.5% | 80% |
| 0.20 | 90% | 25.3% | 85% |
| 0.25 | 85% | 14.3% | 91% |
| 0.30 | 81% | 12.1% | 92% |
| 0.35 | 81% | 7.7% | 95% |
| 0.40 | 78% | 5.5% | 96% |
| 0.45 | 75% | 3.3% | 97% |
| 0.50 | 72% | 0.0% | 100% |
| 0.55 | 69% | 0.0% | 100% |
| 0.60 | 63% | 0.0% | 100% |
| 0.65 | 59% | 0.0% | 100% |
| 0.70 | 54% | 0.0% | 100% |
| 0.75 | 49% | 0.0% | 100% |
| 0.80 | 37% | 0.0% | 100% |
| 0.85 | 27% | 0.0% | 100% |
| 0.90 | 16% | 0.0% | 100% |
| 0.95 | 4% | 0.0% | 100% |

## Why this surpasses the earlier obstacle

Our EDR benchmark reported 26% Discovery recall *at a fixed 0.5 threshold* and concluded we didn't know where to set it. If the score is calibrated, that's no longer a wall: you set the threshold to the false-positive budget you can afford and read off the recall you get, per tactic. The number to trust is the gap column above — small gaps mean the probability can be used as a real operating dial, not just a ranking.

