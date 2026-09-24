# The dual-use / LOLBin detection gap Jev closes

Attackers use the same built-in tools admins do (certutil, rundll32, wmic, powershell, curl, PsExec). A keyword/IOC **signature** sees identical strings for both, so it cannot separate them -- it fires on the attack *and* the admin. An **LLM** could judge intent but is too slow/costly to run on every event. Jev is the first option that is both semantic and cheap enough for full coverage.

Measured on the SAME events -- real Atomic Red Team attacks vs a genuine dual-use admin/dev corpus (250 attacks / 91 benign), model `jev-latest`:

| approach | ROC AUC (separation) |
|---|---|
| Sigma keyword signatures (rules-fired count) | 0.645 |
| Jev malicious probability | 0.935 |

(0.5 = no better than a coin flip at telling attack from admin.)

- The naive **'a signature fired' alert**: catches 97% of attacks but also fires on 100% of benign dual-use activity -- the false-positive storm every SOC knows.

## True-positive rate at a false-positive budget

The number a SOC lives by: how many attacks you catch while keeping benign noise under a budget you can staff.

| false-positive budget | signatures | Jev |
|---|---|---|
| ≤ 1% | 4% | 73% |
| ≤ 5% | 25% | 79% |
| ≤ 10% | 34% | 84% |

## Why this was unsolvable before

- **Signatures** are string matchers. On dual-use binaries the strings are identical for attacker and admin, so no rule can separate them -- the AUC above is near a coin flip and 'any rule fired' lights up on all the benign admin traffic too.
- **LLMs** can read intent, but at seconds and cents per call you cannot run one on every process event, so you sample a fraction and the rest goes uninspected.
- **Jev** judges intent semantically like an LLM, at ~0.5 s and ~$0.00002 per event, so it runs on 100% of events. That combination -- semantic separation of dual-use activity at full-coverage cost -- is the capability that did not exist before, and it is what turns the LOLBin gap from unsolvable into a tunable operating point.

> Caveat: the signature baseline is a generous keyword approximation of Sigma (see `sigma_extract.py`), not a full Sigma engine with logsource/field context; and Jev is not a full EDR. This measures the *separability ceiling* of string matching vs semantics on dual-use commands, which is the point.

