# Why signatures lose (and where they don't): mutation robustness

The mechanism companion to the LOLBin result. We take real attack commands that a **precise signature covers**, apply mild behaviour-preserving mutations (`mutations.py`), and check whether detection survives. `sig (tight)` = the specific low-false-positive signature (the most distinctive Sigma keyword pattern covering the original) still matches; `sig (broad)` = any rule from the huge noisy ruleset still matches; `jev` = Jev still flags malicious. Model `jev-latest`.

- Signature-covered attacks tested: **60**

| mutation | sig (tight) | sig (broad) | Jev | n |
|---|---|---|---|---|
| clean | 100% | 100% | 65% | 60 |
| case_flip | 100% | 100% | 70% | 60 |
| flag_alias | 93% | 100% | 79% | 14 |
| whitespace_pad | 95% | 98% | 65% | 60 |
| quote_insert | 97% | 100% | 69% | 59 |

## Reading this (the honest, and surprising, result)

We expected mild mutation to collapse signatures. It did not -- and that is the finding.

- **clean**: the tight signature matches 100% by construction; Jev's rate is its natural recall on these commands.
- **case_flip** (control): good signatures are case-insensitive, so it does not hurt them.
- **flag_alias / whitespace_pad / quote_insert** change the spelling but not the behaviour, yet the *precise* signature mostly survives (93-100%). Why: the tightest signature keys on a **durable artifact** -- a full path, a binary name, an API like `comsvcs.dll MiniDump` -- that these mild mutations do not touch. The folklore that any mutation defeats signatures is overstated for durable-artifact rules.
- On these **signature-covered** attacks, Jev's recall is *lower* than the precise signature. That is expected: these are exactly the attacks signatures were built for.

## What this means for where Jev fits

Jev does not replace good signatures. Where a precise, durable signature exists, it is cheap, exact and mutation-robust -- keep it. Jev earns its place on what signatures *cannot* express: the dual-use / LOLBin space where the strings are identical for attacker and admin (LOLBIN_GAP.md, AUC 0.65 vs 0.94) and novel behaviour with no rule yet. The two are complementary: signatures for the known and durable, Jev for the ambiguous and novel, both at full coverage.

- The **sig (broad)** column stays ~100% only because that ruleset matches almost everything, including 100% of benign activity (LOLBIN_GAP.md). High recall there is noise, not detection.

> Caveat: mild, textbook transformations and a keyword approximation of Sigma, not a full engine. Stronger obfuscation (tool renaming for bring-your-own tools, encoding chains) would erode even durable-artifact signatures further; this run deliberately stays mild.

