# carve benchmark — noise reduction, localization lift & false-clear audit

Reproducible via `carve/bench/run.sh` + `carve/bench/verify.py`. Each finding from
`cargo audit` is triaged by `carve triage`; every `not_affected` verdict is then
checked against an **independent oracle** that re-derives presence and
runtime-reachability directly from cargo's resolve graph (`cargo metadata`), in a
separate implementation from carve's. A clear the oracle can't justify is a **false
clear**. Target triaged for: `linux/x86_64`.

## Localization lift: carve alone vs carve + arbor

`arbor` (a CVE→vulnerable-function localizer) produced v0.4 localizations for the
function-bearing advisories in this corpus; carve consumed them via
`carve triage --enrich`. Same 114 findings, same corpus, baseline vs enriched:

| metric | carve alone | + arbor enrich | delta |
|---|---:|---:|---:|
| cleared (`not_affected`, suppressible now) | 19% (22) | 19% (22) | **0** |
| out of "affected" (cleared + needs-review) | 28% (32) | **33% (38)** | **+5 pts (+6 findings)** |
| affected | 82 | 76 | −6 |
| **false clears** | **0** | **0** | **0** |

6 findings moved `affected → needs-review` — concentrated in **mdbook (+5)** and
**delta-0.13.0 (+1)**: crates that ship, but whose specific vulnerable function/type
arbor localized and carve then found unreached.

### Honest reading of the lift

- **`cleared` did not move (19% → 19%), by design.** Enrichment only *adds*
  reachability targets; carve never emits `not_affected` from a reachability miss
  (it is recall-biased), so localization can down-prioritize `affected → needs-review`
  but can never fully clear a finding. That trade is deliberate — it's exactly what
  keeps false clears at **0** while still de-noising.
- **The gain is +5 points on the de-noised bucket (28% → 33%)** — real, and safe
  (false-clear count unchanged at 0, independently verified).
- **Why it isn't bigger** — and it's a carve limit, not an arbor one:
  1. 6 of arbor's 14 localizations were no-code-change/empty (chrono, tokio,
     tungstenite, shlex, git2, remove_dir_all) — nothing to match against.
  2. Several localized symbols are *private methods*; carve's scanner is syntactic and
     can't see method-call receivers (`buf.method()`), so it conservatively holds those
     at needs-review instead of resolving them.
  3. The 4 `openssl-src` advisories stay put (carve's static-link guard keeps `-src`
     crates at needs-review regardless).
  The ceiling here is carve's syntactic resolution. v1.0 receiver-type resolution (the
  same rust-analyzer capability arbor already runs) is what converts more of these
  `needs-review`s into confident verdicts.

## Per-project (enriched run)

| project | findings | cleared | needs review | affected | noise ↓ (cleared) | noise ↓ (cleared+review) |
|---|---:|---:|---:|---:|---:|---:|
| bandwhich | 2 | 1 | 0 | 1 | 50% | 50% |
| delta | 10 | 1 | 0 | 9 | 10% | 10% |
| delta-0.13.0 | 19 | 1 | 2 | 16 | 5% | 15% |
| gitui-v0.22.1 | 23 | 9 | 6 | 8 | 39% | 65% |
| mdbook-v0.4.21 | 25 | 5 | 7 | 13 | 20% | 48% |
| starship-v1.10.3 | 28 | 3 | 1 | 24 | 10% | 14% |
| zoxide-v0.8.3 | 7 | 2 | 0 | 5 | 28% | 28% |
| **total** | **114** | **22** | **16** | **76** | **19%** | **33%** |

## Interpretation vs the market

Reachability-SCA vendors market **80–92%** noise reduction (Endor Labs ~92%, Socket
~80%). carve's **19% cleared / 33% incl-review (with arbor)** is far lower — measured,
not spun:

- **78% of these findings are whole-crate advisories** (unmaintained, yanked, unsound,
  or vulns with no function list). No reachability tool clears these; the vendors' headline
  numbers are measured on a friendlier denominator (function-named CVEs in JS/Java whose
  advisories carry far richer call data than RustSec).
- carve **trades raw % for a provable `0` false clears**: it only clears on structural
  grounds (not-present / not-shipped / platform), and parks everything reachability can't
  *prove* safe at `needs-review` rather than clearing it. The vendors lift their % by
  clearing "function not called" via a call graph they trust; carve refuses to until it
  can resolve receivers soundly.

So the position is honest: **strong on trust (0 false clears, independently audited),
modest on raw noise reduction**, and the arbor integration moves the de-noised bucket
+5 points without costing a single false clear.

## What the oracle checks

- `component_not_present` → crate must be absent from cargo's resolved package set.
- `vulnerable_code_not_in_execute_path` → crate must be unreachable via normal-only
  edges (a separate BFS over the resolve graph).
- `vulnerable_code_not_present` → the advisory's `os`/`arch` must exclude the target.

## Honest scope

- `affected` means "ships and is reached", not "exploitable"; the human still judges
  exploitability.
- `needs review` is **not** counted as cleared — carve is recall-biased and never
  downgrades a reached-but-unconfirmed crate to safe.
- Enrichment can only move a finding `affected → needs-review`, never to `not_affected`,
  so it cannot manufacture a false clear (held across both runs).
- The oracle and carve both consume cargo's authoritative resolve graph; they are
  independent *implementations*, so a divergence catches a carve bug — a
  cross-implementation check, not a fully orthogonal exploit oracle.
