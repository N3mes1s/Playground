# carve benchmark — noise reduction & false-clear audit

Reproducible via `carve/bench/run.sh` + `carve/bench/verify.py`. Each finding from `cargo audit` is triaged by `carve triage`; every `not_affected` verdict is then checked against an **independent oracle** that re-derives presence and runtime-reachability directly from cargo's resolve graph (`cargo metadata`), in a separate implementation from carve's. A clear the oracle can't justify is a **false clear**.

Target triaged for: `linux/x86_64`.

## Per-project

| project | findings | cleared (not-affected) | needs review | affected | noise ↓ (cleared) | noise ↓ (cleared+review) |
|---|---:|---:|---:|---:|---:|---:|
| bandwhich | 2 | 1 | 0 | 1 | 50% | 50% |
| delta | 10 | 1 | 0 | 9 | 10% | 10% |
| delta-0.13.0 | 19 | 1 | 1 | 17 | 5% | 10% |
| gitui-v0.22.1 | 23 | 9 | 6 | 8 | 39% | 65% |
| mdbook-v0.4.21 | 25 | 5 | 2 | 18 | 20% | 28% |
| starship-v1.10.3 | 28 | 3 | 1 | 24 | 10% | 14% |
| zoxide-v0.8.3 | 7 | 2 | 0 | 5 | 28% | 28% |
| **total** | **114** | **22** | **10** | **82** | **19%** | **28%** |

## Headline

- **19%** of `cargo audit` findings are cleared with a machine-checkable justification (suppressible now).
- **28%** are moved out of the "affected" bucket (cleared or down-prioritized to needs-review).
- **False clears: 0** — every `not_affected` verdict is backed by the independent cargo-resolve oracle.

## Interpretation — and an honest comparison to the market

The reachability-SCA vendors market **80–92%** noise reduction (Endor Labs ~92%,
Socket ~80%). carve's **19% cleared / 28% incl-review** looks far worse — so here
is exactly why, measured, not hand-waved:

- **78% of these findings are whole-crate advisories** (89/114: 35 unmaintained,
  20 yanked, 21 unsound, and vulns with no function list). There is no function to
  reason about — if the crate ships, it is `affected`. **No reachability tool,
  call-graph or otherwise, clears these.** The vendors' headline numbers are
  measured on a friendlier denominator: function-named CVEs in ecosystems
  (JS/Java) whose advisories carry far richer call data than RustSec, where most
  entries are informational/whole-crate.
- **Only 25/114 findings even name a vulnerable function.** Restricted to real
  *vulnerability* advisories the rate is higher: **15% cleared, 39% incl-review**
  (38 findings).
- **All 22 of carve's clears are structural**: 10 `not-in-execute-path`
  (dev/build-only), 10 platform-gated (`vulnerable_code_not_present`), 2
  `component_not_present`. carve contributes **zero** clears from "the vulnerable
  function isn't called" — it parks those ~9 cases in **needs-review**, because a
  *syntactic* DFUG can't prove non-reachability soundly. A call-graph tool clears
  them (lifting its %) by trusting its call graph; carve refuses, trading the
  number for the property below.

So the benchmark states carve's real position plainly:

- **What carve wins on today: a provable, independently-audited `0` false
  clears**, plus structural clears (platform / build-vs-runtime) that
  function-reachability tools can *miss*. That is the trust axis.
- **Where carve is behind: raw noise reduction.** Closing it needs real
  call-graph reachability to safely convert *needs-review → cleared*. That is the
  single highest-value item on the roadmap — bounded above by the 78% whole-crate
  ceiling that constrains every tool in this space.

## What the oracle checks

- `component_not_present` → crate must be absent from cargo's resolved package set.
- `vulnerable_code_not_in_execute_path` → crate must be unreachable via normal-only edges (a separate BFS over the resolve graph).
- `vulnerable_code_not_present` → the advisory's `os`/`arch` must exclude the target.

## Honest scope

- `affected` means "ships and is reached", not "exploitable"; the human still judges exploitability.
- `needs review` is **not** counted as cleared — carve is recall-biased and never downgrades a reached-but-unconfirmed crate to safe.
- The oracle and carve both consume cargo's authoritative resolve graph; they are independent *implementations*, so a divergence catches a carve bug (it is a cross-implementation check, not a fully orthogonal exploit oracle).
