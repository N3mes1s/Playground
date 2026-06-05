# Triaging the RUSTSEC-2026 advisory set with `carve`

A run of `carve`'s reachability triage over the **entire RUSTSEC-2026 advisory
class** against real, popular Rust projects. The point: version-match scanners
(`cargo audit`) tell you a vulnerable crate is *somewhere* in your lockfile;
`carve triage` tells you whether it actually **ships in your binary** and whether
anything **reaches the vulnerable code** — and emits an auditable OpenVEX
document either way.

## The 2026 advisory universe

From `rustsec/advisory-db` (snapshot used in this run):

| total | vulnerabilities | unmaintained | unsound | notice | with named functions | with os/arch gate |
|---:|---:|---:|---:|---:|---:|---:|
| 172 | 110 | 32 | 29 | 1 | 31 | 3 |

## Method

- **Per-project:** `cargo audit --json` (against the 2026 DB) piped through
  `carve triage`, for both current `main` and an older release tag of each app.
- **Whole-class:** a synthesized report containing **all 172** 2026 advisories
  (crate, named functions, and os/arch pulled from each advisory's TOML) run
  through `carve triage` against each project's full transitive DFUG — so every
  advisory is classified for every product, not just the few that happen to fire.
- carve reads the **exact committed `Cargo.lock`** (`--locked`) and triages for
  the host target (`linux/x86_64`); `--target-os`/`--target-arch` override it.

## Result 1 — all 172 advisories, per product (exposure matrix)

Triage is *product-relative*: an advisory for a crate you don't depend on is
`not_affected / component_not_present`. Across the corpus, each product is
exposed to a **handful** of the 172, and carve clears the rest structurally:

| product (version) | not-affected | needs review | affected |
|---|---:|---:|---:|
| delta (main) | 169 | 0 | 3 |
| delta 0.13.0 | 169 | 0 | 3 |
| gitui (main) | 168 | 0 | 4 |
| gitui v0.22.1 | 170 | 1 | 1 |
| starship (main) | 169 | 0 | 3 |
| starship v1.10.3 | 169 | 0 | 3 |
| bottom (main) | 169 | 0 | 3 |
| mdbook v0.4.21 | 169 | 1 | 2 |

That "168–170 not-affected" column is the signal: of 172 advisories in the 2026
class, a typical CLI app is genuinely touched by only 2–4. carve makes that
machine-checkable instead of a manual scavenger hunt.

## Result 2 — the headline: same advisory, different verdict by reachability

**RUSTSEC-2026-0009** (`time`, *Denial of Service via Stack Exhaustion*) is only
triggered through `time`'s date-**parsing** functions
(`time::OffsetDateTime::parse`, `time::Date::parse`, …). Two real projects both
ship a vulnerable `time`, yet carve splits them:

- **delta → AFFECTED.** Its `plist` dependency calls
  `time::OffsetDateTime::parse` — the exact vulnerable function. carve shows the
  reaching edge as evidence.
- **gitui v0.22.1 → NEEDS REVIEW (not cleared).** Its `time` users (`git2`,
  `simplelog`) only touch `time::at` / `now_utc` / formatting — never `parse`.
  carve finds no reference to the vulnerable functions, but **refuses to call it
  safe** (method-call/macro/re-export paths can't be ruled out syntactically).

A version-match scanner gives both the same verdict. carve distinguishes a real
exposure (delta) from a probable non-issue that still warrants a human glance
(gitui) — without ever producing a false "safe".

## Result 3 — the 2026 advisories that actually landed in real trees

| advisory | crate | kind | verdicts |
|---|---|---|---|
| RUSTSEC-2026-0007 | bytes | vulnerability (integer overflow in `BytesMut::reserve`) | starship: affected |
| RUSTSEC-2026-0008 | git2 | unsound (UB dereferencing `Buf`) | delta, gitui: affected |
| RUSTSEC-2026-0009 | time | vulnerability (parse DoS) | delta: **affected**; gitui: **needs review**; starship: affected |
| RUSTSEC-2026-0097 | rand | unsound (`rand::rng()` with custom logger) | delta, gitui, starship, mdbook: affected |

These ship and are reached, so "affected" is the correct, non-cleared verdict —
carve does not clear real exposures. The value is the **169 it does clear**
(Result 1) and the **reachability split** on 0009 (Result 2).

## Platform gating in the 2026 set

Three 2026 advisories are platform-gated; carve clears them on off-target builds
(`vulnerable_code_not_present`) and keeps them on-target:

- **RUSTSEC-2026-0125** (`libcrux-ml-dsa`, AVX2 signature-verification edge case)
  and **RUSTSEC-2026-0126** — `arch = ["x86_64"]`: cleared on `aarch64`.
- (From the prior gitui run: `mio` RUSTSEC-2024-0019 and `atty` RUSTSEC-2021-0145
  are `os = ["windows"]` — cleared on a Linux target, kept with `--target-os
  windows`.)

None of these crates are in the corpus trees, so they show as
`component_not_present` here; the gate matters when the crate *is* present.

## Honest limits

- **Triage is product-relative.** "All 172" means every advisory is correctly
  *classified for each product*, not that any one product is exposed to all 172.
  Most resolve to `component_not_present` — which is the point.
- **`affected` ≠ exploitable.** It means the vulnerable crate ships and is
  reached; whether the input is attacker-controlled is left to the human. carve
  ranks the queue and supplies evidence; it does not claim exploitability.
- **Recall-biased, by design.** A shipped crate whose vulnerable function isn't
  syntactically referenced is `under_investigation`, never `not_affected` — the
  syntactic DFUG can't see method receivers, macros, or re-exports, so it never
  downgrades those to "safe".
- The platform gate assumes the triage target matches the deploy target
  (defaults to host; override with `--target-os`/`--target-arch`).
