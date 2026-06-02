# carve — design notes

## The problem

A `cargo update` (or `npm install`, or `pip install -U`) pulls whole upstream
releases. Three things go wrong:

1. **Supply-chain compromise.** A maintainer account is phished, a build server
   is owned, a typo-squat is published — and the next release ships malware. You
   find out after it's in your build.
2. **Attack surface.** You call three functions from a crate; you ship all of it.
   Every unused module is reachable code an attacker can pivot through if another
   bug lets them.
3. **CVE exposure.** A CVE lands in a dependency module you never call. You're now
   "affected" by scanners, owe an upgrade, and inherit the upgrade's risk — for
   code you don't use.

## The thesis

Invert the default. Pull **only the code you call**, transcribed **verbatim** at
a version you have **proof-read**, into a tree **you** control, with a durable
**link** back to upstream so upgrades are a reviewable diff — and make the whole
thing **reversible** so it's never a trap.

Two invariants make this trustworthy rather than just another vendoring hack:

- **Verbatim, never invented.** Every vendored byte is a copy of an upstream
  byte, SHA-256-linked to the source file and version in `carve.lock`. carve
  *selects* code; it never *writes* code. This is what lets a human (or a model)
  proof-read a bounded, faithful slice instead of auditing a whole crate.
- **Reversible.** Vendoring is a Cargo `[patch.crates-io]` entry over a local
  path; restoring removes it. If a slice turns out incomplete or a real upstream
  fix lands, `carve restore` puts you back on the registry in one step.

## Pipeline

### 1. Dependency Functional Usage Graph (DFUG) — `carve analyze`

`cargo metadata` enumerates declared dependencies and resolves versions. A `syn`
visitor walks every `.rs` file and records each reference into a dependency:

- `use` imports build a *local-name → fully-qualified-path* table.
- Value paths (`ExprPath`), type paths (`TypePath`), and macro invocations resolve
  their leading segment: a known dependency ident → fully-qualified reference; an
  import alias → expanded; anything else → local/std, ignored.

Output: per crate, the distinct items used and every product call site
(`file:line`), plus **declared-but-unreferenced** deps (the cheapest win: delete
them). The resolver is intentionally syntactic and under-reports rather than
inventing edges — completeness is enforced downstream by compilation, not guessed
here.

### 2. Minimization plan — `carve plan`

The agent reads the DFUG and classifies each crate by how safe a syntactic slice
is:

- **HIGH** — narrow, value/type-only surface → item-level slice is safe.
- **MED** — wider surface → slice, but gate on a verification build.
- **LOW** — macro-bearing surface (macros expand to unknown code) → vendor whole
  for now, slice later under verification.

This is a *proposal*, emitted before anything is written, so it can be reviewed.

### 3. Transcribe — `carve vendor`

Stage 1 copies the whole crate source verbatim into `vendor/<crate>-<version>/`,
hashing every file into the `carve.lock` ledger, and (with `--apply`) adds the
reversible patch. Whole-crate vendoring is the *safe floor*: always correct,
already an improvement (you build your own bytes at a pinned, hashed version).

Stage 2 narrows this to the item level (below).

### 4. Verify / proof-read — `carve verify`

Re-hashes vendored files against the ledger. The contract: **vendored bytes equal
the bytes we recorded equal the upstream bytes.** Upgrading a dependency becomes:
re-transcribe at the new version → `git diff vendor/` → read it → commit. The diff
*is* the audit.

### 5. Reverse — `carve restore`

Remove the patch, delete the vendored tree, drop the ledger entry. Verified to
round-trip and rebuild against upstream.

## The agent

The agent is defined by a **tool surface** (`Tool` trait, JSON in/out) plus a
driver. Tools today: `read_file`, `sha256`, `parse_items` (syn top-level items),
`cargo_check` (the compilation gate). Everything is instrumented with `tracing`
spans, so a run is replayable from `--log-json` output — the "whole observability
layer" the idea calls for.

- **`RuleBasedAgent`** (ships now): deterministic. Produces the minimization plan
  and can locate upstream definition sites via the tool surface (`carve locate`).
- **`LlmAgent`** (Stage 2): the *same* tool surface handed to a model. The model
  proposes which items + transitive helpers form a minimal compilable slice; every
  proposal is checked by `cargo_check`. Because the model can only point at
  existing upstream spans (and the result must compile against our real call
  sites), it can select but not fabricate. Observability + the verbatim/hash
  invariant are the guardrails.

## Roadmap

- **Stage 1 (done):** DFUG, plan, verbatim vendor, provenance ledger, verify,
  reversibility, agent tool surface, observability. Dogfooded on `carve`.
- **Stage 2:** Agent-driven item-level slicing — compute the transitive
  intra-crate closure of each used item, transcribe just those spans into a
  shape-preserving module tree, and iterate against `cargo_check` until the slice
  compiles against our real call sites. Record the kept-items → upstream-spans
  link in `carve.lock`.
- **Stage 3:** Fork a real Rust project, run carve end-to-end, and report the
  attack-surface / LOC / CVE-exposure reduction versus upstream.

## Why Rust first

`cargo metadata` gives exact dependency resolution, `syn` gives a faithful AST,
and `[patch.crates-io]` gives lossless reversibility for free. The crate-source
registry cache is the verbatim ground truth to transcribe from. The concepts
(usage graph → minimal slice → provenance link → reversible vendor) generalize to
other ecosystems later.
