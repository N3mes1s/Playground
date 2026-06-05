# carve

**An agent-run control plane over your dependencies: keep only the code you
actually use, own it as a small, provenance-tracked, reversible slice — so
vetting, justifying CVE exceptions, and patching each change becomes affordable.**

A typical project pulls hundreds of transitive crates it can neither read nor
control. `carve` inserts a layer you *do* control: it computes which code of each
dependency your product actually calls, transcribes **only that slice** verbatim
into a local `vendor/` tree, and links every byte back to upstream. That small,
owned slice is the multiplier — it's what makes the things you could never afford
to do over a full dependency tree cheap enough to do on every change:

- **Audit ergonomics.** An upgrade becomes "read this 200-line diff," not
  "re-audit a 20k-line crate." You stop pulling the whole crate on every bump.
- **Justified CVE exceptions (VEX).** Scanners flag by *package@version*
  regardless of whether you reach the vulnerable code. Because carve physically
  removes the code you don't use and keeps the usage graph as evidence, a
  "not-affected" exception becomes **auditable**, not a hand-wave — cutting the
  CVE-triage treadmill.
- **Patch without forking.** The code is already in your tree, minimal and owned,
  so an emergency fix (a CVE hotfix before upstream ships one) is a one-line edit
  recorded as a tracked delta (`carve patch`) — not a fork to host and babysit.
- **A gate for vetting updates.** Because the slice is small, scanning/reviewing
  *the next version of exactly the functions you use* before adopting it is
  tractable — the affordable per-update check whole-crate vendoring can't do.

Two invariants keep it honest:

- **Never invent code.** `carve` copies verbatim. Every vendored byte is
  SHA-256-linked to the upstream file it came from (the `carve.lock` ledger);
  intentional local fixes are recorded as explicit, tracked patches, never drift.
- **Always reversible.** Vendoring is a Cargo `[patch.crates-io]` entry; restoring
  removes it. `carve restore <crate>` puts you back on the registry dependency.

**What it is and isn't.** carve is a supply-chain *control plane and audit-surface
reducer*, across ecosystems (in Rust the linker already strips unused code from
the binary, so the win is the source you own and audit; in Python/JS/etc. the full
dependency ships, so it shrinks the runtime surface too). It is **not**, by itself,
an anti-malware tool: code you actually call is kept verbatim, so a malicious
update of a *used* function is caught by the update-vetting gate above (and your
proof-read of that small diff), not by slicing. Claims here are scoped to that.

> Status: **Stages 1–6 working.** DFUG, provenance ledger, verbatim vendoring,
> reversibility, verification, the autonomous-agent tool surface, agent-driven
> **module + single-item slicing** with an **attack-surface reduction %** readout,
> update-impact analysis, a **live LLM agent** over the same tool surface,
> **deep transitive vendoring** (dependencies of dependencies, incl. native
> `*-sys`) on the 90-crate `sharkdp/fd`, and **(Stage 6)** `carve harden` — the
> autonomous one-command pipeline — run at scale on `BurntSushi/ripgrep`
> (43-crate closure → **−56% LOC, −34% `unsafe`** across the crates worth owning;
> with an honest finding that optimized build time is unchanged). See the
> [STAGE-2-3](STAGE-2-3-REPORT.md), [STAGE-4](STAGE-4-REPORT.md),
> [STAGE-5](STAGE-5-REPORT.md), and [STAGE-6](STAGE-6-REPORT.md) reports;
> architecture in [DESIGN.md](DESIGN.md).

## Install / build

```bash
cargo build --release   # produces target/release/carve
```

## Commands

| Command | What it does |
|---|---|
| `carve analyze [--transitive]` | Build the Dependency Functional Usage Graph (DFUG): which dependency items your product references, how often, and from where. `--transitive` builds it across the WHOLE closure (dependencies of dependencies). Flags unreferenced deps as drop candidates. |
| `carve plan` | The agent reads the DFUG and proposes, per crate, whether item-level slicing is safe (HIGH), needs a verification build (MED), or should be vendored whole for now (LOW). |
| `carve vendor <crate> [--apply]` | Transcribe a crate verbatim into `vendor/`, recording provenance in `carve.lock`. `--apply` also wires the reversible `[patch.crates-io]` entry. |
| `carve harden [--transitive] [--budget N] [--min-reduction PCT]` | **The whole pipeline, autonomously, in one command.** Vendors the closure, detects which crates are actually compiled for this target, has the agent slice every one, reverts crates that shed less than `--min-reduction` % (not worth owning), and reports the aggregate attack-surface reduction **and the clean `--release` build-time delta**. `--test` runs the consumer's test suite as a behavioral gate; re-runs are incremental (intact slices are reused). |
| `carve vendor-all [--apply] [--transitive]` | Vendor every direct dependency in one shot, or the ENTIRE transitive closure with `--transitive` (native-linked sys crates and duplicated-version crates are left on the registry and reported). |
| `carve slice <crate> [--llm] [--items] [--budget N]` | **The agent** carves the vendored crate down to only what the product needs, running `cargo check` against the real consumer and keeping only what still compiles. Reports the **attack-surface reduction %** (files/LOC/items/bytes/`unsafe`). `--items` adds item-level slicing via cheap **compiler-guided convergence** (two error-guided phases — value/type symbols, then `impl` blocks — ~O(reference-depth) checks); `--budget N` opts into an extra per-item catch-all. `--llm` lets a model plan the module cuts (needs `ANTHROPIC_API_KEY`). `--test` adds a behavioral gate (runs the consumer's test suite, not just compile). The compiler gates every cut. |
| `carve llm-check` | Verify LLM-agent connectivity (needs `ANTHROPIC_API_KEY`). |
| `carve impact <crate> --to <ver> [--diff] [--scan]` | Assess whether moving to an upstream version touches code inside your slice (and which items you call). `--diff` prints the exact unified diff of the in-slice changes (the bounded proof-read surface); `--scan` runs an LLM security review of that diff (backdoor/exfiltration check, needs `ANTHROPIC_API_KEY`). |
| `carve restore <crate>` | Reverse it: remove the patch, delete the vendored tree, drop the ledger entry. |
| `carve status` | Show the provenance ledger. |
| `carve verify` | Re-hash vendored files and confirm they still match the ledger (the "proof-read" guarantee); accepts files recorded as intentional patches. |
| `carve patch <crate>` | Record local edits to a vendored crate (e.g. an emergency CVE hotfix) as tracked provenance deltas, so they're deliberate — not drift — and an upgrade can re-base them. |
| `carve locate <crate> <item>` | Agent locates the upstream definition site of a used item — the slice it would transcribe. |
| `carve tools` | List the tool surface available to the autonomous agent. |

Global flags: `--verbose`, `--log-json` (structured NDJSON for replay), and the
`RUST_LOG` env var (e.g. `RUST_LOG=carve=debug`).

## Example (dogfooded on this very crate)

```console
$ carve analyze
Dependency Functional Usage Graph — carve
  dependencies referenced: 13

  anyhow v1.0.102  —  5 item(s), 48 ref(s)
       32×  anyhow::Result
        4×  anyhow::Context
        4×  anyhow::bail
  serde_json v1.0.150  —  6 item(s), 31 ref(s)
       16×  serde_json::Value
        8×  serde_json::json
  ...

$ carve vendor walkdir --apply --note "proof-read at v2.5.0"
Vendoring walkdir v2.5.0 (verbatim) …
  transcribed 20 file(s) -> vendor/walkdir-2.5.0
  added [patch.crates-io] walkdir -> vendor/walkdir-2.5.0

$ carve verify
  OK   walkdir v2.5.0 (20 files match ledger)

$ carve restore walkdir          # fully reversible
Restored walkdir to its upstream dependency (patch + vendor dir removed).
```

## Configuration (`carve.toml`)

Drop a `carve.toml` (or `.carve.toml`) next to your `Cargo.toml` to set policy.
CLI flags override the config; the config overrides built-in defaults.

```toml
# carve.toml
transitive    = true     # vendor/slice the whole closure (deps of deps)
min_reduction = 10.0     # revert a slice below this LOC % back to upstream
budget        = 0        # per-crate item-slice refinement checks

# Crates carve must NOT vendor or slice — kept as normal upstream dependencies.
# Use for deps you'd rather track upstream, native crates, or ones that don't
# slice well. Merged with any --exclude flags.
exclude = ["openssl-sys", "ring"]
```

Then `carve harden` (or `vendor-all`) reads it automatically. `--exclude <crate>`
on the command line is merged with the config's `exclude` list.

## How it works

```
 source tree                  cargo metadata
      │                              │
      ▼                              ▼
  syn AST scan  ──────────►  resolve dep idents/versions
      │                              │
      └──────────────┬───────────────┘
                     ▼
        Dependency Functional Usage Graph        (carve analyze)
                     │
                     ▼
            agent minimization plan              (carve plan)
                     │   keep only used items
                     ▼
     verbatim transcribe + SHA-256 ledger        (carve vendor)
                     │   reversible [patch]
                     ▼
          cargo check / build verifies           (agent tool: cargo_check)
                     │
                     ▼
       carve.lock  ◄──────────►  carve restore   (lossless round-trip)
```

The DFUG extractor is deliberately **conservative**: it resolves `use` imports
and value/type/macro path references syntactically and *under-reports* (e.g. it
won't guess the type behind a method call) rather than inventing edges. The
agent's `cargo check` gate is what ultimately proves a slice is complete — so the
system can *select* code but never *fabricate* it.

See [DESIGN.md](DESIGN.md) for the threat model, the agent architecture, and the
roadmap toward agent-driven item-level slicing and a real-project fork.

## Limitations

- **Verification is compile-only, not behavioral.** A slice is verified to compile
  (debug *and* release), but `cargo check` passing does not prove the slice
  *behaves* identically — removing e.g. a `Drop`, a ctor/`inventory` registration,
  or feature/target-gated runtime code can compile yet change behavior. The right
  fix (next on the roadmap) is to run the upstream crate's **own test suite**
  against the slice. **Until that lands, treat a sliced crate as needing the
  upstream tests run before production use.**
- Slicing is **target-specialized**: carving a crate's ARM/WASM backends pins the
  vendored copy to your build target. The compiler gates every cut, so the result
  always compiles. Item-level slicing converges cheaply (compiler-guided,
  ~O(reference-depth) checks) in two phases — value/type symbols, then `impl`
  blocks via method/trait errors. `--budget` adds an optional per-item catch-all
  for any residue.
- **Whole-closure `harden` is an offline/CI batch job**, not a per-build gate:
  per-crate slicing is rebuild-bound (minutes), so a 100+ crate closure runs for
  a while. Interactive use is `analyze` to find high-value targets, then `slice`
  them individually (seconds-to-minutes).
- Transitive `[patch]` can't express a crate present at **multiple versions**;
  those are vendored for the record but left on the registry.
- The DFUG resolver is syntactic, not a full type resolver. It maps `pkg-name`
  to `pkg_name` and honors `use` renames, but won't follow re-exports or resolve
  method-call receiver types. It errs toward under-reporting.
- `carve impact` matches changed item idents against used path segments (a
  heuristic); it flags the right files but the per-item "used API" match can be
  coarse for common names.
- Rust-only.
