# carve

**Carve out only the dependency code you actually use — transcribe it verbatim,
track its provenance, and stay reversible.**

Modern supply chains make it nearly impossible to be sure a new dependency
release is safe. `carve` attacks the problem from the other end: instead of
pulling whole crates (and their whole attack surface, and their whole CVE
exposure) on every `cargo update`, it figures out *which code of each dependency
your product actually calls*, and lets an agent transcribe **only that slice**
into a local `vendor/` tree — byte-for-byte identical to upstream, never invented.

You get two wins:

1. **Supply-chain attacks can't reach you.** You build against your own vendored
   copy, proof-read at a known version. A malicious `1.2.4` upstream release
   doesn't touch you until *you* re-transcribe and re-read the diff.
2. **Smaller attack surface and CVE exposure.** You only carry the code you use.
   A CVE in a dependency module you never call simply isn't in your tree.

Two hard constraints keep it honest:

- **Never invent code.** `carve` copies verbatim, in the same shape as upstream.
  Every vendored byte is SHA-256-linked back to the exact upstream file it came
  from (the `carve.lock` ledger). Upgrading = re-transcribe + read the diff.
- **Always reversible.** Vendoring is a Cargo `[patch.crates-io]` entry; restoring
  removes it. Round-trip is lossless — `carve restore <crate>` puts you back on
  the registry dependency, and the project still builds.

> Status: **Stages 1–5 working.** DFUG, provenance ledger, verbatim vendoring,
> reversibility, verification, the autonomous-agent tool surface, agent-driven
> **module + single-item slicing** with an **attack-surface reduction %** readout,
> update-impact analysis, a **live LLM agent** over the same tool surface, and
> **deep transitive vendoring** (dependencies of dependencies) — including native
> `*-sys` crates — proven on the 90-crate, 6-level-deep `sharkdp/fd`. See the
> [STAGE-2-3](STAGE-2-3-REPORT.md), [STAGE-4](STAGE-4-REPORT.md), and
> [STAGE-5](STAGE-5-REPORT.md) reports; architecture in [DESIGN.md](DESIGN.md).

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
| `carve vendor-all [--apply] [--transitive]` | Vendor every direct dependency in one shot, or the ENTIRE transitive closure with `--transitive` (native-linked sys crates and duplicated-version crates are left on the registry and reported). |
| `carve slice <crate> [--llm] [--items] [--budget N]` | **The agent** carves the vendored crate down to only what the product needs, running `cargo check` against the real consumer and keeping only what still compiles. Reports the **attack-surface reduction %** (files/LOC/items/bytes/`unsafe`). `--items` adds item-level slicing via cheap **compiler-guided convergence** (two error-guided phases — value/type symbols, then `impl` blocks — ~O(reference-depth) checks); `--budget N` opts into an extra per-item catch-all. `--llm` lets a model plan the module cuts (needs `ANTHROPIC_API_KEY`). The compiler gates every cut. |
| `carve llm-check` | Verify LLM-agent connectivity (needs `ANTHROPIC_API_KEY`). |
| `carve impact <crate> --to <ver>` | Assess whether moving to an upstream version touches code inside your slice (and which items you call) — i.e. whether the update needs a proof-read or is safe to take. |
| `carve restore <crate>` | Reverse it: remove the patch, delete the vendored tree, drop the ledger entry. |
| `carve status` | Show the provenance ledger. |
| `carve verify` | Re-hash vendored files and confirm they still match the ledger (the "proof-read" guarantee). |
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

- Slicing is **target-specialized**: carving a crate's ARM/WASM backends pins the
  vendored copy to your build target. The compiler gates every cut, so the result
  always compiles. Item-level slicing converges cheaply (compiler-guided,
  ~O(reference-depth) checks) in two phases — value/type symbols, then `impl`
  blocks via method/trait errors. `--budget` adds an optional per-item catch-all
  for any residue.
- Transitive `[patch]` can't express a crate present at **multiple versions**;
  those are vendored for the record but left on the registry.
- The DFUG resolver is syntactic, not a full type resolver. It maps `pkg-name`
  to `pkg_name` and honors `use` renames, but won't follow re-exports or resolve
  method-call receiver types. It errs toward under-reporting.
- `carve impact` matches changed item idents against used path segments (a
  heuristic); it flags the right files but the per-item "used API" match can be
  coarse for common names.
- Rust-only.
