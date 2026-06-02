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

> Status: **Stage 1** (this experiment). The Dependency Functional Usage Graph,
> provenance ledger, verbatim vendoring, reversibility, verification, and the
> autonomous-agent tool surface all work today and are dogfooded on `carve`
> itself. Agent-driven *item-level* slicing is Stage 2 — see [DESIGN.md](DESIGN.md).

## Install / build

```bash
cargo build --release   # produces target/release/carve
```

## Commands

| Command | What it does |
|---|---|
| `carve analyze` | Build the Dependency Functional Usage Graph (DFUG): which dependency items your product references, how often, and from where. Flags unreferenced deps as drop candidates. |
| `carve plan` | The agent reads the DFUG and proposes, per crate, whether item-level slicing is safe (HIGH), needs a verification build (MED), or should be vendored whole for now (LOW). |
| `carve vendor <crate> [--apply]` | Transcribe a crate verbatim into `vendor/`, recording provenance in `carve.lock`. `--apply` also wires the reversible `[patch.crates-io]` entry. |
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

## Limitations (Stage 1)

- Vendoring is whole-crate verbatim for now; item-level slicing is Stage 2.
- The DFUG resolver is syntactic, not a full type resolver. It maps `pkg-name`
  to `pkg_name` and honors `use` renames, but won't follow re-exports or resolve
  method-call receiver types. It errs toward under-reporting.
- Rust-only.
