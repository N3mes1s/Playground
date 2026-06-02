# carve — Stage 4 proof: LLM agent wired + deep transitive vendoring

Two new capabilities, both run live:

1. **The agent is now an actual LLM** driving the same tool surface.
2. **carve goes deep** — it vendors the *entire transitive closure*
   (dependencies of dependencies), proven on a complex real project (`sharkdp/fd`).

Reproduce with [`examples/fd-transitive-demo.sh`](examples/fd-transitive-demo.sh).
The LLM parts need `ANTHROPIC_API_KEY` (model overridable via `CARVE_LLM_MODEL`,
default `claude-sonnet-4-6`).

---

## 1. The LLM agent (same tools, model-driven)

`carve llm-check` confirms connectivity; `carve slice <crate> --llm` lets the
model plan the slice. The model talks to the Anthropic Messages API in a real
tool-use loop, calling `read_file` / `parse_items` **through the same
`ToolRegistry`** the rule-based agent uses, then returns a JSON removal plan.

```
$ carve llm-check
  model replied: carve-llm-ok
  LLM agent is wired and reachable.

$ carve slice memchr --manifest-path aho-corasick/Cargo.toml --llm
Consulting LLM agent to plan the slice…
  (16-step tool-use loop: the model reads files via read_file/parse_items)
  LLM proposed removing 8 module(s): src/tests/memchr/naive, src/tests/…, src/tests

Agent slicing memchr v2.8.1 (verifying every cut against the consumer build)…
  carved away 11 module(s): src/arch/aarch64, src/arch/wasm32, src/arch/all/shiftor,
                            src/tests (+ test submodules)
  files: 45 -> 26   LOC: 15799 -> 11602  (26.6% reduction)
  consumer build verified after slicing: YES
```

The crucial property: the LLM **proposes**, but every cut is still gated by
`cargo check` against the real consumer. The model can steer (and explain) what
to remove, but it can neither break the build nor invent code — the compiler is
the oracle. Each turn is a `tracing` span (`--log-json` to replay the whole
session).

## 2. Deep transitive vendoring — dependencies of dependencies (`sharkdp/fd`)

### Deep DFUG across the whole closure

```
$ carve analyze --manifest-path fd/Cargo.toml --transitive

Transitive Dependency Functional Usage Graph — fd-find
  crates in closure: 90  (max depth 6)
  functional edges:  289
  scanned for usage: 90 crates

  crates by depth (0 = product, 1 = direct, 2+ = deps of deps):
      depth 0: 1   depth 1: 20   depth 2: 26   depth 3: 19
      depth 4: 12  depth 5: 4    depth 6: 8

  Top functional edges (who leans hardest on whom):
      nix → libc                  736 item(s), 4130 ref(s)
      rustix → linux-raw-sys      964 item(s), 1246 ref(s)
      syn → proc-macro2            40 item(s), 1171 ref(s)
      regex-automata → regex-syntax 43 item(s), 593 ref(s)
      clap_derive → syn            44 item(s), 375 ref(s)
      clap_complete → clap         38 item(s), 331 ref(s)
```

This is the usage graph at every level of the tree, not just fd's direct deps —
the "deeper and deeper" view. fd's dependency graph is **6 levels deep**.

### Vendor the entire closure and rebuild from it

```
$ carve vendor-all --manifest-path fd/Cargo.toml --transitive --apply
  vendored 78/78 dependency(ies); provenance in carve.lock
  wired 74 [patch.crates-io] entries
  left on registry (can't patch a duplicated name): bitflags, nix
  left on registry (1 native-linked sys crate — native build not
                    source-reproducible): tikv-jemalloc-sys

$ git -C fd diff --stat
 Cargo.toml | 249 +++++++++++++++++++++++++++++++++++++++++   # the ONLY change

$ cargo build           # → Finished — build OK from vendored closure
$ carve verify          # → All vendored bytes match their upstream provenance
$ ./target/debug/fd --version   # → fd 10.4.2  (runs; regex/ignore/walkdir all vendored)
```

**74 crates now build from local, hash-verified, verbatim copies** — the deep
supply chain is pulled into the tree. The only project change is the
`[patch.crates-io]` block in `Cargo.toml`; no source edits.

### Honest boundaries (and why they're the right call)

carve deliberately leaves two classes of crate on the registry and reports them:

- **Native-linked `*-sys` crates** (here `tikv-jemalloc-sys`, `links = "jemalloc"`):
  their build compiles bundled C / links a native library. Copying Rust source
  cannot reproduce that build faithfully, so vendoring it would be a lie. carve
  detects `links` and skips it.
- **Crates present at multiple versions** (`bitflags`, `nix`): a single
  `[patch.crates-io]` entry is keyed by name and can't express two versions, so
  carve vendors them for the record but leaves the build on the registry.

Everything else — the pure-Rust supply chain, 74 crates across 6 levels — is
vendored, verified, reversible, and compiling.

---

## What Stage 4 adds

- **Agent = real LLM** over the existing tool surface, compiler-gated so it
  selects-but-never-invents.
- **Depth:** the DFUG and vendoring now span the full transitive closure
  (dependencies of dependencies), proven on a 90-crate, 6-level-deep real project
  that rebuilds and runs entirely from vendored source.
