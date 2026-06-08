# llmake — design & reasoning

> *"There is all this stuff, which I want to process/compute over in this
> iterated way, with some build artifacts being important/worth saving.
> GNU Autotools × Notion or something. Is anyone building this?"*

This document captures **why** llmake is shaped the way it is, so the
reasoning survives the code.

## 1. The problem

A recurring pattern across research, writing, analysis, and engineering:

1. You accumulate **source material** — markdown notes, specs, transcripts,
   scraped pages, prior outputs, code.
2. You want to **compute over it with LLMs**, repeatedly: summarize, critique,
   extract, rewrite, cross-reference, refactor.
3. The intermediate and final outputs are **artifacts worth keeping** —
   versioned, diffed, and shared.
4. The loop is **iterative**: tweak one input or prompt, re-run, compare.

Today this lives in scattered chat threads and one-off scripts. Two things are
missing: **artifacts are not first-class**, and **recompute is not
incremental**. Change one source doc and you have no idea what's now stale.

## 2. The key insight: it's a build system

The user's own metaphor is the design. "GNU Autotools × Notion" decomposes
cleanly:

- **Autotools / make** = the *compute* model. Sources have dependencies;
  targets are derived; a build tool figures out the minimal recompute. This is
  exactly what's missing from LLM workflows.
- **Notion** = the *content* model. A workspace of documents and context you
  edit collaboratively, with structure and history.

So llmake is a **`make` whose source files are your notes/context and whose
compiler is an LLM (or a coding agent)**. Targets form a DAG; each target
compiles to a cached artifact; only what changed recomputes.

Reframing "LLM workflow tool" as "build system for inference" is the single
decision everything else falls out of. It gives us, for free, the concepts of
incrementality, reproducibility, dependency tracking, and artifact provenance —
all well-understood from `make`/`bazel`/`dvc`.

## 3. Mapping requirements → modules

The request had five pillars. Each is an isolated, swappable module so the MVP
stays small and every pillar can grow independently.

| Requirement | Module | MVP decision |
|---|---|---|
| Manage input files (markdown) + general context | `context.py` | Glob patterns → loaded files; separate `inputs` vs shared `context`. |
| Inference workflows + stored prompts | `spec.py` + `graph.py` | Declarative `llmake.yaml`; a reusable prompt library; a target DAG with topo-sort + cycle detection. |
| Coding agents, not just chat | `providers/` | One `Provider` interface; chat (`anthropic`) **and** agent (`claude-agent`) backends are peers behind it. |
| Compiled, shareable outputs | `cache.py` + `export.py` | Content-addressed incremental cache; one self-contained HTML bundle for sharing. |
| Real-time collaboration + snapshots/VCS | `snapshot.py` | **Git-backed snapshots** in MVP; real-time collab is a documented future seam. |

The orchestrator (`runner.py`) is deliberately thin — it only sequences the
modules above. The CLI (`cli.py`) is a thin shell over the library API
(`load_workflow`, `build`, `status`), so llmake is usable as a library too.

## 4. The cache: what makes it "make"

A target's cache key is a hash over **everything that can change its output**:
the fully-rendered prompt (which already contains the input/context text), the
provider, the model, the params, and — transitively — its upstream artifacts'
keys. If the key matches the last build and the artifact still exists, the
target is up to date and is skipped.

Consequence: change one note, and only the targets *downstream* of it
recompute. This is the property that turns an expensive pile of LLM calls into
a cheap, iterative loop. It's also what makes builds reproducible across
machines — the cache index (`.llmake/cache.json`) is small and commit-friendly.

## 5. Why "providers" are the right abstraction

The hard requirement "access to general-purpose coding agents (and not just
chat models)" is the reason inference is behind a single `Provider` interface
that speaks two dataclasses (`InferenceRequest` / `InferenceResult`). A chat
model and a coding agent differ enormously in mechanics (one round-trip vs. a
tool-using loop that edits files), but llmake only cares that both turn a
materialized request into artifact text. So:

- `echo` — offline, deterministic, zero-dependency. **The default**, so the
  whole tool runs with no API keys / no network (and powers the tests/CI).
- `anthropic` — a hosted chat model.
- `claude-agent` — shells out to the Claude Code CLI in the workspace, so a
  step can be *"read these files and refactor,"* not just *"answer this."* File
  edits land in the workspace; the agent's summary becomes the artifact.

Adding a backend (OpenAI, a local model, a different agent harness) is one
subclass + one registry line. Nothing else changes.

## 6. Scope: what's in the MVP and what's deferred

**In:** the build graph, incremental cache, prompt library, pluggable
chat/agent providers, git snapshots, HTML export, an offline default, an
end-to-end example, and tests.

**Deliberately deferred (seams left in place):**

- **Real-time collaboration.** True multi-cursor editing needs a CRDT/sync
  layer (e.g. y-py) and a server. MVP leans on git for the "snapshots / VCS
  integration" half of the requirement; the `snapshot.py` interface
  (`snapshot` / `list_snapshots`) is where a live-sync backend would slot in.
- **A web UI (the "Notion" surface).** The library/CLI is the engine; a GUI is
  a separate front-end over the same `load_workflow` / `build` API.
- **Hosted artifact sharing.** `export.py` produces a portable file today;
  publishing it to a URL is an add-on, not a core concern.
- **Richer inputs** (binaries, URLs, DB queries) and **cost/eval tracking**
  per build — both extend existing modules without touching the engine.

## 7. Prior art — "is anyone building this?"

Pieces exist; the *combination* (build-system semantics over an editable
content workspace, with agents as first-class compilers) is the gap llmake
probes:

- **promptfoo / LangChain LCEL / LangGraph / DSPy** — compose and evaluate LLM
  steps, but they're code-first pipelines, not an incremental build over an
  editable document workspace with saved artifacts.
- **DVC / Make / Bazel** — exactly the incremental-build model, but for data/code,
  not prompt+context+agent steps.
- **Notion / Obsidian** — the content workspace and collaboration, but no
  notion of *compiling* documents through inference into versioned artifacts.
- **Cursor / Claude Code** — agents over a repo, but transient: no declared DAG
  of reusable prompts, no cached/shareable build artifacts.

llmake's bet: sit in the middle — `make`'s dependency graph, Notion's editable
source material, and agents-or-models as interchangeable compilers.
