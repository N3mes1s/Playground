# llmake

**A build system for LLM inference workflows.** *GNU Autotools × Notion.*

Treat your notes, specs, and context as **source**. Declare a DAG of
prompt/agent steps in an `llmake.yaml`. Compile them into **cached, shareable
artifacts**. Re-running only recomputes what changed — like `make`, but the
compiler is a [DSPy](https://dspy.ai) program (or a coding agent).

> Born from the question: *"There is all this stuff which I want to
> process/compute over in an iterated way, with some build artifacts being
> worth saving. Is anyone building this?"* — see **[DESIGN.md](DESIGN.md)** for
> the full reasoning.

## Why

Most LLM work is one-off: paste context into a chat, get an output, copy it
somewhere, lose track of which inputs produced it. Change one source doc and
nothing tells you what's now stale. llmake makes the **artifacts first-class**
and the **recompute incremental**.

## The model

| Concept | What it is |
|---|---|
| **Workspace** | A folder of input files (markdown/…) + shared context. |
| **Prompt library** | Reusable, named prompts (files or inline). |
| **Target** | One node in the build graph → compiles to one artifact. |
| **Provider** | The inference backend. **DSPy** is the engine; a coding agent is also a peer. |
| **Cache** | Content-addressed; only stale targets recompute. |
| **Snapshot** | A git commit+tag of the build artifacts. |
| **Export** | A self-contained HTML bundle of all artifacts, for sharing. |

## Install

```bash
pip install -r requirements.txt        # PyYAML + dspy (the engine)
# or, to get the `llmake` command:
pip install -e .
```

DSPy talks to any model via LiteLLM. Set the key for whatever you use:

```bash
export OPENAI_API_KEY=...        # for openai/* models
export ANTHROPIC_API_KEY=...     # for anthropic/* models
# (OpenRouter, Azure, local vLLM, etc. all work — see DSPy/LiteLLM docs)
```

No key handy? Every command accepts `--provider echo`, a deterministic offline
stub, so you can drive the mechanics without calling a model.

### Choosing the model (keep it in the environment, not the config)

Any [LiteLLM](https://docs.litellm.ai/docs/providers) model works via the `dspy`
provider. Account-specific choices belong in your environment, not committed
YAML, so the default model/provider resolve in this order:

```
--model / --provider flag  >  target's value  >  manifest `defaults`
  >  $LLMAKE_MODEL / $LLMAKE_PROVIDER  >  built-in (dspy / openai/gpt-4o-mini)
```

So set it once in your shell (or the remote env) and leave the manifests portable:

```bash
# Example: Fireworks-hosted Kimi K2.6 (a reasoning model)
export FIREWORKS_API_KEY=fw_...
export LLMAKE_MODEL=fireworks_ai/accounts/fireworks/models/kimi-k2p6
# reasoning models need token headroom — set per-workflow: params: {max_tokens: 8000}
```

Now `llmake build` uses Kimi without any model string hardcoded in the repo.

## Quickstart

```bash
cd examples/research-notes
export PYTHONPATH=$(cd ../.. && pwd)        # if you didn't `pip install -e .`
alias llmake="python3 -m llmake.cli"

llmake graph                  # show the dependency DAG
llmake build                  # compile via DSPy (needs an API key)
llmake build --provider echo  # ...or drive it offline, no key needed
llmake build                  # again -> all cached, nothing recomputes
llmake build -j4              # compile independent targets concurrently
llmake export -o build/export.html     # shareable bundle
```

Edit `inputs/notes.md`, run `llmake build` again, and watch only `summary` and
its descendants (`critique`, `report`) rebuild.

## Workflow manifest (`llmake.yaml`)

```yaml
version: 1
project: research-notes

defaults:
  provider: dspy
  model: openai/gpt-4o-mini   # LiteLLM format: openai/*, anthropic/*, openrouter/*
  params:
    temperature: 0.7
    module: predict           # dspy program: predict | cot | rlm

prompts:                      # the stored, reusable prompt library
  summarize: prompts/summarize.md       # file ref
  critique: prompts/critique.md

inputs:
  - inputs/*.md
context:
  - context/*.md              # shared with every step

targets:                      # the build DAG; each -> build/<name>.md
  summary:
    prompt: summarize
    inputs: [inputs/notes.md, inputs/interview.md]
    params: {module: cot}     # chain-of-thought for this step
  critique:
    prompt: critique
    needs: [summary]
  report:
    prompt: |
      Combine the summary and critique into a final brief.
      {{needs:summary}}
      {{needs:critique}}
    needs: [summary, critique]
    # provider: claude-agent   # or compile this step as a coding agent
    # kind: agent
```

### DSPy modules (per target, via `params.module`)

| `module` | DSPy program | Use it for |
|---|---|---|
| `predict` | `dspy.Predict` | a straight single call (default) |
| `cot` | `dspy.ChainOfThought` | steps that benefit from explicit reasoning |
| `rlm` | `dspy.RLM` | large corpora — inputs are handed to a recursive REPL and explored, not crammed into one prompt |

`rlm` also accepts `sub_model`, `max_iterations`, and `max_llm_calls`. Token
usage and cost are recorded per target and summarized after each build.

### Fan-out / fan-in (`foreach`)

Real pipelines run one prompt over *many* files (summarize each paper, compile
each note). A `foreach` target fans out into one step per matched file, and a
downstream target fans them back in:

```yaml
targets:
  extract:
    foreach: sources/*.md     # -> extract[a.md], extract[b.md], ...
    prompt: extract           # {{item}} = file contents, {{item_name}} = name
  synthesis:
    prompt: synthesize
    needs: [extract]          # {{needs:extract}} = ALL extracts, concatenated
```

Each instance is cached independently → edit one source and only *its* extract
(plus the downstream synthesis) recomputes; the rest stay cached. Instance
artifacts land in `build/<target>/<filename>`.

### Prompt templating

Inside any prompt: `{{input}}` (all inputs), `{{input:path}}` (one file),
`{{context}}` (shared context), `{{needs:NAME}}` (an upstream artifact),
`{{item}}` / `{{item_name}}` (the current file in a `foreach` step). If you
reference none of them, inputs + upstream artifacts are auto-appended.

## Providers

```bash
llmake providers     # list backends and whether each is available
```

| Provider | Kind | Notes |
|---|---|---|
| `dspy` | chat, agent | **Default.** DSPy programs over any LiteLLM model. |
| `claude-agent` | agent, chat | Runs the `claude` CLI in the workspace — reads/edits files, not just chat. |
| `echo` | chat, agent | Offline deterministic stub; no model called (tests, dry runs). |

The `claude-agent` provider runs in the workspace, so an agent step can read the
input files, edit code, and emit a summary as its artifact — *"go refactor these
and report back,"* not just *"answer this."* Add your own backend by subclassing
`Provider` and calling `register()` in `llmake/providers/__init__.py`.

## Production features

- **Incremental** content-addressed cache — only stale targets recompute.
- **Parallel builds** (`-j N`) — a dependency-aware scheduler compiles
  independent targets concurrently (DSPy LMs are applied per-thread via
  `dspy.context`, so configs don't collide).
- **Retry with backoff** around every provider call (`params.retries`,
  `params.retry_backoff`).
- **Atomic artifact writes** — a crash never leaves a half-written artifact.
- **Cost/token provenance** — recorded per artifact and summarized per build.

### Caching & determinism (important)

LLM calls aren't pure functions — the same prompt can yield different outputs
(see [RESEARCH.md §5](RESEARCH.md)). llmake's contract is therefore: a cached
artifact is **current, not verified**. The cache key includes the prompt,
provider, **model**, params, and upstream artifact keys, so changing any of them
(including the model string when your provider upgrades) invalidates downstream.
Caching one sample is the *desired* build-system behavior — the artifact stays
stable until you choose to regenerate (`--force`) — but never treat "cached" as
"correct." Diff artifacts across snapshots to see what actually changed.

## Snapshots & sharing

```bash
llmake snapshot -m "first compile of the brief"   # git commit+tag of build/
llmake snapshots                                  # list them
llmake export -o out.html                          # one shareable HTML file
```

## Commands

| Command | Purpose |
|---|---|
| `build [targets…]` | compile (incremental; `-j N` for parallel, `--force` to rebuild) |
| `status [targets…]` | show fresh vs. stale targets |
| `graph` | print the dependency DAG |
| `providers` | list inference backends + availability |
| `snapshot -m MSG` | git-commit + tag the build artifacts |
| `snapshots` | list snapshots |
| `export -o OUT.html` | bundle artifacts into one shareable file |
| `clean` | remove build artifacts + cache |

Global: `-C DIR` / `--workflow PATH` to locate the manifest; `-v/-vv` for logs.

## Layout

```
llmake/
  spec.py        # parse/validate llmake.yaml (the "Makefile")
  graph.py       # DAG: topo-sort, cycle detection, build plan
  context.py     # resolve & load input/context files
  render.py      # {{...}} prompt templating
  cache.py       # content-addressed incremental build cache
  runner.py      # the build engine (incremental, parallel, retry)
  snapshot.py    # git-backed snapshots / VCS integration
  export.py      # shareable HTML bundle
  plan.py        # expand targets into steps (foreach fan-out, fan-in wiring)
  providers/     # backends: dspy (engine), claude-agent, echo
  cli.py         # command-line entry point
examples/
  research-notes/      # simple linear DAG (summary -> critique -> report)
  research-synthesis/  # foreach fan-out: per-source extract -> synthesis -> gaps
  kb-compile/          # "LLM as compiler": notes/*.md -> handbook sections + index
tests/test_llmake.py   # offline tests (graph, render, cache, parallel, retry, foreach, dspy)
```

The two `foreach` examples (`research-synthesis`, `kb-compile`) are the
highest-evidence use cases from [RESEARCH.md](RESEARCH.md).

## Tests

```bash
python3 tests/test_llmake.py      # or: python -m pytest tests/
```

Build mechanics run offline via the `echo` provider; the DSPy provider is
exercised with DSPy's `DummyLM` — no API keys, no network.

## Status

MVP / experiment, hardened toward production (incremental + parallel builds,
retry, atomic writes, cost tracking). Real-time collaboration and a web UI are
deliberately out of scope but have seams left for them — see
**[DESIGN.md](DESIGN.md) §6**.
