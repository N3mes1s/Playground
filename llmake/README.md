# llmake

**A build system for LLM inference workflows.** *GNU Autotools × Notion.*

Treat your notes, specs, and context as **source**. Declare a DAG of
prompt/agent steps in an `llmake.yaml`. Compile them into **cached, shareable
artifacts**. Re-running only recomputes what changed — like `make`, but the
compiler is an LLM (or a coding agent).

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
| **Provider** | The inference backend: a chat model *or* a coding agent. |
| **Cache** | Content-addressed; only stale targets recompute. |
| **Snapshot** | A git commit+tag of the build artifacts. |
| **Export** | A self-contained HTML bundle of all artifacts, for sharing. |

## Install

```bash
pip install -r requirements.txt        # just PyYAML for the core
# optional, to actually call models:
pip install anthropic                   # for the `anthropic` provider
# the `claude-agent` provider shells out to the `claude` CLI (no pip dep)
```

Or install as a package (gives you the `llmake` command):

```bash
pip install -e .
```

## Quickstart

```bash
cd examples/research-notes

# If you didn't `pip install -e .`, run via the module + PYTHONPATH:
export PYTHONPATH=$(cd ../.. && pwd)
alias llmake="python3 -m llmake.cli"

llmake graph        # show the dependency DAG
llmake build        # compile everything (offline `echo` provider by default)
llmake build        # again -> all cached, nothing recomputes
llmake status       # what's fresh vs. stale
llmake export -o build/export.html     # shareable bundle
```

Edit `inputs/notes.md`, run `llmake build` again, and watch only `summary` and
its descendants (`critique`, `report`) rebuild.

## Workflow manifest (`llmake.yaml`)

```yaml
version: 1
project: research-notes

defaults:
  provider: echo            # offline & deterministic; no API key needed
  model: claude-opus-4-8

prompts:                    # the stored, reusable prompt library
  summarize: prompts/summarize.md       # file ref
  critique: prompts/critique.md

inputs:
  - inputs/*.md
context:
  - context/*.md            # shared with every step

targets:                    # the build DAG; each -> build/<name>.md
  summary:
    prompt: summarize
    inputs: [inputs/notes.md, inputs/interview.md]
  critique:
    prompt: critique
    needs: [summary]
  report:
    prompt: |
      Combine the summary and critique into a final brief.
      {{needs:summary}}
      {{needs:critique}}
    needs: [summary, critique]
    # provider: claude-agent   # run this step as a coding agent instead
    # kind: agent
```

### Prompt templating

Inside any prompt: `{{input}}` (all inputs), `{{input:path}}` (one file),
`{{context}}` (shared context), `{{needs:NAME}}` (an upstream artifact). If you
reference none of them, inputs + upstream artifacts are auto-appended.

## Providers (chat *and* agents)

```bash
llmake providers     # list backends and whether each is available
```

| Provider | Kind | Needs |
|---|---|---|
| `echo` | chat, agent | nothing — offline, deterministic (default) |
| `anthropic` | chat | `anthropic` pkg + `ANTHROPIC_API_KEY` |
| `claude-agent` | agent, chat | the `claude` CLI on PATH |

The `claude-agent` provider runs in the workspace, so an agent step can read
the input files, edit code, and emit a summary as its artifact — *"go refactor
these and report back,"* not just *"answer this."* Add your own backend by
subclassing `Provider` and registering it in `llmake/providers/__init__.py`.

## Snapshots & sharing

```bash
llmake snapshot -m "first compile of the brief"   # git commit+tag of build/
llmake snapshots                                  # list them
llmake export -o out.html                          # one shareable HTML file
```

## Commands

| Command | Purpose |
|---|---|
| `build [targets…]` | compile (incremental; whole graph if omitted) |
| `status [targets…]` | show fresh vs. stale targets |
| `graph` | print the dependency DAG |
| `providers` | list inference backends + availability |
| `snapshot -m MSG` | git-commit + tag the build artifacts |
| `snapshots` | list snapshots |
| `export -o OUT.html` | bundle artifacts into one shareable file |
| `clean` | remove build artifacts + cache |

Global: `-C DIR` / `--workflow PATH` to locate the manifest.

## Layout

```
llmake/
  spec.py        # parse/validate llmake.yaml (the "Makefile")
  graph.py       # DAG: topo-sort, cycle detection, build plan
  context.py     # resolve & load input/context files
  render.py      # {{...}} prompt templating
  cache.py       # content-addressed incremental build cache
  runner.py      # the build engine (ties it all together)
  snapshot.py    # git-backed snapshots / VCS integration
  export.py      # shareable HTML bundle
  providers/     # pluggable backends: echo, anthropic, claude-agent
  cli.py         # command-line entry point
examples/research-notes/   # runnable end-to-end example
tests/test_llmake.py       # offline tests (graph, render, incremental build)
```

## Tests

```bash
python3 tests/test_llmake.py      # or: python -m pytest tests/
```

Everything runs offline via the `echo` provider — no keys, no network.

## Status

MVP / experiment. Real-time collaboration and a web UI are deliberately out of
scope but have seams left for them — see **[DESIGN.md](DESIGN.md) §6**.
