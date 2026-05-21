# peek-experiments

Hands-on exploration of **PEEK** — [github.com/zhuohangu/peek](https://github.com/zhuohangu/peek),
the reference implementation of *"PEEK: Context Map as an Orientation Cache for
Long-Context LLM Agents"* ([arXiv:2510.04618](https://arxiv.org/abs/2510.04618)).

The goal here is to *understand how PEEK works* by running its real control
flow end to end and watching the data structures evolve — not to ship anything.

## What PEEK is

When an LLM agent operates repeatedly on the same large external context (a
document corpus, a code repo), it keeps re-doing the same orientation work:
figuring out the structure, where things live, what the key entities are.

PEEK caches that **orientation knowledge** as a small, prompt-resident
**context map** — think "a CPU cache / database index for a long context".
You prepend the map to the agent's next call so it can skip the rediscovery.
PEEK is agent-agnostic, model-agnostic, and unsupervised: it learns purely
from inference-time signals, no ground-truth labels.

## How it works (the parts)

PEEK splits into a deterministic layer and an LM-driven layer.

| Component | Role |
|-----------|------|
| **`ContextMap`** | The cache itself: section-indexed text. Each item is one line `[<slug>-NNNNN] content` under a `## SECTION` heading. IDs are stable across edits. Six sections: `context_roadmap`, `context_understanding`, `domain_constants`, `parsing_schema`, `error_patterns`, `reusable_results`. |
| **`Distiller`** *(LM)* | Reads an agent's run trajectory. Emits a diagnosis, **tags** every existing map item (`helpful` / `harmful` / `neutral` / `stale`), and proposes cache candidates. |
| **`Cartographer`** *(LM)* | Turns the Distiller's reflection into structured **`ADD` / `DELETE` / `REPLACE`** edits against the map, respecting a token budget. |
| **`Evictor`** | Deterministic. When the map exceeds its hard token budget, removes items in ascending **(score, age)** order until it fits. `helpful` = +1, `harmful`/`stale` = −1, `neutral` = 0. |
| **`CachePolicy`** | Orchestrates one update step (PEEK's Algorithm 1): Distiller → score update → Cartographer → apply edits → evict. Freezes the map after `evolve_steps`. `save()` / `load()` persist it. |
| **`LMClient`** | Minimal protocol — `completion(messages)` + `last_usage()`. Ships with OpenAI / Anthropic / Gemini clients; any stub that satisfies the protocol works. |

The intended loop (from PEEK's own README):

```python
policy = CachePolicy(client=..., token_budget=1024, evolve_steps=10)
for question in stream_of_questions:
    system_prompt = f"{base_instructions}\n\nContext Map:\n{policy.current_map_text}"
    trajectory = my_agent.run(system_prompt, question, long_external_context)
    policy.update(trajectory=trajectory, question=question)
policy.save("maps/my-corpus.peek.json")
```

## The experiments

PEEK needs an LLM behind the `LMClient` protocol for the Distiller and
Cartographer. This directory provides **two** ways to satisfy it, neither of
which needs a PEEK-managed API key:

- **`ScriptedLMClient`** (`scripted_client.py`) — an offline stub that replays
  pre-programmed Distiller/Cartographer JSON. Deterministic; the run is the
  same every time. PEEK's README explicitly endorses "a local stub".
- **`ClaudeCodeClient`** (`claude_code_client.py`) — routes each completion
  through the local **`claude` CLI** (Claude Code) in non-interactive print
  mode. A real model does the distilling and cartography; no API key of its
  own — it reuses whatever auth the Claude Code install already has.

Either way, everything *except* the model is the genuine PEEK code: JSON
extraction, `ContextMap.apply`, scoring, the Evictor, the freeze, `save`/`load`.

| File | What it does |
|------|--------------|
| `scripted_client.py` | The offline `LMClient` stub + small helpers (`map_ids`, `id_of`, `tags_for`). |
| `claude_code_client.py` | A live `LMClient` that shells out to the `claude` CLI. Run it directly for a one-call self-test. |
| `corpus.py` | Generates a deterministic ~72k-char synthetic "ACME handbook" — the real long context experiment 3 navigates. |
| `rlm_agent.py` | A real RLM agent: answers a question by running code in a persistent Python REPL over a long context until it emits `FINAL:`. |
| `experiment_1_mechanics.py` | The **deterministic layer**, no LLM: `ContextMap` ADD/REPLACE/DELETE, stable IDs, the scoring convention, and a narrated priority-eviction run. |
| `experiment_2_policy_loop.py` | The **`CachePolicy` loop** over *canned* trajectories: the map bootstraps from empty, self-corrects, hits the budget, then freezes. Runs against either backend. |
| `experiment_3_rlm.py` | **End to end**: a real RLM agent explores a real corpus; PEEK distills its genuine trajectories. Measures model turns per question, baseline vs PEEK. |

The three experiments form a ladder: #1 is the deterministic core with no model,
#2 adds the real `CachePolicy` loop but with scripted/curated trajectories, and
#3 removes the last piece of scaffolding — the trajectories are produced by an
actual agent doing actual work, so it can *measure* whether the cache helps.

## Run it

```bash
pip install -r requirements.txt          # installs peek-ai from GitHub + tiktoken
cd peek-experiments

python experiment_1_mechanics.py          # deterministic layer, no LLM

python experiment_2_policy_loop.py        # offline scripted LM (default, instant)
python experiment_2_policy_loop.py --live # real LM via the `claude` CLI
python experiment_2_policy_loop.py --live --model opus   # pick the model

python experiment_3_rlm.py                # end to end: real agent + real corpus (live, slow)
python experiment_3_rlm.py --questions 2  # shorter / cheaper run

python claude_code_client.py              # one-call self-test of the live client

# (optional) PEEK's own test suite — 10 tests, all green
pip install peek-ai[test] && pytest --pyargs peek   # or: pytest tests/ in a peek checkout
```

### Live mode — using this Claude Code instance as the LLM

`ClaudeCodeClient` makes PEEK run with no API key by treating the local
`claude` binary as the model endpoint. Each `completion()` call runs:

```
claude -p --output-format json --tools "" --no-session-persistence \
       --strict-mcp-config --system-prompt "<minimal>"
```

feeding the prompt on stdin and reading the `result` + `usage` fields back out
of the JSON envelope. Built-in tools are disabled and the coding-agent system
prompt is replaced, so the call behaves as a plain text completion.

Two practical wrinkles the client handles:

- **It runs the subprocess from an empty, non-git temp directory.** Project
  `CLAUDE.md`, settings, and *Stop hooks* are discovered from the cwd; the web
  harness's "uncommitted work" Stop hook would otherwise fire and overwrite the
  completion with git advice.
- **It does not use `--bare`.** `--bare` skips hooks (which would also fix the
  above) but forces API-key auth — broken in environments that authenticate
  another way. Running from a neutral cwd isolates hooks without touching auth.

`--live` runs are real: ~8 model calls per run, non-deterministic, and they
cost tokens. The map that emerges will differ from the scripted narrative
below — e.g. a real Cartographer tends to favour compact `REPLACE`s and may
never hit the token budget.

## What the experiments show

Experiment 2 (default **scripted** backend) walks a context map through its
whole life cycle — the scripted run is deterministic, so these numbers are
exact every time:

```
STEP 1  bootstrap     map empty -> Cartographer ADDs 3 roadmap items   (104 -> 214 tok)
STEP 2  accumulate    items tagged helpful; +understanding +PTO table  (214 -> 292 tok)
STEP 3  self-correct  a roadmap pointer is tagged 'harmful' and DELETEd (292 -> 377 tok)
STEP 4  budget squeeze 4 ADDs overflow 440 tok -> Evictor removes 2     (-> 432/440 tok)
STEP 5  frozen        evolve_steps reached -> update() returns None, 0 LM calls
```

Three behaviours worth calling out:

1. **The map self-corrects.** In step 3 a roadmap item that pointed the agent
   to the wrong chapter is tagged `harmful` by the Distiller and removed by the
   Cartographer — bad cache entries don't survive contact with a trajectory
   that exposes them.

2. **Eviction is score-driven and section-agnostic.** In step 4 the two items
   evicted are `dc-00005` and `dc-00007` — the *domain constants* (the PTO
   table and the stipend figure) the loop had carefully cached. They were
   evicted first because no question ever exercised them, so the Distiller
   only ever tagged them `neutral` (score 0), while roadmap/parsing items that
   got used accrued `helpful` (+1…+3). The Evictor looks **only** at the score
   and item age — never at which section an item is in. The Cartographer
   *prompt* says "protect domain constants most", but that guidance only
   steers the Cartographer's own `DELETE` choices; it does not bind the
   Evictor. Takeaway: under budget pressure, what protects an item is the
   Distiller repeatedly tagging it `helpful`, not its perceived value.

3. **Evolution is bounded.** With `evolve_steps=4`, the 5th `update()` returns
   `None` immediately and makes zero LM calls — the map is now a frozen,
   read-only cache. `save()`/`load()` round-trips it (map text + scores +
   step count) so it can be reused across processes.

See the script output for the full per-step trace and the final context map.

Running the same experiment with `--live` confirms the loop behaves the same
way with a real model in the seat: the map still bootstraps from empty,
self-corrects the misleading Ch.9 pointer, and freezes after `evolve_steps` —
but the exact items, tags, and token counts differ run to run, and a real
Cartographer tends to keep the map compact enough that the Evictor never
triggers.

## Notes

- PEEK's Distiller prompt is written for **RLM** (Recursive Language Model)
  agents — controller-style agents that explore long context via a REPL — but
  the `CachePolicy` API itself only ever sees a `trajectory` string, so it is
  not actually tied to that agent shape.
- `peek-ai` is not on PyPI yet; `requirements.txt` installs it from the Git
  repo. The package is small (core depends only on `tiktoken`).
- `--live` mode needs the `claude` CLI on `PATH` (it is, inside Claude Code on
  the web). It is unrelated to the `peek-ai` install and needs no extra deps.
- `output/` is git-ignored — it only holds the regenerated saved map.
