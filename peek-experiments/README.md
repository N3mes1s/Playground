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

PEEK needs an LLM for the Distiller and Cartographer, and this sandbox has no
API key. So `scripted_client.py` provides a **`ScriptedLMClient`** — a stub
that satisfies `LMClient` and replays pre-programmed Distiller/Cartographer
JSON. PEEK's README explicitly endorses "a local stub" as a valid client.
Everything *except* the model is the genuine PEEK code: JSON extraction,
`ContextMap.apply`, scoring, the Evictor, the freeze, `save`/`load`.

| File | What it does |
|------|--------------|
| `scripted_client.py` | The offline `LMClient` stub + small helpers (`map_ids`, `id_of`, `tags_for`). |
| `experiment_1_mechanics.py` | The **deterministic layer**, no LLM: `ContextMap` ADD/REPLACE/DELETE, stable IDs, the scoring convention, and a narrated priority-eviction run. |
| `experiment_2_policy_loop.py` | The **full `CachePolicy` loop** driven by the scripted LM: an RLM agent answers 5 questions about a fictional ~41k-char employee handbook; the map bootstraps from empty, self-corrects, hits the budget, then freezes. |

## Run it

```bash
pip install -r requirements.txt          # installs peek-ai from GitHub + tiktoken
cd peek-experiments
python experiment_1_mechanics.py
python experiment_2_policy_loop.py        # writes output/acme-handbook.peek.json

# (optional) PEEK's own test suite — 10 tests, all green
pip install peek-ai[test] && pytest --pyargs peek   # or: pytest tests/ in a peek checkout
```

## What the experiments show

Experiment 2 walks a context map through its whole life cycle:

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

## Notes

- PEEK's Distiller prompt is written for **RLM** (Recursive Language Model)
  agents — controller-style agents that explore long context via a REPL — but
  the `CachePolicy` API itself only ever sees a `trajectory` string, so it is
  not actually tied to that agent shape.
- `peek-ai` is not on PyPI yet; `requirements.txt` installs it from the Git
  repo. The package is small (core depends only on `tiktoken`).
- `output/` is git-ignored — it only holds the regenerated saved map.
