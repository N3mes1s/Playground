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
| `corpus.py` | Generates a deterministic ~116k-char synthetic "ACME handbook" — the long context experiment 3 navigates. Built *orientation-hostile*: function-named chapters and keyword decoys, so finding a fact costs real navigation. |
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

python experiment_3_rlm.py                # end to end: 3 runs x 8 questions, real agent (live, slow)
python experiment_3_rlm.py --runs 5       # more runs = tighter estimate
python experiment_3_rlm.py --runs 1 --questions 3   # quick smoke check

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

## Experiment 3 — does the cache measurably pay off?

Experiment 3 is the honest test: a real agent, a real long corpus, real
trajectories. Because a live model is non-deterministic, it runs the whole
baseline/PEEK comparison `--runs` times (default 3) and reports a *paired*
per-question turn delta with its spread. Getting a number worth trusting took
three passes — and the dead ends along the way are the instructive part.

### First pass — a confound, not a result

The initial multi-run looked like a PEEK win: −4.0 turns on average. It wasn't.
Correctness told the real story — **baseline 11/12 answers right, PEEK only
7/12** — and every wrong PEEK answer was a *1-turn* answer with **zero REPL
searches**. A context map sitting in the prompt tempts the model to answer
immediately from the map (or to guess) instead of reading the corpus. The
"speed-up" was mostly the agent failing faster. Comparing turns across runs
with different accuracy is meaningless.

Fix: an RLM is *defined* by reading its external context, so the agent now
rejects a `FINAL` issued before any search has run, and is told the map is a
navigation aid to confirm against `context` (see `rlm_agent.py`).

### Second pass — no signal, and three reasons why

With the confound removed, a 3 runs × 4 questions re-run came back flat: a
paired delta of +0.0 turns, accuracy back at parity. No measurable effect — and
the writeup named three fixable causes. The **corpus was too easy**: a 72k-char
handbook with topically-named chapters ("EMPLOYEE BENEFITS") lets a competent
agent grep any fact in 3–4 turns flat, so there is almost no orientation cost to
amortise. The **question stream was too short** for the map to mature. And **n
was tiny** — a single CLI timeout had knocked a whole run out of the paired set,
leaving n = 2.

### Third pass — strengthen the setup, then re-measure

This pass acts on all three:

- **A harder corpus** (`corpus.py`, 72k → 116k chars, 9 → 13 chapters). Chapter
  titles now name the *owning function* — "ABSENCE & SCHEDULING PROVISIONS", not
  "holidays" — so the table of contents is no longer a shortcut; and every fact
  is shadowed by two or three keyword *decoys* elsewhere that name the topic but
  defer the figure. Finding a fact now costs genuine navigation.
- **A longer stream** — 8 questions spanning 7 chapters across the handbook, so
  the map has to accumulate orientation corpus-wide, not for one region.
- **A robust estimator** — the paired delta is now computed per *question*
  rather than per run, so one CLI timeout costs a single data point instead of a
  whole run. 3 runs × 8 questions gives up to n = 24.

Re-run, 3 runs × 8 questions, `claude` CLI default model (the `delta` column is
PEEK − baseline; this run dropped nothing — 242 model calls, no timeouts):

```
#  question                   BASELINE       PEEK           delta
                               mean (range)   mean (range)
1  paid company holidays       6.7 (4-10)     3.7 (3-4)      −3.0
2  parental leave (weeks)      5.7 (4-7)      5.7 (5-6)       0.0
3  vacation days at 5 yrs      3.3 (2-4)      4.3 (3-7)      +1.0
4  home-office stipend ($)     3.0 (2-4)      3.3 (3-4)      +0.3
5  probation period (days)     2.0 (2)        4.0 (3-5)      +2.0
6  prof.-dev. budget ($)       2.7 (2-3)      5.3 (4-6)      +2.6
7  sabbatical service (yrs)    4.3 (3-5)      3.0 (3)        −1.3
8  resignation notice (days)   3.0 (3)        4.7 (4-5)      +1.7

paired delta (PEEK − baseline):  +0.42 ± 2.28 turns/question   (n = 24, 0 dropped)
answers correct:  baseline 24/24,  PEEK 24/24
```

**The headline is still "no net effect"** — +0.42 turns/question sits well
inside the ±2.28 spread. But the per-question column is not noise, and it is the
actual result: PEEK's sign tracks how hard the *baseline* found each question.

- Where baseline orientation was **expensive, PEEK paid off.** Holidays cost the
  baseline 6.7 turns — the worst question on the board, range 4–10 — and the map
  cut it to 3.7, a 3.0-turn saving. Sabbatical: 4.3 → 3.0.
- Where baseline orientation was **cheap, PEEK was a tax.** Probation (a flat
  baseline 2.0 turns), the dev budget (2.7) and notice (3.0) all ran *slower*
  with the map: +2.0, +2.6, +1.7. When a fact is one grep away, reading a
  context map and then — as the agent is told to — re-confirming the answer
  against `context` is pure overhead.

(The lone exception is parental leave: slow for the baseline at 5.7 turns, yet
unchanged under PEEK. The pattern is a tendency, not a law.)

So PEEK's value here is real but **conditional**: it amortises orientation only
when orientation actually costs something. This corpus mixes genuinely buried
facts with trivially greppable ones, and the mix averages to zero. The map is
not the weak link — the final map the script prints at the end of each run
carries accurate char offsets and every exact domain constant; the agent simply
does not need it for the easy half of the stream.

The honest next step is now sharper than "more runs": a corpus where *no* fact
is cheaply greppable, so every query pays the orientation cost PEEK is built to
cache. Until then, easy and hard questions mixed in one stream will keep washing
the average back out to zero.

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
