# PrefMem

**A preference-memory layer that makes your agents learn each user's preferences
from their edits — with human approval before anything goes live.**

Your team runs an agent (a copilot, a support-reply bot, an internal tool). Users
keep *editing* its outputs the same way. Those edits are the signal. PrefMem
captures them, infers the user's preferences, lets a reviewer approve them, and
injects the approved ones into future prompts — so the agent improves from real
usage **without you touching the app's prompt logic or fine-tuning anything.**

- **No GPUs, no training.** Works with any LLM (OpenAI, Anthropic, local).
- **Dependency-free SDK** (stdlib only) — drop it into an existing agent in ~5 lines.
- **Governed by default.** Nothing reaches production without review; full audit log.
- **Open-source SDK + engine**, with an optional hosted control-plane (this server).

> Productized from the research in [`../trajectory-continual-learning/`](../trajectory-continual-learning/)
> — the non-parametric "learn preferences from edits" path, made shippable.

## Quickstart (SDK, local mode)

```python
from prefmem import PrefMem

pm  = PrefMem(store="prefmem.db")              # local SQLite; or PrefMem(api_url=..., api_key=...)
ctx = pm.context(user="sam", task="support-reply")

# 1) inject what we've learned for this user into your prompt
system = "You are a support assistant.\n\n" + ctx.guidance()
reply  = your_llm(system, user_message)        # <- your existing agent, unchanged

# 2) log the interaction, then capture how the user reacted
turn = ctx.log(query=user_message, response=reply)
turn.edit(user_final_text)                     # the user edited it -> the signal
# (or turn.accept() / turn.reject())

# 3) learn from the edits (-> pending review), approve, and it's live
pm.learn(user="sam", task="support-reply")
for p in pm.pending():
    pm.approve(p["id"])                        # or do this in the dashboard
```

After approval, `ctx.guidance()` returns the learned preferences and your agent
follows them on the next call — no app code change. See
[`examples/demo_agent.py`](examples/demo_agent.py) for a runnable end-to-end demo
(uses the local `claude` CLI, no API key):

```
$ python examples/demo_agent.py
... Sam edits two drafts ...
LEARN: • Sign off with exactly "Onwards, Sam"   • Keep it to four short sentences
AFTER: agent → "Hey! ... Sorted for you. Onwards, Sam"   ← on a brand-new request
```

## Hosted control-plane (optional)

```bash
pip install "prefmem[server]"
PREFMEM_API_KEY=secret prefmem-server          # http://127.0.0.1:8000  (dashboard at /)
```

Point the SDK at it: `PrefMem(api_url="http://...:8000", api_key="secret")`. The
dashboard lists every learned preference awaiting review with **approve / reject**
buttons and a recent-activity audit feed. Same engine as local mode.

## How it works

```
your agent ──log()──▶ trajectories (trace + edit)  ──learn()──▶ inferred preferences (pending)
    ▲                                                                      │ approve (dashboard/API)
    └────────────── guidance() injects APPROVED preferences ◀────── live preference memory
```

Preference inference aggregates a user's edits so recurring preferences surface
and one-off noise washes out; the LLM backend is pluggable
(`ClaudeCLIBackend` for dev, `AnthropicBackend`/`OpenAIBackend` for prod), with a
no-LLM heuristic fallback.

| File | Role |
|------|------|
| `prefmem/client.py` | The SDK (`PrefMem`, `Context`, `Turn`) — local + hosted modes, stdlib only |
| `prefmem/engine.py` | ingest → learn → govern → serve guidance |
| `prefmem/miner.py` | preference inference from edits + LLM backends |
| `prefmem/store.py` | SQLite persistence (trajectories, preferences, audit) |
| `prefmem/server.py` | FastAPI control-plane + review dashboard |
| `prefmem/schema.py` | core types (`Trajectory`, `Preference`, signals, status) |

## Status & roadmap

**v0.1 (this):** SDK (local + hosted), SQLite store, LLM/heuristic inference,
governance + audit, FastAPI server + dashboard, tests, demo.

Next: multi-project/API-key tenancy and Postgres; async learning worker;
preference scoping (per-user / per-team / global); offline eval harness (measure
edit-rate reduction); SDK packages for TS/Go; optional parametric path (export to
fine-tune) reusing the research repo.

Apache-2.0. The SDK is the open-source core; the hosted control-plane is the
managed product.
