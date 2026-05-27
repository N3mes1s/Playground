# finance-agent

A paper-trading agent for US equities that runs an intraday loop, journals every decision, and rewrites its own strategy playbook each week. Inspired by [unusualwhales.com](https://unusualwhales.com/) — predict the market, close each week green, grow a fixed starting portfolio.

> **Experiment, not investment advice.** This is paper trading. "Always close the week green" is the aspirational target; markets don't owe anyone a guarantee. The point is to see how far a Claude-driven loop can get with explicit risk rules, a research stack, and a self-improving playbook.

## Architecture

```
                          ┌────────────────────────────────────┐
                          │  cli loop  (intraday scheduler)    │
                          └──────────────┬─────────────────────┘
                                         │  every tick (default 5 min)
                                         ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │              Claude Opus 4.7 (adaptive thinking)                  │
   │       tool_runner → loops tool calls → final decision             │
   └──┬──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┘
      │      │      │      │      │      │      │      │      │
      ▼      ▼      ▼      ▼      ▼      ▼      ▼      ▼      ▼
  portfolio quotes history news risk place cancel journal playbook
   (JSON)  yfinance yfinance parallel calc paper paper notes  notes
                                .ai
                                         │
                                         ▼
                          ┌────────────────────────────────────┐
                          │  Friday close → weekly retro       │
                          │  agent reads journal, rewrites     │
                          │  playbook → next week starts smart │
                          └────────────────────────────────────┘
```

Prompt-caching layout: tools + system prompt + playbook are cached (playbook only changes weekly); per-tick portfolio state + market context go in the user turn.

## What's in here

| File              | Role                                                                          |
| ----------------- | ----------------------------------------------------------------------------- |
| `cli.py`          | Entrypoints: `init`, `tick`, `loop`, `status`, `weekly-close`, `reset`        |
| `agent.py`        | Builds the tool runner, system prompt, and runs one tick                      |
| `tools.py`        | The 9 tools exposed to Claude (portfolio, quotes, news, orders, playbook…)    |
| `portfolio.py`    | Paper-trading state (positions, cash, orders, fills) on JSON                  |
| `market_data.py`  | yfinance wrapper — quotes, OHLC history, market-open check                    |
| `research.py`     | parallel.ai search wrapper for headlines & filings                            |
| `risk.py`         | Position-sizing checks, exposure, drawdown, hard limits                       |
| `journal.py`      | Append-only trade + decision log                                              |
| `playbook.py`     | The self-improvement notes — read into the system prompt, rewritten weekly    |
| `config.py`       | Env loading, paths, constants                                                 |
| `data/`           | Runtime state (gitignored)                                                    |

## Risk rails (enforced in `risk.py`, not advisory)

- **Long-only.** No shorts, no leverage, no options, no margin.
- **Max single-name exposure:** 20% of portfolio value.
- **Max concurrent positions:** 10.
- **Min cash reserve:** 5%.
- **Daily loss circuit-breaker:** if intraday P&L hits −5%, trading halts for the rest of the day.
- **Per-trade size cap:** 10% of portfolio per single order (forces scaling in/out).

The agent can argue for an override in its reasoning, but `place_order` will reject anything that violates these rules. This is by design — the agent's job is to find edges within the rails, not bypass them.

## Setup

```bash
cd finance-agent
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# fill in ANTHROPIC_API_KEY and PARALLEL_API_KEY
python cli.py init --starting-cash 10000 --watchlist SPY,QQQ,AAPL,MSFT,NVDA,GOOGL,META,AMZN,TSLA,AMD
```

## Run

```bash
# one tick — useful for debugging
python cli.py tick

# continuous intraday loop (default: every 5 min during market hours)
python cli.py loop --interval 300

# check current state
python cli.py status

# end-of-week: agent reviews trades and rewrites the playbook
python cli.py weekly-close
```

`loop` sleeps overnight and through weekends; weekly-close runs automatically on Friday after market close, but you can also invoke it manually.

## Self-improvement loop

1. Every tick, the agent loads the playbook into context.
2. Every fill, the agent appends a one-line note ("entered NVDA on AI capex headline; sized 8% of port; trailing stop 4%") to the journal.
3. On weekly close, the agent reads the full week's journal + P&L attribution, then **rewrites the playbook** (not appends — full rewrite, so dead heuristics get pruned).
4. Next Monday, the new playbook is in the cached system prompt.

The playbook is just markdown. You can edit it by hand to seed initial strategy or to course-correct.

## Network requirements

- `api.anthropic.com` (Claude)
- `api.parallel.ai` (web research)
- `query1.finance.yahoo.com` / `query2.finance.yahoo.com` (yfinance backend)

If you're running in a sandbox with restricted egress, these need to be on the allowlist. yfinance has no API key — it scrapes Yahoo's public endpoints, so a strict policy may block it; in that case swap `market_data.py` for a broker API (Alpaca's data API is free with a key).

## Going live (later)

This experiment is paper-only by design. To wire up a real broker:

1. Drop `portfolio.py` in favor of an adapter to your broker (Alpaca, IBKR, etc.).
2. Keep the same `Tools` surface so the agent doesn't notice.
3. Add a `--live` flag and a confirmation prompt on first order.

Don't skip step 2 — the agent is trained on the tool descriptions in `tools.py`, so changing them mid-flight invalidates the cached system prompt and breaks the playbook's continuity.
