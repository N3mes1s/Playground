# Research grounding

Levee is built on a small set of recent papers and classic results. Each
component below names the source and where it lives in the codebase.

## 1. TradingAgents — multi-agent LLM debate

> Xiao, Y., Sun, E., Luo, D., Wang, W. (2024). **TradingAgents: Multi-Agents
> LLM Financial Trading Framework**. arXiv:2412.20138.
> https://arxiv.org/abs/2412.20138

The original "single Claude makes all decisions" architecture has a known
failure mode: it skips disconfirming evidence under self-consistency
pressure. TradingAgents splits the work into specialized analyst roles
(Fundamentals, Sentiment, Macro, Technical), runs structured Bull vs Bear
debate, has a Trader synthesize, and a Risk Manager gate the final order.

* **Where:** `multiagent.py`
* **Invoke:** `python cli.py tick --multiagent --debate-rounds 1`
* **Tradeoff:** ~3-4x the token cost of single-agent. Worth it for high-stakes
  decision points; single-agent is fine for routine ticks.

## 2. Reflexion — tight per-trade self-critique

> Shinn, N., Cassano, F., Berman, E., Gopinath, A., Narasimhan, K., Yao, S.
> (2023). **Reflexion: Language Agents with Verbal Reinforcement Learning**.
> arXiv:2303.11366.
> https://arxiv.org/abs/2303.11366

Weekly playbook rewrite is the broad feedback loop. Reflexion fills the gap:
after every closed position, a small Claude call produces a single
OUTCOME / ROOT CAUSE / LESSON / GENERALIZES TO entry. The next tick reads
the recent reflections before deciding.

* **Where:** `reflexion.py`
* **Tool:** `recent_reflections(n)` — agent reads its own recent critiques.

## 3. Voyager / FinMem — skill-library memory

> Wang, G. et al. (2023). **Voyager: An Open-Ended Embodied Agent with LLMs**.
> arXiv:2305.16291.  https://arxiv.org/abs/2305.16291
>
> Yu, Y. et al. (2023). **FinMem: A Performance-Enhanced LLM Trading Agent with
> Layered Memory and Character Design**. arXiv:2311.13743.
> https://arxiv.org/abs/2311.13743

The agent's playbook IS its skill library — every Friday it rewrites in full,
retiring rules that stopped working. Voyager's contribution: the agent owns
the library, not the engineer. FinMem's contribution: layered memory
(short / mid / long term).

* **Where:** `playbook.py` (long-term), `journal.py` (short-term),
  weekly close in `agent.py` / `multiagent.py` (consolidation).

## 4. Kelly criterion + Spitznagel "Safe Haven" — edge-aware sizing

> Kelly, J. L. (1956). **A New Interpretation of Information Rate**. Bell
> System Technical Journal.
>
> Thorp, E. (2006). **The Kelly Criterion in Blackjack, Sports Betting, and
> the Stock Market**. Handbook of Asset and Liability Management.
>
> Spitznagel, M. (2021). **Safe Haven: Investing for Financial Storms**.
> Wiley.

The 2026 bull-tape backtest showed Levee's #1 weakness was under-deployment
during clean trends — fixed 5-7% starters left ~80% capture short. Kelly
fraction (with confidence multiplier and rail clamp) gives an edge-aware
size that scales with conviction without breaching the position caps.

* **Where:** `kelly.py`
* **Tool:** `kelly_size_proposal(p, win, loss, conf, price)` — the Trader
  uses this before proposing a size; the Risk Manager validates against the
  hard rails.

## 5. Historical analog retrieval

Classical case-based reasoning + modern RAG: at decision time, retrieve the
K most similar past setups (own journal + market history) and condition the
current call on what played out.

* **Where:** `analogs.py`
* **Tools:** `journal_analogs(keywords)` — own history search;
  `market_analogs(setup_description)` — parallel.ai-driven prior-episode
  retrieval.

## 6. Free-tier options flow detection — the UnusualWhales signal

> No paper here — this is empirical financial engineering. yfinance's
> public option chain endpoint exposes per-strike volume, open interest,
> and IV. Cross-section + daily snapshots get us ~80% of a paid
> Unusual Whales feed.

The signal classes we detect:
* **Single-strike sweeps** — vol > 5k contracts on 0-7 DTE OTM options.
  The hallmark of an informed bet (someone paying for cheap leverage on
  a near-term catalyst).
* **Vol/OI ratios** — when today's volume >> open interest, most activity
  is new positions opening.
* **Notional concentration** — $1M+ on a single contract.
* **Put/call ratio skew** across the watchlist — daily and overnight.

This is the gap the UMAC case study exposed. Without this, Levee misses
pre-news positioning. Live test (June 2026) caught TSLA $440 0DTE calls
at 61k contracts / $16M notional and AMD put/call ratio at 1.27 (bearish
skew vs watchlist average of 0.46).

* **Where:** `options_flow.py`
* **Tools:** `scan_unusual_options_flow(symbols, ...)` and
  `options_flow_for_ticker(symbol)`.
* **Future:** day-over-day OI delta detection (current implementation
  needs a daily snapshot cron); paid flow (Polygon, CBOE) for sweep
  classification and dark-pool prints.

## 7. Prediction-market priors (Kalshi) — calibrated catalyst probabilities

> Kalshi public REST API, 2025-2026. https://docs.kalshi.com

By 2026 the policy-event prediction markets (Fed decisions, CPI prints,
elections, tariff actions, recession odds) carry enough volume that their
prices are calibrated forecasts. Cheaper and more accurate than the agent
guessing "I think the Fed probably pauses." Pulls live yes/no probabilities
for Fed hike timing, CPI threshold contracts, tariff actions, and Trump
policy markets — read-only, no auth required.

* **Where:** `prediction_markets.py`
* **Tools:** `get_prediction_market_priors(category)` and
  `search_prediction_markets(keyword)`.
* **Example outputs (as of June 2026):** Fed hike before July 2026 = 2.5%
  implied, before Dec 2026 = 31.5%, 3+ emergency cuts in 2026 = 5.85%.

## 8. Parallel.ai Monitor + Task API — real-time situational awareness

> Parallel documentation, 2025. https://docs.parallel.ai

The earlier news-blind backtest missed the UMAC/Pentagon catalyst because the
agent's 5-query scan didn't cover small-cap defense. Monitors fix this: 10
standing NL queries (political/Fed/tariff/Pentagon/FDA/SEC/M&A/earnings +
two thematic sectors) deliver detected events via polling or webhook.
The Task API runs synchronous multi-hop deep research on demand.

* **Where:** `monitors.py`, `tasks.py`
* **Tools:** `get_realtime_alerts()` and `deep_research(question)`.

---

## Things explicitly NOT implemented (yet)

* **Options flow ingest** — would close the UW signal gap directly. Needs
  paid data (Polygon, UW API, CBOE LiveVol).
* **Tree-of-Thoughts decision search** — promising but cost-prohibitive at
  current token economics. Bull/Bear debate is a cheap approximation.
* **HMM regime classifier** — currently rule-based regime tags from the
  Macro analyst. Could be formalized with a small HMM trained on SPY +
  VIX + yield curve. Listed as future work.
* **Computer use / browser agents** — would let the agent attend earnings
  calls, read 10-Ks. Anthropic supports it, but UX/cost is heavy.
