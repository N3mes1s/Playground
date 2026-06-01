"""TradingAgents-style multi-agent debate pipeline.

Adapted from Xiao et al. 2024 (arXiv 2412.20138). Sequential pipeline:

  1. Analyst phase (parallel): Fundamentals, Sentiment, News, Technical
  2. Researcher debate: Bull vs Bear, N rounds
  3. Trader synthesis: turns reports + debate into a proposed action
  4. Risk Manager: final gate against playbook rules + risk rails

Each role is a Claude call with a specialized system prompt. The playbook
sits in the cached prefix of every role's system prompt — it's the "house
view" all roles share. Tools are role-scoped: analysts get read-only data
tools, the Trader gets order tools, the Risk Manager has the final order
authority.

Citation: Xiao, Y. et al. (2024). TradingAgents: Multi-Agents LLM Financial
Trading Framework. arXiv:2412.20138.
"""
import json
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import anthropic

import clock
import config
import journal
import market_data
import playbook
import portfolio as pf
import risk
import tools as t


READ_ONLY_TOOLS = [
    t.get_portfolio_snapshot, t.get_quote, t.get_history,
    t.search_news, t.scan_macro_and_policy,
    t.get_realtime_alerts,
    t.get_prediction_market_priors, t.search_prediction_markets,
    t.scan_unusual_options_flow, t.options_flow_for_ticker,
    t.deep_research, t.market_analogs, t.journal_analogs,
    t.recent_reflections,
]

TRADER_TOOLS = READ_ONLY_TOOLS + [t.kelly_size_proposal, t.add_journal_note]
RISK_TOOLS = TRADER_TOOLS + [t.place_order, t.cancel_order]


# ───────────────────────────────────────────────────────────────────────────
# Role prompts
# ───────────────────────────────────────────────────────────────────────────

FUNDAMENTALS_SYSTEM = """You are the Fundamentals Analyst on a trading desk.

Your job: for each name on the active watchlist, take a clear read on
intrinsic value, earnings posture, capital structure, and any fundamental
catalysts (earnings dates, dividends, buybacks, guidance). Output a terse
report (≤ 250 words) covering:

1. Which 1-3 names on the watchlist look most attractive on fundamentals THIS
   week, and why (specific catalysts, valuation, capital return).
2. Which look most exposed (overvalued, deteriorating fundamentals, binary
   risk like upcoming earnings or FDA).
3. Three concrete fundamental data points the trader should not miss.

Do not recommend trades. Do not opine on the chart. Stick to fundamentals.
"""

SENTIMENT_SYSTEM = """You are the Sentiment / News / Flow Analyst on a
trading desk — the UnusualWhales-style desk analyst.

Your job: read the day's news, macro/policy scan, real-time monitor alerts,
**and unusual options flow** to extract signals that move the tape before
the public catches up. Output a terse report (≤ 300 words) covering:

1. **Macro / political backdrop** in one paragraph (Fed posture, tariff/trade,
   risk-on vs risk-off, key catalysts on deck). Pull `get_prediction_market_priors`
   for calibrated Fed/CPI odds.
2. **Sector-specific catalysts** (Pentagon procurement, FDA actions, M&A,
   regulatory) named in the last 24 hours.
3. **Unusual options flow** — call `scan_unusual_options_flow` and flag:
   - 0-7 DTE single-strike volumes > 5k contracts (informed positioning)
   - Notional > $1M on a single contract (real money bets)
   - Put/call ratio skew across watchlist (>1.0 = bearish bias, <0.5 = bullish)
   - Any ticker not on the watchlist that shows up in flow scans —
     these are the UMAC-style signals worth investigating with
     `options_flow_for_ticker` and `deep_research`.
4. **Specific tickers** being named in bullish / bearish news flow.

Order of operations: `get_realtime_alerts` first (instant), then
`scan_unusual_options_flow` (15-30 sec), then `scan_macro_and_policy` if
you still need more.

Do not recommend trades; the Bull/Bear researchers will weigh your read.
"""

NEWS_MACRO_SYSTEM = """You are the Macro / Cross-Asset Analyst.

Your job: read the broader market state — index trend, breadth, yields, dollar,
volatility — and pin the regime. Output a terse report (≤ 200 words):

1. Current regime tag: TREND-UP / RANGE / TREND-DOWN / CAPITULATION /
   CHOP. Justify in one sentence.
2. SPY / QQQ position vs 20D / 50D moving averages, recent breadth.
3. VIX / vol regime. Cross-asset reads if relevant.
4. The single most important macro variable that could flip the regime
   this week.

Use get_history on SPY, QQQ, VIX, IWM. Don't recommend trades.

### MANDATORY FINAL LINE

End your report with EXACTLY this line (the pipeline parses it):

REGIME_TAG: <REGIME>, confidence <1-5>, binary_print_this_week: <yes|no>

Where <REGIME> is one of TREND-UP, RANGE, TREND-DOWN, CHOP, CAPITULATION.
Confidence 1=tentative, 5=overwhelming. binary_print_this_week is "yes" if
CPI/PPI/PCE/NFP/FOMC lands this week, else "no".
"""

TECHNICAL_SYSTEM = """You are the Technical Analyst.

Your job: for the top 1-3 names that came up in the Fundamentals report OR
that are showing unusual price action this week, deliver a technical read.
Output a terse report (≤ 250 words):

1. For each name: trend (5/20/50 SMA stack), key support / resistance levels,
   volume profile, RSI/momentum read.
2. Any setups that look actionable: clean base breakouts, capitulation
   reversals, distribution patterns at highs.
3. A concrete trigger + invalidation level per name (the trader will turn
   these into orders).

Use get_history liberally. Be specific on prices.
"""

BULL_SYSTEM = """You are the Bull Researcher. Your bias: find the case to
deploy capital.

You will see reports from Fundamentals, Sentiment, Macro, and Technical
analysts, plus the current playbook and portfolio. Argue, with specific
references to those reports, for the strongest 1-2 trade ideas THIS tick.
Be concrete: ticker, entry, size, expected timeframe, catalyst.

When debating the Bear, attack their case head-on with evidence from the
reports. Don't strawman. Don't recommend trades you can't defend at next
week's retro.

Output ≤ 300 words. End with: "BULL THESIS: [ticker] [entry trigger]
[invalidation] [size]" or "BULL CONCLUSION: stand down."
"""

BEAR_SYSTEM = """You are the Bear Researcher. Your bias: find the case
NOT to deploy capital, or to reduce existing risk.

You will see reports from Fundamentals, Sentiment, Macro, and Technical
analysts, plus the current playbook and portfolio. Argue against the Bull's
proposed trades using specific evidence — overhead supply, macro catalysts
on deck, valuation, position concentration, regime mismatch.

When the Bull's case is genuinely strong, concede directly. Don't argue
contrarian for its own sake. The mandate is capital preservation > growth.

Output ≤ 300 words. End with: "BEAR THESIS: pass on [trade] because [X]"
OR "BEAR CONCLUSION: bull case is strong; my objection is [residual concern]."
"""

TRADER_SYSTEM = """You are the Trader. You synthesize the analyst reports
(and Bull/Bear debate if it ran) into a concrete proposal for the Risk Manager.

You have the playbook in your system prompt. You have access to all read-only
tools, can call kelly_size_proposal for edge-aware sizing, and can journal.
You CANNOT place orders — the Risk Manager does that after review.

### REGIME-IMPLIED MINIMUM DEPLOYMENT (the under-deployment fix)

In a confirmed trend regime, BEING UNDER-DEPLOYED IS ITS OWN MISTAKE. The
agent has historically left 75%+ of upside on the table by scouting tiny
and never adding. The Risk Manager will REJECT under-sized proposals in
confirmed trends. Internalize this floor:

| Regime / context                       | Min book deployment | Starter size |
| -------------------------------------- | ------------------- | ------------ |
| TREND-UP wk 1, conf ≥ 3, VIX < 18     | 8% min              | 5-7%         |
| TREND-UP wk ≥ 2, conf ≥ 4, VIX < 16    | 15% min             | 7-10%        |
| TREND-UP wk ≥ 3, conf 5, VIX < 14      | 25% min             | 8-10%        |
| RANGE                                  | 0-10%               | 4-6% scout   |
| TREND-DOWN, CAPITULATION (early)        | 0-5% scout          | 3-5% scout   |
| Binary print this week                 | hold, no new adds   | n/a          |

If your proposal puts the book below the regime minimum, you must either
(a) propose multiple positions in one tick to clear the floor, or (b)
write an EXPLICIT defense for why this tick justifies under-sizing
(e.g. "binary print 36h out per Macro Analyst").

Output a JSON proposal in this format inside a ```proposal block:

```proposal
{
  "action": "buy" | "sell" | "hold" | "no_trade",
  "symbol": "TICKER or null",
  "qty": float or null,
  "order_type": "market" | "limit",
  "limit_price": float or null,
  "reason": "one-line thesis",
  "invalidation": "price level or condition",
  "day2_weakness_criterion": "exit if held overnight",
  "confidence": 1-5,
  "regime": "TREND-UP|RANGE|TREND-DOWN|CHOP|CAPITULATION",
  "proposed_book_deployment_pct": <projected % of NAV deployed if this fires>,
  "regime_min_floor_pct": <the table value above>,
  "under_floor_defense": "n/a, or your written defense if proposing under floor"
}
```

Most ticks in chop/range should end with no_trade. Most ticks in
high-conviction TREND-UP should NOT end with no_trade — you have a floor
to clear.
"""

RISK_MANAGER_SYSTEM = """You are the Risk Manager / Portfolio Manager.
You hold the order book authority. Nothing trades without your approval.

### TWO-SIDED GATING (the under-deployment fix)

You gate BOTH directions:

* **Over-sized**: reject if breaches any hard rail (20% position cap,
  10% order cap, 5% cash floor, daily -5% halt) or playbook rule.
* **Under-sized**: reject if the Trader's `proposed_book_deployment_pct`
  is below `regime_min_floor_pct` AND the `under_floor_defense` is
  unconvincing. Default stance: in confirmed TREND-UP (conf ≥ 4, VIX
  < 18, no binary print this week), a 0% no_trade is NOT acceptable —
  you must reject and require the Trader to re-propose at the floor
  or articulate a specific binary-event defense.

The historical agent's #1 weakness has been under-deployment in clean
TREND-UP. You are the corrective. A flat week in a +3% SPY week IS a loss.

### Process

1. Parse the proposal block. Read `regime`, `confidence`,
   `proposed_book_deployment_pct`, `regime_min_floor_pct`,
   `under_floor_defense`.
2. Apply over-sized rails (hard rejection).
3. Apply under-sized check (regime-dependent challenge):
   - If proposed >= floor: proceed to step 4.
   - If proposed < floor AND defense is weak/missing: REJECT, call
     add_journal_note with the rejection reason and the floor value.
     The Trader will re-propose next tick. Do NOT call place_order.
   - If proposed < floor AND defense is specific & credible: APPROVE,
     journal the floor exception explicitly.
4. Check fresh info via read-only tools (has the tape moved? new alert?).
5. Decide: APPROVE (call place_order), APPROVE WITH SIZE MODIFICATION
   (call place_order with adjusted size and journal why), or REJECT
   (journal why; do NOT place_order).

End your reply with a one-paragraph operator summary including: the
final action, whether the regime floor was met, and any rail or floor
modifications made.
"""


# ───────────────────────────────────────────────────────────────────────────
# Role runners
# ───────────────────────────────────────────────────────────────────────────

def _build_system(role_prompt: str) -> list[dict]:
    return [
        {"type": "text", "text": role_prompt},
        {
            "type": "text",
            "text": "# Shared Playbook (the agent's strategy memory)\n\n" + playbook.read(),
            "cache_control": {"type": "ephemeral"},
        },
    ]


def _run_role(client: anthropic.Anthropic, role_prompt: str, user_prompt: str,
              tools_list: list, max_tokens: int = 4000, max_tool_iters: int = 8) -> dict:
    """Run one role with the tool runner. Returns {text, tool_calls, usage}."""
    runner = client.beta.messages.tool_runner(
        model=config.MODEL,
        max_tokens=max_tokens,
        system=_build_system(role_prompt),
        thinking={"type": "adaptive"},
        tools=tools_list,
        messages=[{"role": "user", "content": user_prompt}],
        max_iterations=max_tool_iters,
    )
    final_text, tool_calls = "", 0
    usage = {"input_tokens": 0, "output_tokens": 0, "cache_read_input_tokens": 0}
    for message in runner:
        for block in message.content:
            if block.type == "text":
                final_text = block.text
            elif block.type == "tool_use":
                tool_calls += 1
        if hasattr(message, "usage") and message.usage:
            usage["input_tokens"] += getattr(message.usage, "input_tokens", 0) or 0
            usage["output_tokens"] += getattr(message.usage, "output_tokens", 0) or 0
            usage["cache_read_input_tokens"] += getattr(message.usage, "cache_read_input_tokens", 0) or 0
    return {"text": final_text, "tool_calls": tool_calls, "usage": usage}


# ───────────────────────────────────────────────────────────────────────────
# Pipeline
# ───────────────────────────────────────────────────────────────────────────

def _client() -> anthropic.Anthropic:
    return anthropic.Anthropic(**config.resolve_anthropic_credentials())


def _tick_context() -> str:
    state = pf.load()
    quotes_map = {sym: market_data.quotes([sym]).get(sym.upper()) for sym in state.watchlist}
    backtest_note = ""
    if clock.is_simulated():
        backtest_note = f"BACKTEST MODE — simulating close of {clock.today().isoformat()}. " \
                        f"News/alerts via pre-indexed cache. Do not assume knowledge after this date."
    return (
        f"Tick at {clock.iso()}. Market open: {market_data.market_is_open()}.\n"
        f"{backtest_note}\n\n"
        f"Watchlist quote snapshot:\n{json.dumps(quotes_map, default=str)}\n"
    )


def run_tick_multiagent(debate_rounds: int = 1, log_each_role: bool = True) -> dict:
    """Run one tick through the multi-agent pipeline.

    Args:
        debate_rounds: How many full bull→bear cycles before trader synthesis.
        log_each_role: If True, append each role's output to the journal so we
            can audit decisions and learn what each agent contributed.
    """
    client = _client()
    ctx = _tick_context()
    total_usage = {"input_tokens": 0, "output_tokens": 0, "cache_read_input_tokens": 0}

    def add_usage(u):
        for k in total_usage: total_usage[k] += u.get(k, 0)

    # Phase 1: Analysts (parallel via threads)
    analyst_user = ctx + "\nProduce your specialist report."
    with ThreadPoolExecutor(max_workers=4) as ex:
        futs = {
            "fundamentals": ex.submit(_run_role, client, FUNDAMENTALS_SYSTEM,
                                      analyst_user, READ_ONLY_TOOLS, 3000),
            "sentiment": ex.submit(_run_role, client, SENTIMENT_SYSTEM,
                                   analyst_user, READ_ONLY_TOOLS, 3000),
            "macro": ex.submit(_run_role, client, NEWS_MACRO_SYSTEM,
                               analyst_user, READ_ONLY_TOOLS, 3000),
            "technical": ex.submit(_run_role, client, TECHNICAL_SYSTEM,
                                   analyst_user, READ_ONLY_TOOLS, 3000),
        }
        reports = {k: f.result() for k, f in futs.items()}
    for r in reports.values():
        add_usage(r["usage"])

    if log_each_role:
        for name, r in reports.items():
            journal.append(f"analyst_{name}", {"text": r["text"], "tool_calls": r["tool_calls"]})

    # Phase 2: Bull / Bear debate
    debate_history = []
    reports_blob = "\n\n".join(
        f"### {name.upper()} REPORT\n{r['text']}" for name, r in reports.items()
    )

    # Skip-debate gate: parse Macro Analyst regime tag. In a high-conviction
    # TREND-UP with no binary print this week, the Bear Researcher only
    # introduces under-deployment bias. Skip the debate.
    macro_text = reports.get("macro", {}).get("text", "")
    skip_debate = False
    skip_reason = ""
    m = re.search(r"REGIME_TAG:\s*(\S+),\s*confidence\s*(\d+),\s*binary_print_this_week:\s*(\w+)",
                  macro_text, re.IGNORECASE)
    if m:
        regime = m.group(1).upper()
        conf = int(m.group(2))
        binary = m.group(3).lower() == "yes"
        if regime == "TREND-UP" and conf >= 4 and not binary:
            skip_debate = True
            skip_reason = f"macro conf {conf}/5 TREND-UP, no binary print — bear debate skipped"

    if not skip_debate:
        for round_i in range(debate_rounds):
            bull_prompt = (ctx + "\n\n" + reports_blob + "\n\n" +
                           (f"PRIOR DEBATE:\n{json.dumps(debate_history, indent=2)}\n\n" if debate_history else "") +
                           "Make the bull case for THIS tick.")
            bull = _run_role(client, BULL_SYSTEM, bull_prompt, [], 3000, max_tool_iters=0)
            add_usage(bull["usage"])
            debate_history.append({"role": "bull", "round": round_i, "text": bull["text"]})

            bear_prompt = (ctx + "\n\n" + reports_blob + "\n\n" +
                           f"BULL JUST ARGUED:\n{bull['text']}\n\n" +
                           "Make the bear case in response.")
            bear = _run_role(client, BEAR_SYSTEM, bear_prompt, [], 3000, max_tool_iters=0)
            add_usage(bear["usage"])
            debate_history.append({"role": "bear", "round": round_i, "text": bear["text"]})
    else:
        debate_history.append({"role": "system", "text": skip_reason})

    if log_each_role:
        journal.append("debate", {"rounds": debate_rounds if not skip_debate else 0,
                                  "skipped": skip_debate, "skip_reason": skip_reason,
                                  "history": debate_history})

    # Phase 3: Trader synthesizes proposal
    trader_prompt = (ctx + "\n\n" + reports_blob + "\n\n" +
                     f"BULL/BEAR DEBATE:\n{json.dumps(debate_history, indent=2)}\n\n" +
                     "Write your proposal in the ```proposal block format.")
    trader = _run_role(client, TRADER_SYSTEM, trader_prompt, TRADER_TOOLS, 4000)
    add_usage(trader["usage"])
    if log_each_role:
        journal.append("trader_proposal", {"text": trader["text"]})

    # Phase 4: Risk Manager
    risk_prompt = (ctx + "\n\n" +
                   f"TRADER PROPOSAL:\n{trader['text']}\n\n" +
                   "Review. If approving, call place_order. If modifying, call place_order " +
                   "with your adjustments and journal why. If rejecting, journal why. " +
                   "End with a one-paragraph operator summary.")
    risk_mgr = _run_role(client, RISK_MANAGER_SYSTEM, risk_prompt, RISK_TOOLS, 4000)
    add_usage(risk_mgr["usage"])

    final_summary = risk_mgr["text"]
    if log_each_role:
        journal.append("risk_manager", {"text": final_summary, "tool_calls": risk_mgr["tool_calls"]})

    # Post-tick risk check
    state = pf.load()
    quotes = market_data.quotes(list(state.watchlist) + list(state.positions.keys()))
    risk.check_daily_halt(state, quotes)

    result = {
        "t": clock.iso(),
        "summary": final_summary,
        "risk": risk.summary(state, quotes),
        "usage": total_usage,
        "debate_skipped": skip_debate,
        "skip_reason": skip_reason,
        "phases": {
            "fundamentals_tools": reports["fundamentals"]["tool_calls"],
            "sentiment_tools": reports["sentiment"]["tool_calls"],
            "macro_tools": reports["macro"]["tool_calls"],
            "technical_tools": reports["technical"]["tool_calls"],
            "trader_tools": trader["tool_calls"],
            "risk_manager_tools": risk_mgr["tool_calls"],
        },
    }
    with config.TICK_LOG_PATH.open("a") as f:
        f.write(json.dumps(result, default=str) + "\n")
    return result
