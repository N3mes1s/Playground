import json
from datetime import datetime, timezone

import anthropic

import clock
import config
import journal
import market_data
import playbook
import portfolio as pf
import risk
import tools

SYSTEM_BASE = """You are a paper-trading agent for US equities. Your mandate is to grow a
fixed paper portfolio while closing each calendar week with positive P&L. Capital
preservation outranks aggressive growth — a flat week beats a red one.

You trade long-only stocks and ETFs. No shorts, no options, no leverage. Your harness
enforces hard risk rails (max position 20%, max order 10%, min cash 5%, daily-loss halt
at -5%) — orders that breach them are rejected. Don't argue with the rails; size into
positions in tranches instead of going to the cap on a single order.

You have ten tools: portfolio snapshot, single quote, OHLCV history, targeted news
search (`search_news`), bundled macro/policy scan (`scan_macro_and_policy`),
place/cancel orders, journal note, and (during weekly close only) playbook rewrite.

## Required tick protocol — every tick, in this order

1. **State.** Call `get_portfolio_snapshot`. Note cash, positions, unrealized P&L, and
   intraday loss vs the halt threshold.
2. **News & policy.** Call `scan_macro_and_policy` UNLESS you've already called it
   this trading session AND nothing intraday suggests a fresh catalyst. The scan
   surfaces what unusualwhales.com would call "the tape catalysts" — political
   commentary on specific stocks/sectors (especially Trump statements naming
   tickers or industries), Fed/Powell speak, tariff and trade news, executive
   orders, and SEC/DOJ regulatory action affecting your watchlist. **A position
   you'd open without checking these is a position you can't defend at week-end.**
3. **Targeted research.** For any name you're considering trading (entry, add, or
   exit), call `search_news` with a specific objective — e.g. "what's driving NVDA
   today" or "any Trump or admin comments on semiconductors today". Confirm the
   catalyst before sizing.
4. **Decide.** Most ticks should end with no trade. The cost of doing nothing is
   zero; the cost of a bad trade is real money. If the news flow contradicts your
   thesis, don't trade — even if the chart looks good.
5. **Order rationale.** Every `place_order` call needs a one-line `reason`
   referencing both the chart signal AND the news/policy context if any. If you
   can't articulate it in one line, don't trade.
6. **Journal.** Use `add_journal_note` to log macro reads, watchlist updates, and
   anything you're waiting on. Your future self at weekly close will read these.

## What to look for in the macro/policy scan

- **Political commentary on stocks/sectors:** Trump or admin officials naming a
  specific ticker, industry, or trade partner — these move prices intraday more
  than most chart signals.
- **Tariff / trade news:** Especially anything affecting semis (TSM/NVDA/AMD),
  large-cap exporters (AAPL/TSLA), and China-exposed names.
- **Fed / Powell:** Rate path commentary, balance sheet, dot plots. Rates-sensitive
  names (tech, REITs, regional banks) react.
- **Executive orders / regulatory:** Drug pricing → pharma; antitrust → big tech;
  energy permitting → XOM/CVX/SLB; defense procurement → LMT/RTX.
- **Geopolitics:** Conflicts, sanctions, major elections — risk-off bias.

## Trading style (refine in the playbook over time)

- Lead with macro: SPY trend and VIX before stock-picking.
- Scale in over two or three tranches; never go to the position cap in one order.
- Cut losers fast (3-5% trailing); let winners run (8-10% trailing).
- Friday afternoon: trim risk, don't add it.
- If the daily-halt rail trips, journal what went wrong and stop.
- Don't trade against fresh political/policy news — wait for the dust to settle.

Be terse in your messages back to the harness. The journal and your tool calls are
the durable record; chat text is just for the operator scanning logs.
"""


def _ts() -> str:
    return clock.iso()


def _tick_user_prompt() -> str:
    state = pf.load()
    quotes_map = {sym: market_data.quotes([sym]).get(sym.upper()) for sym in state.watchlist}
    backtest_banner = ""
    if clock.is_simulated():
        backtest_banner = (
            f"\n\n*** BACKTEST MODE ***\n"
            f"This is a historical simulation as of the close of {clock.today().isoformat()}.\n"
            f"`search_news` is disabled — rely on price action and the playbook.\n"
            f"You do not know what happened after this date. Trade as if it's the close of that day.\n"
        )
    return (
        f"Tick at {_ts()}. Market open: {market_data.market_is_open()}.{backtest_banner}\n\n"
        f"Watchlist quote snapshot (use get_quote for fresh data before trading):\n"
        f"{json.dumps(quotes_map, default=str)}\n\n"
        f"Run the tick. End with a brief one-paragraph summary of your decision."
    )


def _weekly_close_prompt() -> str:
    week_journal = journal.read_since(days=7)
    state = pf.load()
    return (
        f"Weekly close at {_ts()}.\n\n"
        f"Starting cash: ${state.starting_cash:.2f}\n"
        f"Current portfolio (call get_portfolio_snapshot for full detail).\n\n"
        f"Last 7 days of journal entries (fills, opens, cancels, notes):\n"
        f"```jsonl\n{chr(10).join(json.dumps(e, default=str) for e in week_journal)}\n```\n\n"
        f"Do the retro:\n"
        f"1. Compute weekly P&L from the snapshot vs starting cash.\n"
        f"2. Identify the 3 best and 3 worst decisions of the week (by P&L impact or\n"
        f"   by lesson learned, not just dollar size).\n"
        f"3. Pull out 2-4 sharpened heuristics and 1-2 to retire.\n"
        f"4. Suggest watchlist additions/removals (write them in the playbook, but the\n"
        f"   operator updates the actual watchlist).\n"
        f"5. Call `rewrite_playbook` with the new full content. Keep under ~2000 words.\n"
        f"6. End with a one-paragraph summary of the week for the operator.\n"
    )


def _build_system() -> list[dict]:
    return [
        {"type": "text", "text": SYSTEM_BASE},
        {
            "type": "text",
            "text": "# Current Playbook (rewritten weekly by you)\n\n" + playbook.read(),
            "cache_control": {"type": "ephemeral"},
        },
    ]


def _client() -> anthropic.Anthropic:
    return anthropic.Anthropic(**config.resolve_anthropic_credentials())


def run_tick() -> dict:
    client = _client()
    runner = client.beta.messages.tool_runner(
        model=config.MODEL,
        max_tokens=8000,
        system=_build_system(),
        thinking={"type": "adaptive"},
        tools=tools.TICK_TOOLS,
        messages=[{"role": "user", "content": _tick_user_prompt()}],
    )

    final_text = ""
    tool_calls = 0
    usage = {"input_tokens": 0, "output_tokens": 0, "cache_read_input_tokens": 0}
    for message in runner:
        for block in message.content:
            if block.type == "text":
                final_text = block.text
            elif block.type == "tool_use":
                tool_calls += 1
        if hasattr(message, "usage") and message.usage:
            usage["input_tokens"] += message.usage.input_tokens or 0
            usage["output_tokens"] += message.usage.output_tokens or 0
            usage["cache_read_input_tokens"] += getattr(
                message.usage, "cache_read_input_tokens", 0
            ) or 0

    state = pf.load()
    quotes = market_data.quotes(list(state.watchlist) + list(state.positions.keys()))
    risk.check_daily_halt(state, quotes)

    result = {
        "t": _ts(),
        "tool_calls": tool_calls,
        "summary": final_text,
        "risk": risk.summary(state, quotes),
        "usage": usage,
    }
    with config.TICK_LOG_PATH.open("a") as f:
        f.write(json.dumps(result, default=str) + "\n")
    return result


def run_weekly_close() -> dict:
    client = _client()
    runner = client.beta.messages.tool_runner(
        model=config.MODEL,
        max_tokens=16000,
        system=_build_system(),
        thinking={"type": "adaptive"},
        tools=tools.WEEKLY_CLOSE_TOOLS,
        messages=[{"role": "user", "content": _weekly_close_prompt()}],
    )

    final_text = ""
    tool_calls = 0
    for message in runner:
        for block in message.content:
            if block.type == "text":
                final_text = block.text
            elif block.type == "tool_use":
                tool_calls += 1

    journal.append("weekly_close", {"summary": final_text, "tool_calls": tool_calls})
    return {"t": _ts(), "tool_calls": tool_calls, "summary": final_text}
