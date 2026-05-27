import json
from datetime import datetime, timezone

import anthropic

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

You have nine tools: portfolio snapshot, single quote, OHLCV history, web research via
parallel.ai, place/cancel orders, journal note, and (during weekly close only) playbook
rewrite. Each tick:

1. Start with `get_portfolio_snapshot` to see where you stand — cash, positions,
   unrealized P&L, and intraday loss against the halt threshold.
2. Decide whether the tape and your existing book warrant action *this tick*. Most
   ticks should end with no trade. The cost of doing nothing is zero; the cost of a
   bad trade is real money.
3. If you're considering a trade, ground it in either (a) a price-action signal you
   can verify with `get_history`, or (b) a catalyst you can verify with `search_news`.
   Vibes are not a thesis.
4. Before placing an order, write a one-line `reason` argument explaining the setup.
   It will be journaled and reviewed at week-end. If you can't articulate a clean
   reason in one line, don't trade.
5. Use `add_journal_note` for context that doesn't fit on an order — macro reads,
   watchlist updates, things you're waiting on.

Trading style guidelines (refine these in the playbook over time):

- Lead with macro: check SPY trend and VIX before stock-picking.
- Scale in over two or three tranches; never go to your position cap in one order.
- Cut losers fast (3-5% trailing); let winners run (8-10% trailing).
- Friday afternoon: trim risk, don't add it.
- If the daily-halt rail trips, journal what went wrong and stop.

Be terse in your messages back to the harness. The journal and your tool calls are
the durable record; chat text is just for the operator scanning logs.
"""


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tick_user_prompt() -> str:
    state = pf.load()
    quotes_map = {sym: market_data.quotes([sym]).get(sym.upper()) for sym in state.watchlist}
    return (
        f"Tick at {_ts()}. Market open: {market_data.market_is_open()}.\n\n"
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
