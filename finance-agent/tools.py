import functools
import json

from anthropic import beta_tool

import analogs as ana
import clock
import journal
import kelly as kly
import market_data
import monitors as mon
import news_index
import playbook
import portfolio as pf
import prediction_markets as pmkt
import reflexion
import research
import risk
import tasks


def _quotes_for(state: pf.State) -> dict[str, float]:
    symbols = set(state.watchlist) | set(state.positions.keys())
    return market_data.quotes(sorted(symbols))


def _json_tool(fn):
    """Wrap a function returning dict/list/etc. so beta_tool sees a JSON string."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        return json.dumps(fn(*args, **kwargs), default=str)

    return beta_tool(wrapper)


@_json_tool
def get_portfolio_snapshot() -> dict:
    """Return current cash, positions (with unrealized P&L), open orders, and risk metrics."""
    state = pf.load()
    quotes = _quotes_for(state)
    pf.roll_day_if_needed(state, quotes)

    positions = []
    for pos in state.positions.values():
        last = quotes.get(pos.symbol, pos.avg_cost)
        positions.append(
            {
                "symbol": pos.symbol,
                "qty": pos.qty,
                "avg_cost": round(pos.avg_cost, 4),
                "last": round(last, 4),
                "market_value": round(pos.qty * last, 2),
                "unrealized_pnl": round((last - pos.avg_cost) * pos.qty, 2),
                "unrealized_pnl_pct": round((last - pos.avg_cost) / pos.avg_cost, 4),
            }
        )

    return {
        "watchlist": state.watchlist,
        "positions": positions,
        "open_orders": [
            {
                "id": o.id,
                "symbol": o.symbol,
                "side": o.side,
                "qty": o.qty,
                "order_type": o.order_type,
                "limit_price": o.limit_price,
                "reason": o.reason,
            }
            for o in state.open_orders
        ],
        "risk": risk.summary(state, quotes),
    }


@_json_tool
def get_quote(symbol: str) -> dict:
    """Get the latest price snapshot for a single ticker (last, prev close, day high/low).

    Args:
        symbol: Ticker, e.g. AAPL.
    """
    try:
        return market_data.quote(symbol)
    except Exception as e:
        return {"error": str(e), "symbol": symbol}


@_json_tool
def get_history(symbol: str, period: str = "1mo", interval: str = "1d") -> dict:
    """Get OHLCV history for a ticker.

    Args:
        symbol: Ticker, e.g. NVDA.
        period: yfinance period code (1d, 5d, 1mo, 3mo, 6mo, 1y, 2y, ytd, max).
        interval: Bar interval (1m, 5m, 15m, 30m, 60m, 1d, 1wk, 1mo).
    """
    try:
        bars = market_data.history(symbol, period=period, interval=interval)
        return {"symbol": symbol.upper(), "period": period, "interval": interval, "bars": bars}
    except Exception as e:
        return {"error": str(e), "symbol": symbol}


@_json_tool
def search_news(objective: str, max_results: int = 6) -> dict:
    """Search the web for current news, filings, or analyst commentary via parallel.ai.

    Args:
        objective: A natural-language research goal — e.g. "what's driving NVDA today" or
            "latest CPI release reaction".
        max_results: Up to 10.
    """
    if clock.is_simulated():
        cached = news_index.historical_news_for(clock.simulated_date())
        if "error" in cached:
            return cached
        return {
            "note": f"backtest mode: returning ALL pre-indexed scans for "
                    f"{cached['date']} (your objective is ignored — every "
                    f"scan from that day is included).",
            "objective_provided": objective,
            "indexed_queries": cached.get("queries", {}),
        }
    return research.search(objective, max_results=min(max_results, 10))


@_json_tool
def scan_macro_and_policy() -> dict:
    """Bundle the standard market-moving news scans into one call. Run this once
    per tick before deciding on any new entry. Covers political commentary on
    stocks/sectors, Fed/Powell statements, tariff and trade news, executive
    orders, and any major SEC/DOJ regulatory action affecting watchlist names.

    In backtest mode, returns the pre-indexed scans for the simulated date.
    """
    if clock.is_simulated():
        cached = news_index.historical_news_for(clock.simulated_date())
        if "error" in cached:
            return cached
        return {"scans": cached.get("queries", {}), "date": cached.get("date")}
    queries = [
        "Trump statements on specific US stocks or sectors in the last 48 hours",
        "Federal Reserve or Powell statements on rates or markets in the last 48 hours",
        "tariff trade China semiconductor news US equities last 48 hours",
        "executive orders or regulatory actions affecting US stocks last 48 hours",
        "biggest US equity market-moving news today",
    ]
    out = {}
    for q in queries:
        try:
            out[q] = research.search(q, max_results=4)
        except Exception as e:
            out[q] = {"error": str(e)}
    return {"scans": out}


@_json_tool
def place_order(
    symbol: str,
    side: str,
    qty: float,
    order_type: str = "market",
    limit_price: float | None = None,
    reason: str = "",
) -> dict:
    """Submit a paper-trading order. Validates against risk rails before filling.

    Args:
        symbol: Ticker to trade.
        side: "buy" or "sell".
        qty: Number of shares (fractional allowed).
        order_type: "market" or "limit".
        limit_price: Required if order_type is "limit".
        reason: One-line thesis for the trade. Logged to the journal.
    """
    symbol = symbol.upper()
    side = side.lower()
    if side not in ("buy", "sell"):
        return {"ok": False, "error": "side must be buy or sell"}
    if order_type not in ("market", "limit"):
        return {"ok": False, "error": "order_type must be market or limit"}
    if order_type == "limit" and limit_price is None:
        return {"ok": False, "error": "limit_price required for limit orders"}
    if qty <= 0:
        return {"ok": False, "error": "qty must be positive"}

    state = pf.load()
    quotes = _quotes_for(state)
    pf.roll_day_if_needed(state, quotes)
    if risk.check_daily_halt(state, quotes):
        return {"ok": False, "error": "daily loss circuit-breaker tripped; trading halted"}

    try:
        last = market_data.quote(symbol)["last"]
    except Exception as e:
        return {"ok": False, "error": f"could not fetch quote: {e}"}

    if side == "buy":
        check = risk.evaluate_buy(state, symbol, qty, last, quotes)
    else:
        check = risk.evaluate_sell(state, symbol, qty)
    if not check.ok:
        return {"ok": False, "error": check.reason}

    order = pf.new_order(symbol, side, qty, order_type, limit_price, reason or None)

    fill_price = None
    if order_type == "market":
        fill_price = last
    elif order_type == "limit":
        if side == "buy" and last <= limit_price:
            fill_price = min(last, limit_price)
        elif side == "sell" and last >= limit_price:
            fill_price = max(last, limit_price)

    if fill_price is not None:
        fill = pf.apply_fill(state, order, fill_price)
        pf.save(state)
        journal.append("fill", {"order": order, "fill": fill, "reason": reason})
        return {
            "ok": True,
            "filled": True,
            "order_id": order.id,
            "fill_price": fill_price,
            "fill_id": fill.id,
        }

    state.open_orders.append(order)
    pf.save(state)
    journal.append("order_open", {"order": order, "reason": reason})
    return {"ok": True, "filled": False, "order_id": order.id, "status": "open"}


@_json_tool
def cancel_order(order_id: str) -> dict:
    """Cancel an open limit order by id.

    Args:
        order_id: The order id returned by place_order.
    """
    state = pf.load()
    for i, o in enumerate(state.open_orders):
        if o.id == order_id:
            removed = state.open_orders.pop(i)
            removed.status = "canceled"
            pf.save(state)
            journal.append("order_cancel", {"order": removed})
            return {"ok": True, "order_id": order_id}
    return {"ok": False, "error": f"no open order with id {order_id}"}


@_json_tool
def add_journal_note(note: str, tags: list[str] | None = None) -> dict:
    """Add a free-form note to the trade journal (your own scratchpad — visible to your
    future self during weekly close).

    Args:
        note: The text of the note. Keep it under ~300 chars.
        tags: Optional labels like ["thesis", "macro", "watchlist"].
    """
    journal.append("note", {"note": note[:600], "tags": tags or []})
    return {"ok": True}


@_json_tool
def rewrite_playbook(content: str) -> dict:
    """Replace the playbook with new content. Only call this during weekly close.

    Args:
        content: The full new playbook in markdown. Should include lessons from the
            week's trades, refined heuristics, and watchlist suggestions. Aim for
            under ~2000 words.
    """
    playbook.write(content)
    journal.append("playbook_update", {"length": len(content)})
    return {"ok": True, "bytes_written": len(content)}


@_json_tool
def get_realtime_alerts(limit_per_monitor: int = 5) -> dict:
    """Poll all configured parallel.ai monitors for recently-detected events.
    Each monitor is a standing NL query (e.g. "Pentagon procurement news",
    "Trump statements naming stocks") that fires when material changes are
    detected. This is the agent's real-time situational awareness — use it at
    the start of every tick BEFORE deciding. Disabled in backtest mode.

    Args:
        limit_per_monitor: How many recent events to return per monitor (1-20).
    """
    if clock.is_simulated():
        return {"error": "monitors disabled in backtest mode — see scan_macro_and_policy"}
    try:
        return mon.poll_all_recent(max_events_per_monitor=min(limit_per_monitor, 20))
    except Exception as e:
        return {"error": str(e)}


@_json_tool
def kelly_size_proposal(
    win_probability: float,
    avg_win_return_pct: float,
    avg_loss_return_pct: float,
    confidence: int,
    price: float,
    current_position_value: float = 0.0,
    fractional_kelly: float = 0.25,
) -> dict:
    """Compute an edge-aware position size using fractional Kelly.

    Replaces fixed-% sizing in the playbook with a sizing prescription based
    on the trader's explicit edge estimate. Use this BEFORE placing an order
    when you can articulate the expected win probability and win/loss ratio.

    Args:
        win_probability: 0-1, your estimate of the trade winning.
        avg_win_return_pct: e.g. 0.08 for a target +8% win.
        avg_loss_return_pct: e.g. -0.04 for a -4% stop.
        confidence: 1-5, how strong is the setup; scales the fractional Kelly.
        price: current entry price for the symbol.
        current_position_value: $ already in this name (0 if new).
        fractional_kelly: default 0.25 (quarter-Kelly) for tail safety.
    """
    state = pf.load()
    quotes = market_data.quotes(list(state.watchlist) + list(state.positions.keys()))
    nav = pf.market_value(state, quotes)
    edge = kly.EdgeEstimate(
        win_prob=win_probability,
        avg_win_return=avg_win_return_pct,
        avg_loss_return=avg_loss_return_pct,
        confidence=confidence,
    )
    return kly.kelly_position_size(nav, edge, price, current_position_value, fractional_kelly)


@_json_tool
def journal_analogs(keywords: list[str], max_entries: int = 5) -> dict:
    """Retrieve past journal entries that match given keywords. Use to find
    your own prior decisions in similar setups before acting now.

    Args:
        keywords: List of terms to filter on (e.g. ["NVDA", "scout", "earnings"]).
        max_entries: How many most-recent matches to return.
    """
    return {"entries": ana.journal_analogs(keywords, n=max_entries)}


@_json_tool
def market_analogs(setup_description: str) -> dict:
    """Find historical market analogs to the current setup via web research.
    Returns prior dated episodes that look similar with their subsequent
    outcomes. Use to inform regime / catalyst calls.

    Args:
        setup_description: Specific characterization of current setup,
            e.g. "Fed paused after 75bp hike, CPI still above 3%, SPY near
            6mo high, yield curve steepening".
    """
    if clock.is_simulated():
        return {"error": "market_analogs disabled in backtest (would look up real-world data after the simulated date)"}
    return ana.market_analogs(setup_description, max_results=5)


@_json_tool
def recent_reflections(n: int = 5) -> dict:
    """Read the most recent Reflexion entries — the tight-loop per-trade
    self-critiques from prior closed positions. Read these before any new
    entry to avoid repeating recent mistakes.
    """
    return {"reflections": reflexion.recent(n=n)}


@_json_tool
def get_prediction_market_priors(category: str = "all") -> dict:
    """Pull live implied probabilities from Kalshi prediction markets for
    upcoming economic catalysts. These are real-money bets — the prices are
    calibrated forecasts you can use as priors before deciding on a trade.

    Categories: fed_rates | cpi | rates | tariffs | trump_policy | macro | all

    Use this BEFORE the macro analyst's regime call, before any rates-sensitive
    trade, or before an earnings-cluster week. Example: if the market is
    pricing a 65% probability of CPI > 3.5%, that's a real risk-off signal
    that should temper any new long.
    """
    if clock.is_simulated():
        return {"error": "prediction market priors disabled in backtest (would leak forward info)"}
    return {"markets": pmkt.get_economic_priors(category=category)}


@_json_tool
def search_prediction_markets(keyword: str) -> dict:
    """Free-text search across Kalshi prediction markets. Use for niche topics
    (specific election outcomes, named policy actions, geopolitical events).

    Args:
        keyword: e.g. "Trump tariff", "Powell replacement", "recession 2026".
    """
    if clock.is_simulated():
        return {"error": "prediction market search disabled in backtest"}
    return {"markets": pmkt.search_markets(keyword, limit=15)}


@_json_tool
def deep_research(question: str) -> dict:
    """Run a multi-hop deep research task via parallel.ai (slower than search,
    much better when you need to understand a thematic catalyst, validate a
    flow signal, or build a thesis from scratch). Returns cited research.
    Disabled in backtest mode. Blocks ~30-120s.

    Args:
        question: Specific research objective, e.g. "What's the recent
            Pentagon stance on small-cap drone makers and which tickers are
            most exposed?" or "Catalyst behind UMAC's options flow today."
    """
    if clock.is_simulated():
        return {"error": "deep_research disabled in backtest mode"}
    return tasks.deep_research(question, processor="base", timeout=300)


TICK_TOOLS = [
    get_portfolio_snapshot,
    get_quote,
    get_history,
    search_news,
    scan_macro_and_policy,
    get_realtime_alerts,
    get_prediction_market_priors,
    search_prediction_markets,
    deep_research,
    market_analogs,
    journal_analogs,
    recent_reflections,
    kelly_size_proposal,
    place_order,
    cancel_order,
    add_journal_note,
]

WEEKLY_CLOSE_TOOLS = [
    get_portfolio_snapshot,
    get_history,
    rewrite_playbook,
    add_journal_note,
]
