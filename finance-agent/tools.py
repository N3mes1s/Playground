import functools
import json

from anthropic import beta_tool

import clock
import journal
import market_data
import playbook
import portfolio as pf
import research
import risk


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
        return {
            "error": "news search disabled in backtest mode (parallel.ai returns current "
                     "news, which would be lookahead for a historical simulation). Rely on "
                     "price/volume action and the playbook."
        }
    return research.search(objective, max_results=min(max_results, 10))


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


TICK_TOOLS = [
    get_portfolio_snapshot,
    get_quote,
    get_history,
    search_news,
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
