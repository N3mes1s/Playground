import json
import time
import uuid
from dataclasses import asdict
from datetime import date, datetime, timedelta
from pathlib import Path

import agent
import clock
import config
import journal
import market_data
import playbook
import portfolio as pf
import risk


def _configure_data_dir(d: Path) -> None:
    d.mkdir(parents=True, exist_ok=True)
    config.DATA_DIR = d
    config.PORTFOLIO_PATH = d / "portfolio.json"
    config.JOURNAL_PATH = d / "journal.jsonl"
    config.PLAYBOOK_PATH = d / "playbook.md"
    config.TICK_LOG_PATH = d / "ticks.jsonl"


def _process_open_limit_orders(state: pf.State, on_date: date) -> list[dict]:
    """Check open limit orders against today's H/L; fill at limit price if touched."""
    fills = []
    remaining = []
    for order in state.open_orders:
        bar = market_data.day_bar(order.symbol, on_date)
        if not bar:
            remaining.append(order)
            continue
        filled = False
        if order.side == "buy" and bar["l"] <= (order.limit_price or 0):
            fill = pf.apply_fill(state, order, order.limit_price)
            fills.append({"order_id": order.id, "symbol": order.symbol,
                          "side": "buy", "price": order.limit_price, "qty": order.qty})
            journal.append("fill", {"order": order, "fill": fill, "reason": "limit triggered (backtest)"})
            filled = True
        elif order.side == "sell" and bar["h"] >= (order.limit_price or 0):
            fill = pf.apply_fill(state, order, order.limit_price)
            fills.append({"order_id": order.id, "symbol": order.symbol,
                          "side": "sell", "price": order.limit_price, "qty": order.qty})
            journal.append("fill", {"order": order, "fill": fill, "reason": "limit triggered (backtest)"})
            filled = True
        if not filled:
            remaining.append(order)
    state.open_orders = remaining
    return fills


def _portfolio_value(state: pf.State) -> float:
    quotes = market_data.quotes(list(state.watchlist) + list(state.positions.keys()))
    return pf.market_value(state, quotes)


def run(
    start: date,
    end: date,
    starting_cash: float,
    watchlist: list[str],
    run_id: str | None = None,
    use_multiagent: bool = False,
) -> dict:
    run_id = run_id or f"bt_{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}_{uuid.uuid4().hex[:6]}"
    out_dir = Path(__file__).parent / "data" / "backtests" / run_id
    _configure_data_dir(out_dir)

    print(f"[backtest] run_id={run_id} out={out_dir}")
    print(f"[backtest] window {start} -> {end}, cash=${starting_cash}, "
          f"watchlist={watchlist}")

    fetch_start = (start - timedelta(days=400)).isoformat()
    fetch_end = (end + timedelta(days=2)).isoformat()
    print(f"[backtest] prefetching OHLC {fetch_start} -> {fetch_end} for "
          f"{len(watchlist)} symbols...")
    market_data.prefetch(watchlist, fetch_start, fetch_end)
    print(f"[backtest] prefetch done.")

    days = market_data.trading_days(start, end)
    print(f"[backtest] {len(days)} trading days in window.")

    pf.init(starting_cash=starting_cash, watchlist=watchlist)
    if config.PLAYBOOK_PATH.exists():
        config.PLAYBOOK_PATH.unlink()

    weekly_marks = []
    week_start_value = starting_cash
    week_start_date = None
    daily_records = []

    for i, d in enumerate(days):
        clock.set_date(d)
        state = pf.load()

        if week_start_date is None:
            week_start_date = d
            week_start_value = _portfolio_value(state)

        # Process limit orders from prior day against today's bars
        limit_fills = _process_open_limit_orders(state, d)
        if limit_fills:
            pf.save(state)
            state = pf.load()

        # Reset day_start for halt accounting
        state.day_start_value = _portfolio_value(state)
        state.day_start_date = d.isoformat()
        state.halted_until = None
        pf.save(state)

        # Run agent tick
        t0 = time.time()
        try:
            if use_multiagent:
                import multiagent
                result = multiagent.run_tick_multiagent(debate_rounds=1, log_each_role=False)
                # Normalize shape: backtest expects tool_calls flat
                tool_calls = sum(result.get("phases", {}).values())
                result["tool_calls"] = tool_calls
            else:
                result = agent.run_tick()
        except Exception as e:
            result = {"summary": f"ERROR: {e}", "tool_calls": 0,
                      "usage": {"input_tokens": 0, "output_tokens": 0, "cache_read_input_tokens": 0}}
        dt = time.time() - t0

        state = pf.load()
        pv = _portfolio_value(state)
        positions_str = ",".join(f"{p.symbol}({p.qty:.1f})" for p in state.positions.values())
        print(f"[{i+1:>2}/{len(days)}] {d.isoformat()}  pv=${pv:>9.2f}  "
              f"cash=${state.cash:>8.2f}  pos=[{positions_str}]  "
              f"tools={result.get('tool_calls',0)}  {dt:.1f}s")

        daily_records.append({
            "date": d.isoformat(),
            "portfolio_value": round(pv, 2),
            "cash": round(state.cash, 2),
            "positions": [asdict(p) for p in state.positions.values()],
            "open_orders": len(state.open_orders),
            "limit_fills_today": limit_fills,
            "tool_calls": result.get("tool_calls", 0),
            "usage": result.get("usage", {}),
            "summary": result.get("summary", ""),
            "duration_sec": round(dt, 1),
        })

        # Friday → weekly close
        is_friday = d.weekday() == 4
        is_last = i == len(days) - 1
        if is_friday or is_last:
            print(f"[backtest] running weekly close (week {week_start_date} -> {d})...")
            t0 = time.time()
            try:
                close_result = agent.run_weekly_close()
            except Exception as e:
                close_result = {"summary": f"ERROR: {e}", "tool_calls": 0}
            wdt = time.time() - t0
            weekly_marks.append({
                "week_start": week_start_date.isoformat(),
                "week_end": d.isoformat(),
                "start_value": round(week_start_value, 2),
                "end_value": round(pv, 2),
                "weekly_return": round((pv - week_start_value) / week_start_value, 4),
                "summary": close_result.get("summary", ""),
                "duration_sec": round(wdt, 1),
            })
            print(f"[backtest] weekly P&L: ${pv - week_start_value:+.2f} "
                  f"({(pv - week_start_value) / week_start_value:+.2%}) in {wdt:.1f}s")
            week_start_date = None

    clock.set_date(None)

    summary = {
        "run_id": run_id,
        "start": start.isoformat(),
        "end": end.isoformat(),
        "trading_days": len(days),
        "starting_cash": starting_cash,
        "final_value": daily_records[-1]["portfolio_value"] if daily_records else starting_cash,
        "total_return": round(
            (daily_records[-1]["portfolio_value"] - starting_cash) / starting_cash, 4
        ) if daily_records else 0,
        "weekly_marks": weekly_marks,
        "green_weeks": sum(1 for w in weekly_marks if w["weekly_return"] > 0),
        "red_weeks": sum(1 for w in weekly_marks if w["weekly_return"] < 0),
        "flat_weeks": sum(1 for w in weekly_marks if w["weekly_return"] == 0),
        "best_week": max((w for w in weekly_marks), key=lambda w: w["weekly_return"], default=None),
        "worst_week": min((w for w in weekly_marks), key=lambda w: w["weekly_return"], default=None),
        "total_tokens": {
            "input": sum(r["usage"].get("input_tokens", 0) for r in daily_records),
            "output": sum(r["usage"].get("output_tokens", 0) for r in daily_records),
            "cache_read": sum(r["usage"].get("cache_read_input_tokens", 0) for r in daily_records),
        },
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
    (out_dir / "daily.jsonl").write_text("\n".join(json.dumps(r, default=str) for r in daily_records))
    return summary
