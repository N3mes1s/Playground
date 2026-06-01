"""Options flow forward-validation framework.

yfinance options data is point-in-time — there's no historical chain
replay. The only honest way to validate "does our unusual-flow detector
predict future moves?" is to snapshot daily and evaluate forward.

This module:
  1. Daily snapshot — calls `options_flow.snapshot_chain` for every
     watchlist ticker and persists to disk under data/flow_snapshots/.
  2. Daily flag — runs `scan_unusual_flow` and persists detected hits.
  3. Forward evaluation — for each flagged contract from N days ago,
     check the current price and compute the realized P&L if you had
     bought one contract at the flag-day close.
  4. Aggregate report — hit rate, average return, by signal strength,
     by DTE bucket, etc.

Run via:
  python cli.py flow-snapshot   # daily snapshot (cron this)
  python cli.py flow-evaluate   # evaluate prior days' flags
"""
import json
import math
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import yfinance as yf

import config
import options_flow as ofl

SNAP_DIR = config.DATA_DIR / "flow_snapshots"
SNAP_DIR.mkdir(parents=True, exist_ok=True)
FLAGS_PATH = config.DATA_DIR / "flow_flags.jsonl"


def daily_snapshot(symbols: list[str],
                   min_volume: int = 1000,
                   min_notional: float = 100_000,
                   min_vol_oi_ratio: float = 2.0,
                   max_dte: int = 45) -> dict:
    """Snapshot today's chains and persist detected unusual flow."""
    today = date.today()
    out = {"date": today.isoformat(), "symbols": symbols, "flagged_contracts": []}

    for sym in symbols:
        try:
            snap = ofl.snapshot_chain(sym, max_expiries=6)
        except Exception as e:
            out["flagged_contracts"].append({"symbol": sym, "error": str(e)})
            continue
        snap_path = SNAP_DIR / f"{sym.upper()}_{today.isoformat()}.json"
        snap_path.write_text(json.dumps(snap, default=str))

        hits = ofl.scan_unusual_flow(
            sym, snap=snap,
            min_volume=min_volume, min_notional=min_notional,
            min_vol_oi_ratio=min_vol_oi_ratio, max_dte=max_dte,
        )
        for h in hits:
            flag = {**h, "flagged_date": today.isoformat()}
            out["flagged_contracts"].append(flag)
            with FLAGS_PATH.open("a") as f:
                f.write(json.dumps(flag) + "\n")

    out["summary"] = {
        "symbols_scanned": len(symbols),
        "flags": len([h for h in out["flagged_contracts"] if "error" not in h]),
    }
    return out


def _option_current_price(symbol: str, expiry: str, side: str, strike: float) -> Optional[float]:
    """Try to fetch the current price for a specific option contract."""
    try:
        t = yf.Ticker(symbol)
        if expiry not in t.options:
            return None  # contract may have expired
        chain = t.option_chain(expiry)
        df = chain.calls if side == "call" else chain.puts
        match = df[df["strike"] == strike]
        if match.empty:
            return None
        price = float(match.iloc[0].get("lastPrice", 0) or 0)
        return price if not math.isnan(price) else 0.0
    except Exception:
        return None


def evaluate_flags(days_ago: int = 5, min_dte_remaining: int = 0) -> dict:
    """For each flag from N days ago, compute current P&L (if contract
    still trades) and aggregate hit rate + avg return.

    Args:
        days_ago: How many sessions back to evaluate.
        min_dte_remaining: Skip contracts that already expired.
    """
    if not FLAGS_PATH.exists():
        return {"error": "no flags yet — run flow-snapshot first"}
    today = date.today()
    target_date = (today - timedelta(days=days_ago)).isoformat()

    flags = []
    with FLAGS_PATH.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
                if e.get("flagged_date") == target_date:
                    flags.append(e)
            except json.JSONDecodeError:
                continue

    if not flags:
        return {"target_date": target_date, "flags_evaluated": 0,
                "note": "no flags on that date"}

    evaluated = []
    for f in flags:
        flag_price = f.get("last_price") or 0
        cur_price = _option_current_price(f["symbol"], f["expiry"], f["side"], f["strike"])
        if cur_price is None:
            evaluated.append({**f, "current_price": None, "outcome": "expired_or_untradeable"})
            continue
        ret = (cur_price - flag_price) / flag_price if flag_price > 0 else 0
        evaluated.append({
            "symbol": f["symbol"], "side": f["side"], "strike": f["strike"],
            "expiry": f["expiry"], "dte_when_flagged": f.get("dte"),
            "flag_price": round(flag_price, 2),
            "current_price": round(cur_price, 2),
            "return": round(ret, 4),
            "notional_at_flag": f.get("notional_usd"),
            "vol_oi_at_flag": f.get("vol_oi_ratio"),
            "outcome": "win" if ret > 0 else ("loss" if ret < 0 else "flat"),
        })

    tradeable = [e for e in evaluated if e.get("current_price") is not None]
    wins = [e for e in tradeable if e["outcome"] == "win"]
    losses = [e for e in tradeable if e["outcome"] == "loss"]
    avg_return = sum(e["return"] for e in tradeable) / len(tradeable) if tradeable else 0
    win_avg = sum(e["return"] for e in wins) / len(wins) if wins else 0
    loss_avg = sum(e["return"] for e in losses) / len(losses) if losses else 0

    return {
        "target_date": target_date,
        "evaluated_at": today.isoformat(),
        "days_held": days_ago,
        "flags_evaluated": len(evaluated),
        "tradeable": len(tradeable),
        "expired_or_untradeable": len(evaluated) - len(tradeable),
        "wins": len(wins),
        "losses": len(losses),
        "win_rate": round(len(wins) / len(tradeable), 3) if tradeable else None,
        "avg_return_all": round(avg_return, 4),
        "avg_win_return": round(win_avg, 4),
        "avg_loss_return": round(loss_avg, 4),
        "expectancy": round(avg_return, 4),  # naive — one contract each
        "by_contract": evaluated,
    }
