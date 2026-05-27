from datetime import datetime, time, timedelta, timezone

import pandas as pd
import yfinance as yf

import clock

MARKET_OPEN = time(9, 30)
MARKET_CLOSE = time(16, 0)

_history_cache: dict[str, pd.DataFrame] = {}


def prefetch(symbols: list[str], start: str, end: str) -> None:
    for sym in symbols:
        df = yf.Ticker(sym).history(start=start, end=end, interval="1d", auto_adjust=False)
        if df.index.tz is None:
            df.index = df.index.tz_localize("America/New_York")
        else:
            df.index = df.index.tz_convert("America/New_York")
        _history_cache[sym.upper()] = df


def _cached_bars_through(symbol: str, as_of) -> pd.DataFrame | None:
    df = _history_cache.get(symbol.upper())
    if df is None:
        return None
    return df[df.index.date <= as_of]


def market_is_open(now: datetime | None = None) -> bool:
    if clock.is_simulated():
        return True
    now = (now or datetime.now(timezone.utc)).astimezone(clock.ET)
    if now.weekday() >= 5:
        return False
    return MARKET_OPEN <= now.time() <= MARKET_CLOSE


def next_open(now: datetime | None = None) -> datetime:
    now = (now or datetime.now(timezone.utc)).astimezone(clock.ET)
    candidate = now.replace(hour=9, minute=30, second=0, microsecond=0)
    if candidate <= now:
        candidate += timedelta(days=1)
    while candidate.weekday() >= 5:
        candidate += timedelta(days=1)
    return candidate


def quote(symbol: str) -> dict:
    if clock.is_simulated():
        as_of = clock.simulated_date()
        bars = _cached_bars_through(symbol, as_of)
        if bars is None or bars.empty:
            raise ValueError(f"no historical data for {symbol} as of {as_of}")
        latest = bars.iloc[-1]
        prev_close = float(bars.iloc[-2]["Close"]) if len(bars) >= 2 else float(latest["Open"])
        return {
            "symbol": symbol.upper(),
            "last": float(latest["Close"]),
            "previous_close": prev_close,
            "day_high": float(latest["High"]),
            "day_low": float(latest["Low"]),
            "currency": "USD",
            "as_of": clock.iso(),
            "note": "backtest: this is the historical close for the simulated date",
        }
    t = yf.Ticker(symbol)
    fast = t.fast_info
    return {
        "symbol": symbol.upper(),
        "last": float(fast.last_price),
        "previous_close": float(fast.previous_close),
        "day_high": float(fast.day_high) if fast.day_high else None,
        "day_low": float(fast.day_low) if fast.day_low else None,
        "currency": fast.currency,
        "as_of": datetime.now(timezone.utc).isoformat(),
    }


def quotes(symbols: list[str]) -> dict[str, float]:
    if not symbols:
        return {}
    out: dict[str, float] = {}
    for sym in symbols:
        try:
            out[sym.upper()] = quote(sym)["last"]
        except Exception:
            continue
    return out


def history(symbol: str, period: str = "1mo", interval: str = "1d") -> list[dict]:
    if clock.is_simulated() and interval == "1d":
        as_of = clock.simulated_date()
        bars = _cached_bars_through(symbol, as_of)
        if bars is None or bars.empty:
            return []
        days = {"1d": 1, "5d": 5, "1mo": 22, "3mo": 66, "6mo": 132, "1y": 252, "2y": 504, "ytd": 252, "max": 5000}.get(period, 66)
        sliced = bars.tail(days)
        rows = []
        for ts, row in sliced.iterrows():
            rows.append({
                "t": ts.isoformat(),
                "o": float(row["Open"]),
                "h": float(row["High"]),
                "l": float(row["Low"]),
                "c": float(row["Close"]),
                "v": int(row["Volume"]),
            })
        return rows
    df = yf.Ticker(symbol).history(period=period, interval=interval, auto_adjust=False)
    rows = []
    for ts, row in df.iterrows():
        rows.append({
            "t": ts.isoformat(),
            "o": float(row["Open"]),
            "h": float(row["High"]),
            "l": float(row["Low"]),
            "c": float(row["Close"]),
            "v": int(row["Volume"]),
        })
    return rows


def day_bar(symbol: str, on_date) -> dict | None:
    df = _history_cache.get(symbol.upper())
    if df is None:
        return None
    matches = df[df.index.date == on_date]
    if matches.empty:
        return None
    row = matches.iloc[0]
    return {
        "o": float(row["Open"]),
        "h": float(row["High"]),
        "l": float(row["Low"]),
        "c": float(row["Close"]),
        "v": int(row["Volume"]),
    }


def trading_days(start, end) -> list:
    if not _history_cache:
        return []
    any_df = next(iter(_history_cache.values()))
    dates = sorted({ts.date() for ts in any_df.index})
    return [d for d in dates if start <= d <= end]
