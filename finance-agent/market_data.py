from datetime import datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

import yfinance as yf

ET = ZoneInfo("America/New_York")
MARKET_OPEN = time(9, 30)
MARKET_CLOSE = time(16, 0)


def market_is_open(now: datetime | None = None) -> bool:
    now = (now or datetime.now(timezone.utc)).astimezone(ET)
    if now.weekday() >= 5:
        return False
    return MARKET_OPEN <= now.time() <= MARKET_CLOSE


def next_open(now: datetime | None = None) -> datetime:
    now = (now or datetime.now(timezone.utc)).astimezone(ET)
    candidate = now.replace(hour=9, minute=30, second=0, microsecond=0)
    if candidate <= now:
        candidate += timedelta(days=1)
    while candidate.weekday() >= 5:
        candidate += timedelta(days=1)
    return candidate


def quote(symbol: str) -> dict:
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
    df = yf.Ticker(symbol).history(period=period, interval=interval, auto_adjust=False)
    rows = []
    for ts, row in df.iterrows():
        rows.append(
            {
                "t": ts.isoformat(),
                "o": float(row["Open"]),
                "h": float(row["High"]),
                "l": float(row["Low"]),
                "c": float(row["Close"]),
                "v": int(row["Volume"]),
            }
        )
    return rows
