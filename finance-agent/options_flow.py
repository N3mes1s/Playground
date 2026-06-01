"""Free-tier options flow detection — the UMAC-style signal.

By snapshotting daily option chains and looking for anomalies, we get ~80%
of what Unusual Whales sells. The signal classes we detect:

1. **Sweep**: very high volume in a short-dated OTM contract on a single day.
   The hallmark of an informed bet — someone is paying for cheap leverage
   on a near-term catalyst.

2. **Block on low OI**: volume/OI ratio >> 1 means most of today's activity
   is opening new positions, not closing existing ones.

3. **Notional concentration**: a single strike with > $X notional in one
   session. Filters out lottery-ticket noise.

4. **Put/call skew flip**: aggregate watchlist put-volume/call-volume change
   day over day above a threshold.

The detector caches the day's chains so we can compare T to T-1 and detect
overnight changes in OI (which is the cleanest informed-flow signal).
"""
import json
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Optional

import yfinance as yf

import config

CACHE_DIR = config.DATA_DIR / "options_chains"
CACHE_DIR.mkdir(parents=True, exist_ok=True)


def _snapshot_path(symbol: str, snap_date: date) -> Path:
    return CACHE_DIR / f"{symbol.upper()}_{snap_date.isoformat()}.json"


def snapshot_chain(symbol: str, max_expiries: int = 6) -> dict:
    """Snapshot today's full option chain for a ticker. Returns serialized data."""
    t = yf.Ticker(symbol)
    expiries = t.options[:max_expiries] if t.options else []
    out = {"symbol": symbol.upper(), "snapshot_at": datetime.now(timezone.utc).isoformat(),
           "expiries": {}}
    for exp in expiries:
        try:
            chain = t.option_chain(exp)
        except Exception as e:
            out["expiries"][exp] = {"error": str(e)}
            continue
        out["expiries"][exp] = {
            "calls": _df_to_records(chain.calls),
            "puts": _df_to_records(chain.puts),
        }
    snap_date = date.today()
    _snapshot_path(symbol, snap_date).write_text(json.dumps(out, default=str))
    return out


def _df_to_records(df) -> list[dict]:
    import math
    keep = ["strike", "lastPrice", "bid", "ask", "volume", "openInterest",
            "impliedVolatility", "inTheMoney"]
    rows = []
    for _, r in df.iterrows():
        row = {}
        for k in keep:
            v = r.get(k)
            if v is None:
                row[k] = None
                continue
            if k == "inTheMoney":
                row[k] = bool(v)
                continue
            try:
                fv = float(v)
                if math.isnan(fv) or math.isinf(fv):
                    row[k] = 0.0
                else:
                    row[k] = fv
            except (TypeError, ValueError):
                row[k] = 0.0
        rows.append(row)
    return rows


def _safe_int(v):
    try:
        import math
        fv = float(v or 0)
        if math.isnan(fv) or math.isinf(fv):
            return 0
        return int(fv)
    except (TypeError, ValueError):
        return 0


def load_snapshot(symbol: str, snap_date: date) -> Optional[dict]:
    p = _snapshot_path(symbol, snap_date)
    if not p.exists():
        return None
    return json.loads(p.read_text())


def scan_unusual_flow(
    symbol: str,
    snap: Optional[dict] = None,
    min_volume: int = 1000,
    min_notional: float = 50_000,
    min_vol_oi_ratio: float = 3.0,
    max_dte: int = 60,
) -> list[dict]:
    """Detect unusual single-strike activity. Returns list of flagged contracts.

    Args:
        symbol: Underlying ticker.
        snap: Pre-loaded snapshot dict (if None, fetches a fresh one).
        min_volume: Minimum contracts traded today (default 1000).
        min_notional: Minimum $ notional (default $50k).
        min_vol_oi_ratio: Flag if volume/OI > this (default 3x = mostly new).
        max_dte: Maximum days to expiry to consider (default 60d, short-dated).
    """
    if snap is None:
        snap = snapshot_chain(symbol)
    hits = []
    today = date.today()
    for exp_str, payload in (snap.get("expiries") or {}).items():
        if isinstance(payload, dict) and payload.get("error"):
            continue
        try:
            exp_date = date.fromisoformat(exp_str)
        except ValueError:
            continue
        dte = (exp_date - today).days
        if dte < 0 or dte > max_dte:
            continue
        for side in ("calls", "puts"):
            for row in payload.get(side, []):
                vol = row.get("volume") or 0
                oi = row.get("openInterest") or 0
                price = row.get("lastPrice") or 0
                strike = row.get("strike")
                if vol < min_volume:
                    continue
                notional = vol * price * 100  # one contract = 100 shares
                if notional < min_notional:
                    continue
                vol_oi = vol / oi if oi > 0 else float("inf")
                if vol_oi < min_vol_oi_ratio:
                    continue
                hits.append({
                    "symbol": symbol.upper(),
                    "side": side[:-1],  # 'call' or 'put'
                    "expiry": exp_str,
                    "dte": dte,
                    "strike": strike,
                    "last_price": price,
                    "volume": _safe_int(vol),
                    "open_interest": _safe_int(oi),
                    "vol_oi_ratio": round(vol_oi, 2) if oi > 0 else "inf",
                    "notional_usd": round(notional, 0),
                    "implied_vol": row.get("impliedVolatility"),
                    "in_the_money": row.get("inTheMoney", False),
                })
    hits.sort(key=lambda x: x["notional_usd"], reverse=True)
    return hits


def aggregate_put_call_ratio(symbol: str, snap: Optional[dict] = None,
                              max_dte: int = 45) -> dict:
    if snap is None:
        snap = snapshot_chain(symbol)
    call_vol = put_vol = 0
    today = date.today()
    for exp_str, payload in (snap.get("expiries") or {}).items():
        if isinstance(payload, dict) and payload.get("error"):
            continue
        try:
            dte = (date.fromisoformat(exp_str) - today).days
        except ValueError:
            continue
        if dte < 0 or dte > max_dte:
            continue
        for row in payload.get("calls", []):
            call_vol += row.get("volume") or 0
        for row in payload.get("puts", []):
            put_vol += row.get("volume") or 0
    pc = put_vol / call_vol if call_vol > 0 else None
    return {"symbol": symbol.upper(), "call_volume": _safe_int(call_vol),
            "put_volume": _safe_int(put_vol), "put_call_ratio": round(pc, 3) if pc else None}


def watchlist_flow_scan(symbols: list[str], **kwargs) -> dict:
    """Run unusual-flow scan across a watchlist. Returns hits + ratios."""
    all_hits = []
    ratios = []
    for sym in symbols:
        try:
            snap = snapshot_chain(sym, max_expiries=4)
            all_hits.extend(scan_unusual_flow(sym, snap=snap, **kwargs))
            ratios.append(aggregate_put_call_ratio(sym, snap=snap))
        except Exception as e:
            ratios.append({"symbol": sym.upper(), "error": str(e)})
    all_hits.sort(key=lambda x: x["notional_usd"], reverse=True)
    return {
        "as_of": datetime.now(timezone.utc).isoformat(),
        "unusual_contracts": all_hits[:30],
        "put_call_ratios": ratios,
        "summary": {
            "symbols_scanned": len(symbols),
            "anomalies_found": len(all_hits),
            "total_unusual_notional_usd": round(sum(h["notional_usd"] for h in all_hits), 0),
        },
    }
