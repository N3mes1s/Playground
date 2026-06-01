"""Prediction-market priors via Kalshi public REST API.

Markets like Fed rate decisions, CPI prints, jobs reports, elections, and
policy actions trade as binary contracts with real money at stake. The
implied probability (yes price in $) is the market's calibrated forecast.

This is a 2026-distinct addition: prior to ~2024 these markets were thin
and noisy; by 2026 the policy-event contracts have enough volume to be
useful priors for catalyst probability.

Docs: https://docs.kalshi.com/api-reference/market/get-markets
Auth: none required for read-only.
"""
import requests

BASE = "https://external-api.kalshi.com/trade-api/v2"
TIMEOUT = 30

ECONOMIC_SERIES = {
    "fed_rates": ["KXFEDHIKE", "KXRATEHIKE", "KXEMERCUTS", "KXLOWESTRATE", "KXFEDNOM"],
    "cpi": ["KXCPI", "CPICOREYOY", "CPIFOOD", "KXLCPIMAXYOY", "KXAIRFARECPI"],
    "rates": ["TBILL", "KXFRMMAX"],
    "tariffs": ["KXGLOBALTARIFFS", "KXUNDOTARIFFCOUNT", "KXTARIFFEUAUTO", "KXBRAZILTARIFFSIZE"],
    "trump_policy": ["KXTRUMPTOPIC", "KXTRUMPNEC", "KXEXEC", "KXTRUMPTIME"],
    "macro": ["NGDP"],
}


def get_markets(status: str = "open", series_ticker: str | None = None,
                limit: int = 100) -> list[dict]:
    params = {"status": status, "limit": limit}
    if series_ticker:
        params["series_ticker"] = series_ticker
    r = requests.get(f"{BASE}/markets", params=params,
                     headers={"Accept": "application/json"}, timeout=TIMEOUT)
    if not r.ok:
        return []
    return r.json().get("markets", [])


def _prob(m: dict, side: str = "yes") -> float | None:
    bid = m.get(f"{side}_bid_dollars")
    ask = m.get(f"{side}_ask_dollars")
    try:
        if bid is None and ask is None:
            return None
        if bid is None:
            return float(ask)
            if ask is None:
                return float(bid)
        return (float(bid) + float(ask)) / 2
    except (TypeError, ValueError):
        return None


def get_economic_priors(category: str = "all", min_volume: float = 0.0) -> list[dict]:
    """Return current implied probabilities for active economic markets.

    Args:
        category: one of fed_rates|cpi|rates|tariffs|trump_policy|macro|all
        min_volume: filter out illiquid markets (24h volume floor in contracts).
            Default 0 so we include markets with stale 24h vol but live quotes.
    """
    out = []
    cats = [category] if category in ECONOMIC_SERIES else list(ECONOMIC_SERIES.keys())
    seen_tickers = set()
    for cat in cats:
        for series_tk in ECONOMIC_SERIES[cat]:
            markets = get_markets(status="open", series_ticker=series_tk, limit=50)
            for m in markets:
                tk = m.get("ticker")
                if not tk or tk in seen_tickers:
                    continue
                try:
                    if float(m.get("volume_24h_fp", "0")) < min_volume:
                        continue
                except (ValueError, TypeError):
                    pass
                seen_tickers.add(tk)
                out.append({
                    "category": cat,
                    "series": series_tk,
                    "ticker": tk,
                    "question": m.get("yes_sub_title", ""),
                    "implied_yes_prob": _prob(m, "yes"),
                    "implied_no_prob": _prob(m, "no"),
                    "last_price_dollars": m.get("last_price_dollars"),
                    "volume_24h": m.get("volume_24h_fp"),
                    "open_interest": m.get("open_interest_fp"),
                    "close_time": m.get("close_time"),
                })
    return out


def search_markets(keyword: str, limit: int = 20) -> list[dict]:
    """Crude keyword search across open markets by yes_sub_title."""
    markets = get_markets(status="open", limit=1000)
    kw = keyword.lower()
    out = []
    for m in markets:
        title = (m.get("yes_sub_title", "") or "").lower()
        ticker = (m.get("ticker", "") or "").lower()
        if kw in title or kw in ticker:
            try:
                vol = float(m.get("volume_24h_fp", "0"))
            except (ValueError, TypeError):
                vol = 0
            out.append({
                "ticker": m.get("ticker"),
                "question": m.get("yes_sub_title", ""),
                "implied_yes_prob": _prob(m, "yes"),
                "volume_24h": vol,
                "close_time": m.get("close_time"),
            })
    out.sort(key=lambda x: x["volume_24h"], reverse=True)
    return out[:limit]
