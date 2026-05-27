import json
import time
from datetime import date, timedelta
from pathlib import Path

import config
import research

CACHE_DIR = config.DATA_DIR / "news_cache"


def _date_key(d: date) -> str:
    return d.isoformat()


def _cache_path(d: date) -> Path:
    return CACHE_DIR / f"{_date_key(d)}.json"


def has_cache(d: date) -> bool:
    return _cache_path(d).exists()


def load_cache(d: date) -> dict | None:
    p = _cache_path(d)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:
        return None


def _queries_for(d: date, watchlist: list[str]) -> list[str]:
    ds = d.strftime("%B %d, %Y")
    watch_str = ", ".join(watchlist[:10])
    return [
        f"biggest US stock market news on {ds} S&P 500 indexes",
        f"Federal Reserve or Jerome Powell statements rates inflation on or around {ds}",
        f"Trump or White House statements affecting US stocks tariffs on or around {ds}",
        f"executive orders or SEC DOJ regulatory news affecting US equities on or around {ds}",
        f"specific stock-moving headlines on {ds} for {watch_str}",
    ]


def build_for_date(d: date, watchlist: list[str], force: bool = False,
                   max_results_per_query: int = 4) -> dict:
    if not force and has_cache(d):
        return load_cache(d)

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    out = {"date": _date_key(d), "queries": {}}
    for q in _queries_for(d, watchlist):
        try:
            r = research.search(q, max_results=max_results_per_query)
        except Exception as e:
            r = {"error": str(e), "results": []}
        out["queries"][q] = r

    _cache_path(d).write_text(json.dumps(out, indent=2, default=str))
    return out


def build_range(start: date, end: date, watchlist: list[str], force: bool = False) -> dict:
    days = []
    cur = start
    while cur <= end:
        if cur.weekday() < 5:  # weekdays only
            days.append(cur)
        cur += timedelta(days=1)

    print(f"[news_index] indexing {len(days)} weekdays {start} -> {end}")
    print(f"[news_index] cache dir: {CACHE_DIR}")

    stats = {"total": len(days), "fetched": 0, "cached": 0, "errors": 0}
    for i, d in enumerate(days, 1):
        if not force and has_cache(d):
            stats["cached"] += 1
            if i % 10 == 0 or i == len(days):
                print(f"[{i:>3}/{len(days)}] {d} cached (skip)")
            continue
        t0 = time.time()
        try:
            build_for_date(d, watchlist, force=force)
            stats["fetched"] += 1
            print(f"[{i:>3}/{len(days)}] {d} fetched in {time.time()-t0:.1f}s")
        except Exception as e:
            stats["errors"] += 1
            print(f"[{i:>3}/{len(days)}] {d} ERROR: {e}")
    return stats


def historical_news_for(d: date) -> dict:
    """Return the news cache for a date, or an explanatory error if not indexed."""
    data = load_cache(d)
    if data is None:
        return {
            "error": f"no news cache for {_date_key(d)}; run "
                     f"`python cli.py index-news --start {d.isoformat()} --end {d.isoformat()}` first"
        }
    return data
