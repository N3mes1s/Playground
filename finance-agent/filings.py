"""SEC EDGAR filings loader — long-context 10-K / 10-Q analysis.

By 2026, Claude's 1M-token context window is large enough to ingest an
entire 10-K (typical 100-300K tokens) and answer specific questions
about it. The cached-prefix pattern means the same filing only pays the
ingestion cost once per ~5 minutes of TTL.

Public EDGAR endpoints (no auth, no key needed):
  https://data.sec.gov/submissions/CIK0000000000.json     (company filings index)
  https://www.sec.gov/cgi-bin/browse-edgar?...            (search)
  https://www.sec.gov/Archives/edgar/data/<cik>/<acc>/    (raw documents)

EDGAR requires a User-Agent header with contact info — we use a generic
"Levee Research contact@levee.app" header.
"""
import json
import re
from pathlib import Path
from typing import Optional

import requests

import config

UA = {"User-Agent": "Levee Research contact@levee.app", "Accept": "application/json"}
TIMEOUT = 60

# Hardcoded CIK lookup for common tickers (saves a roundtrip)
TICKER_CIKS = {
    "AAPL": "0000320193", "MSFT": "0000789019", "NVDA": "0001045810",
    "GOOGL": "0001652044", "META": "0001326801", "AMZN": "0001018724",
    "TSLA": "0001318605", "AMD": "0000002488", "NFLX": "0001065280",
    "AVGO": "0001730168", "ORCL": "0001341439", "CRM": "0001108524",
    "PLTR": "0001321655", "UBER": "0001543151", "COIN": "0001679788",
    "MSTR": "0001050446", "ARM": "0001973239", "SPY": None,  # ETF
    "QQQ": None,  # ETF
}

CACHE_DIR = config.DATA_DIR / "filings_cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)


def _cik(symbol: str) -> Optional[str]:
    sym = symbol.upper()
    if sym in TICKER_CIKS:
        return TICKER_CIKS[sym]
    # Fallback: query EDGAR ticker mapping
    try:
        r = requests.get("https://www.sec.gov/files/company_tickers.json",
                         headers=UA, timeout=TIMEOUT)
        data = r.json()
        for entry in data.values():
            if entry.get("ticker", "").upper() == sym:
                cik = str(entry.get("cik_str", "")).zfill(10)
                TICKER_CIKS[sym] = cik
                return cik
    except Exception:
        return None
    return None


def list_filings(symbol: str, form_type: str = "10-K", limit: int = 5) -> list[dict]:
    """List recent filings of a given type for a ticker."""
    cik = _cik(symbol)
    if not cik:
        return [{"error": f"no CIK for {symbol} (likely ETF or unknown ticker)"}]
    url = f"https://data.sec.gov/submissions/CIK{cik}.json"
    try:
        r = requests.get(url, headers=UA, timeout=TIMEOUT)
        r.raise_for_status()
        d = r.json()
    except Exception as e:
        return [{"error": str(e)}]

    recent = d.get("filings", {}).get("recent", {})
    forms = recent.get("form", [])
    dates = recent.get("filingDate", [])
    accs = recent.get("accessionNumber", [])
    primary_docs = recent.get("primaryDocument", [])

    hits = []
    for i, form in enumerate(forms):
        if form != form_type:
            continue
        hits.append({
            "form": form,
            "filing_date": dates[i],
            "accession": accs[i],
            "primary_doc": primary_docs[i],
            "url": f"https://www.sec.gov/Archives/edgar/data/{int(cik)}/{accs[i].replace('-', '')}/{primary_docs[i]}",
        })
        if len(hits) >= limit:
            break
    return hits


def fetch_filing(symbol: str, form_type: str = "10-K") -> dict:
    """Fetch the most recent filing of a given type. Caches by accession."""
    filings = list_filings(symbol, form_type=form_type, limit=1)
    if not filings or "error" in filings[0]:
        return {"error": filings[0].get("error", "no filings found") if filings else "no filings"}
    f = filings[0]
    cache_path = CACHE_DIR / f"{symbol.upper()}_{form_type}_{f['accession'].replace('-', '')}.txt"
    if cache_path.exists():
        return {**f, "text": cache_path.read_text(), "cached": True}

    try:
        r = requests.get(f["url"], headers={**UA, "Accept": "text/html"}, timeout=TIMEOUT)
        r.raise_for_status()
        html = r.text
    except Exception as e:
        return {**f, "error": f"fetch failed: {e}"}

    # Strip HTML tags crudely — preserves text content. For 10-Ks this is
    # noisy but cheap; the alternative (selectolax/BeautifulSoup) adds deps.
    text = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&nbsp;", " ", text)
    text = re.sub(r"&amp;", "&", text)
    text = re.sub(r"&lt;", "<", text)
    text = re.sub(r"&gt;", ">", text)
    text = re.sub(r"\s+", " ", text)
    text = text.strip()
    cache_path.write_text(text)
    return {**f, "text": text, "cached": False}


def analyze_filing(symbol: str, form_type: str, question: str, max_chars: int = 600_000) -> dict:
    """Load a filing into Claude's cached context and answer a question.

    `max_chars` ~150K tokens at 4 chars/tok. Adjust per Opus 4.7's 1M context.
    """
    import anthropic
    filing = fetch_filing(symbol, form_type=form_type)
    if "error" in filing:
        return filing
    text = filing.get("text", "")[:max_chars]
    if not text:
        return {"error": "empty filing text"}

    client = anthropic.Anthropic(**config.resolve_anthropic_credentials())
    resp = client.messages.create(
        model=config.MODEL,
        max_tokens=4000,
        system=[
            {"type": "text",
             "text": f"You are a financial analyst reading the most recent {form_type} for {symbol.upper()}. "
                     f"Filed {filing.get('filing_date')}. Answer the operator's question precisely with "
                     f"section citations where possible."},
            {"type": "text",
             "text": f"=== {symbol.upper()} {form_type} ({filing.get('filing_date')}) ===\n\n{text}",
             "cache_control": {"type": "ephemeral"}},
        ],
        thinking={"type": "adaptive"},
        messages=[{"role": "user", "content": question}],
    )
    answer = ""
    for block in resp.content:
        if block.type == "text":
            answer = block.text
    return {
        "symbol": symbol.upper(),
        "form": form_type,
        "filing_date": filing.get("filing_date"),
        "filing_url": filing.get("url"),
        "filing_chars": len(text),
        "answer": answer,
        "usage": {
            "input_tokens": resp.usage.input_tokens,
            "cache_creation_input_tokens": getattr(resp.usage, "cache_creation_input_tokens", 0),
            "cache_read_input_tokens": getattr(resp.usage, "cache_read_input_tokens", 0),
            "output_tokens": resp.usage.output_tokens,
        },
    }
