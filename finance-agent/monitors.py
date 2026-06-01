"""Parallel.ai Monitor API client + agent-facing helpers.

A monitor is a scheduled NL query that fires events when material changes are
detected. Events can be delivered via webhook OR polled. We use polling.

See: https://docs.parallel.ai/api-reference/monitor/
"""
import json
import time
from pathlib import Path
from typing import Optional

import requests

import config

BASE = "https://api.parallel.ai/v1/monitors"
HEADERS = lambda: {"x-api-key": config.PARALLEL_API_KEY, "Content-Type": "application/json"}
TIMEOUT = 60

REGISTRY_PATH = config.DATA_DIR / "monitors_registry.json"
EVENT_CACHE_DIR = config.DATA_DIR / "monitor_events"


def _load_registry() -> dict:
    if not REGISTRY_PATH.exists():
        return {}
    return json.loads(REGISTRY_PATH.read_text())


def _save_registry(reg: dict) -> None:
    REGISTRY_PATH.write_text(json.dumps(reg, indent=2))


def create_monitor(
    name: str,
    query: str,
    frequency: str = "1d",
    processor: str = "lite",
    include_backfill: bool = True,
    exclude_domains: Optional[list[str]] = None,
    location: str = "us",
) -> dict:
    """Create an event-stream monitor. Frequency: 1h | 12h | 1d | 7d | 30d."""
    payload = {
        "type": "event_stream",
        "frequency": frequency,
        "processor": processor,
        "metadata": {"name": name, "source": "levee-agent"},
        "settings": {
            "query": query,
            "include_backfill": include_backfill,
            "advanced_settings": {
                "source_policy": {
                    "exclude_domains": exclude_domains or ["reddit.com", "x.com", "twitter.com"],
                },
                "location": location,
            },
        },
    }
    r = requests.post(BASE, json=payload, headers=HEADERS(), timeout=TIMEOUT)
    if not r.ok:
        raise RuntimeError(f"create_monitor failed: {r.status_code} {r.text[:300]}")
    data = r.json()
    reg = _load_registry()
    reg[name] = {"monitor_id": data.get("monitor_id") or data.get("id"), "query": query,
                 "frequency": frequency, "created_at": data.get("created_at")}
    _save_registry(reg)
    return data


def list_monitors_remote() -> list[dict]:
    r = requests.get(BASE, headers=HEADERS(), timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    return data.get("monitors") or data.get("data") or []


def list_events(monitor_id: str, limit: int = 20, cursor: Optional[str] = None,
                include_completions: bool = False) -> dict:
    params = {"limit": limit, "include_completions": str(include_completions).lower()}
    if cursor:
        params["cursor"] = cursor
    r = requests.get(f"{BASE}/{monitor_id}/events", headers=HEADERS(),
                     params=params, timeout=TIMEOUT)
    if not r.ok:
        raise RuntimeError(f"list_events failed: {r.status_code} {r.text[:300]}")
    return r.json()


def delete_monitor(monitor_id: str) -> int:
    r = requests.delete(f"{BASE}/{monitor_id}", headers=HEADERS(), timeout=TIMEOUT)
    return r.status_code


def poll_all_recent(max_events_per_monitor: int = 10) -> dict:
    """Poll every registered monitor for recent events. Returns {name: [events]}."""
    reg = _load_registry()
    out = {}
    for name, info in reg.items():
        mid = info["monitor_id"]
        try:
            data = list_events(mid, limit=max_events_per_monitor)
            out[name] = data.get("events", [])
        except Exception as e:
            out[name] = [{"error": str(e)}]
    return out


# Standard set of monitors for the agent
STANDARD_MONITORS = [
    {
        "name": "political_stock_commentary",
        "query": "Trump, White House officials, cabinet members, or other prominent US political figures naming specific US-listed stocks, tickers, or industries in statements, speeches, interviews, or social media posts. Focus on anything that could move a stock price.",
        "frequency": "1h",
    },
    {
        "name": "pentagon_dod_procurement",
        "query": "Pentagon, Department of Defense, US military, or related federal agency announcements about procurement contracts, industry stakes, technology investments, executive orders, or major defense industry developments. Include small-cap and mid-cap defense and dual-use technology companies (drones, autonomous systems, defense AI, satellites, hypersonics, semiconductors).",
        "frequency": "1h",
    },
    {
        "name": "fda_drug_approvals_warnings",
        "query": "FDA drug approval announcements, CRL letters, safety warnings, advisory committee outcomes, or label changes affecting specific US-listed pharmaceutical or biotech companies. Include orphan designations, breakthrough therapy designations, and PDUFA dates.",
        "frequency": "1h",
    },
    {
        "name": "sec_doj_regulatory_enforcement",
        "query": "SEC enforcement actions, DOJ antitrust filings, FTC investigations, or significant regulatory news affecting specific US publicly traded companies. Include consent decrees, M&A blocking actions, and major sector-wide regulatory developments.",
        "frequency": "12h",
    },
    {
        "name": "fed_powell_treasury_speak",
        "query": "Federal Reserve, Chair Powell, FOMC members, or Treasury Secretary statements, speeches, or testimony on interest rates, inflation, the dollar, or market conditions. Include surprise CPI/PCE/PPI prints and major economic data releases that move bond yields significantly.",
        "frequency": "1h",
    },
    {
        "name": "tariff_trade_announcements",
        "query": "US tariff announcements, trade deal developments, executive orders affecting trade, China or EU trade tensions, semiconductor export controls, or Supreme Court rulings on trade authority. Include impact assessments on specific sectors.",
        "frequency": "1h",
    },
    {
        "name": "ma_unusual_corporate_activity",
        "query": "M&A announcements (target companies and acquirers), going-private deals, hostile bids, activist investor stakes, unusual share buyback announcements, or major corporate restructurings in US-listed small, mid, and large-cap stocks.",
        "frequency": "1h",
    },
    {
        "name": "earnings_guidance_surprises",
        "query": "Major US-listed companies reporting earnings beats, misses, or material guidance revisions that move their stock 5% or more pre-market or after-hours. Include sector-wide read-throughs and analyst rating changes immediately following earnings.",
        "frequency": "1h",
    },
    {
        "name": "thematic_drones_defense_dual_use",
        "query": "Drone industry developments (commercial, military, counter-drone), autonomous systems, defense tech startups going public, Pentagon AI initiatives, or M&A in dual-use technology. Focus on small-cap and mid-cap publicly traded companies.",
        "frequency": "12h",
    },
    {
        "name": "thematic_nuclear_uranium_smr",
        "query": "Nuclear power policy, uranium production developments, small modular reactor (SMR) progress, DOE nuclear initiatives, or related energy policy affecting US-listed nuclear, uranium mining, and energy infrastructure stocks.",
        "frequency": "12h",
    },
]


def setup_standard_monitors(dry_run: bool = False) -> dict:
    """Create the standard set of monitors. Skips any already in the registry."""
    reg = _load_registry()
    out = {"created": [], "skipped": [], "errors": []}
    for spec in STANDARD_MONITORS:
        name = spec["name"]
        if name in reg:
            out["skipped"].append(name)
            continue
        if dry_run:
            out["created"].append(f"DRY: {name} ({spec['frequency']})")
            continue
        try:
            data = create_monitor(
                name=name,
                query=spec["query"],
                frequency=spec["frequency"],
                processor=spec.get("processor", "lite"),
                include_backfill=True,
            )
            out["created"].append(f"{name} → {data.get('monitor_id') or data.get('id')}")
        except Exception as e:
            out["errors"].append(f"{name}: {e}")
    return out
