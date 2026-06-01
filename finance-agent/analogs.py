"""Historical analog retrieval — "this setup looks like X from 2018."

Inspired by the case-based reasoning literature and modern RAG patterns:
when the agent faces a decision, retrieve the K most similar past setups
from its journal + a curated historical-analog database, condition the
current decision on what happened in those analogs.

Implementation (v1):
1. Embed the current tick's context (regime + macro + ticker) into a short
   semantic query.
2. Query the journal (own history) for similar prior setups via keyword
   search (cheap first pass).
3. For market-level analogs (e.g., "this looks like Oct 2018"), use
   parallel.ai's Search API with a date-anchored objective.

This is the missing inductive step in the current agent: it learns from
its own recent trades (playbook) but doesn't actively retrieve historical
market analogs. A 2026 trader's edge often comes from "what happened the
last time the Fed paused mid-hike cycle."
"""
import json

import journal
import research


def journal_analogs(query_keywords: list[str], n: int = 5) -> list[dict]:
    """Search the agent's own journal for prior entries matching keywords."""
    if not journal.config.JOURNAL_PATH.exists():
        return []
    entries = []
    with journal.config.JOURNAL_PATH.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            text = json.dumps(e).lower()
            if any(kw.lower() in text for kw in query_keywords):
                entries.append(e)
    return entries[-n:]


def market_analogs(setup_description: str, max_results: int = 5) -> dict:
    """Use parallel.ai to find historical market analogs to the current setup.

    E.g.: "Fed paused mid-hike cycle with CPI still 3%+ — what happened to
    SPY in the following 90 days, historically?"
    """
    objective = (
        f"Historical market analogs to this setup, with cited dates and "
        f"outcomes: {setup_description}. List 3-5 prior episodes, the "
        f"specific dates, and what happened to US equity indexes in the "
        f"following 30-90 days. Focus on patterns that repeated."
    )
    return research.search(objective, max_results=max_results)
