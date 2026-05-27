import requests

import config

SEARCH_URL = "https://api.parallel.ai/v1beta/search"
TIMEOUT = 60


def search(objective: str, max_results: int = 8) -> dict:
    if not config.PARALLEL_API_KEY:
        return {
            "error": "PARALLEL_API_KEY not set",
            "results": [],
        }
    payload = {
        "objective": objective,
        "max_results": max_results,
        "mode": "fast",
    }
    headers = {
        "x-api-key": config.PARALLEL_API_KEY,
        "Content-Type": "application/json",
    }
    try:
        resp = requests.post(SEARCH_URL, json=payload, headers=headers, timeout=TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except requests.HTTPError as e:
        return {"error": f"HTTP {e.response.status_code}: {e.response.text[:300]}", "results": []}
    except requests.RequestException as e:
        return {"error": str(e), "results": []}

    results = data.get("results") or data.get("data") or []
    trimmed = []
    for r in results[:max_results]:
        excerpts = r.get("excerpts") or []
        if isinstance(excerpts, list):
            content = " … ".join(excerpts)
        else:
            content = str(excerpts)
        if not content:
            content = r.get("snippet") or r.get("excerpt") or r.get("content") or ""
        trimmed.append(
            {
                "title": r.get("title") or r.get("name"),
                "url": r.get("url") or r.get("link"),
                "content": content[:1500],
            }
        )
    return {"results": trimmed, "usage": data.get("usage")}
