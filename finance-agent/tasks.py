"""Parallel.ai Task API client for synchronous deep research.

Unlike Search (one-shot) or Monitor (scheduled), the Task API runs multi-hop
research and returns a cited report. We use blocking retrieval — create then
GET the result endpoint which holds the connection until completion or 600s
timeout.

See: https://docs.parallel.ai/api-reference/tasks/
"""
import requests

import config

CREATE_URL = "https://api.parallel.ai/v1/tasks/runs"
RESULT_URL = "https://api.parallel.ai/v1/tasks/runs/{run_id}/result"
HEADERS = lambda: {"x-api-key": config.PARALLEL_API_KEY, "Content-Type": "application/json"}


def deep_research(question: str, processor: str = "base", timeout: int = 300) -> dict:
    """Run a deep research task and block until result.

    Args:
        question: Natural-language research objective.
        processor: lite | base | pro | ultra | ultra8x. base ~= 1-2 min.
        timeout: Seconds to block on the result endpoint (max 600).
    """
    if not config.PARALLEL_API_KEY:
        return {"error": "PARALLEL_API_KEY not set", "content": ""}
    create_resp = requests.post(
        CREATE_URL,
        json={"processor": processor, "input": question, "enable_events": False},
        headers=HEADERS(),
        timeout=60,
    )
    if not create_resp.ok:
        return {"error": f"create failed: {create_resp.status_code} {create_resp.text[:300]}", "content": ""}
    run = create_resp.json()
    run_id = run.get("run_id")
    if not run_id:
        return {"error": "no run_id returned", "content": "", "raw": run}

    result_resp = requests.get(
        RESULT_URL.format(run_id=run_id),
        headers=HEADERS(),
        params={"timeout": str(timeout)},
        timeout=timeout + 30,
    )
    if not result_resp.ok:
        return {"error": f"result failed: {result_resp.status_code} {result_resp.text[:300]}",
                "content": "", "run_id": run_id}
    data = result_resp.json()
    output = data.get("output") or {}
    return {
        "run_id": run_id,
        "status": data.get("run", {}).get("status"),
        "content": output.get("content"),
        "type": output.get("type"),
        "citations": output.get("basis") or [],
    }
