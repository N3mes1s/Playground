"""Run a single-prompt baseline against every committed intent fixture
and emit structured plans into baselines/ for comparison vs the
multi-agent rollout-rehearsal output."""

import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from openai import OpenAI

ROOT = Path(__file__).resolve().parent.parent
INTENTS = sorted(ROOT.glob("fixtures/intent_*.md"))
OUT_DIR = ROOT / "rollout-rehearsal" / "baselines"
OUT_DIR.mkdir(parents=True, exist_ok=True)


def baseline_prompt(intent: str) -> str:
    return f"""You are an experienced staff engineer producing a rollout
plan for a proposed code change. Read the intent and produce ONLY a
JSON object wrapped in a ```json fenced block. The JSON shape:

{{
  "summary": "<= 200 chars",
  "steps": [
    {{"id":"S1","action":"...","owner":"...","depends_on":[],
      "gate":"wait_for:... | monitor:... | approval:... | window:... | none",
      "rollback":"...","observability":"..."}}
  ],
  "open_questions":[],
  "conflicts":[{{"between":["A","B"],"issue":"..."}}]
}}

Be concrete and reference specific parts of the intent. 5-15 steps.
Multiple stakeholder perspectives where relevant (backend, data, sre,
security, product). Identify real conflicts and open questions.

# Intent

{intent}
"""


def run_one(intent_path: Path, client: OpenAI, model: str) -> tuple[str, dict]:
    intent = intent_path.read_text()
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": baseline_prompt(intent)}],
        max_completion_tokens=3500,
    )
    text = resp.choices[0].message.content or ""
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    body = fence.group(1) if fence else text
    try:
        plan = json.loads(body)
    except json.JSONDecodeError:
        plan = {"_raw": text, "_error": "json_decode_failed"}
    out = {
        "intent": str(intent_path.relative_to(ROOT)),
        "model": model,
        "tokens_in": resp.usage.prompt_tokens,
        "tokens_out": resp.usage.completion_tokens,
        "plan": plan,
    }
    out_path = OUT_DIR / f"{intent_path.stem}.baseline.json"
    out_path.write_text(json.dumps(out, indent=2))
    return intent_path.stem, out


def main() -> int:
    client = OpenAI()
    model = os.environ.get("MODEL", "gpt-5.4-mini")
    print(f"[baseline] {len(INTENTS)} intents, model={model}", file=sys.stderr)
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(run_one, p, client, model): p for p in INTENTS}
        for fut in as_completed(futures):
            stem, _ = fut.result()
            print(f"[baseline]   {stem} done", file=sys.stderr)
    print(f"[baseline] all written to {OUT_DIR}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
