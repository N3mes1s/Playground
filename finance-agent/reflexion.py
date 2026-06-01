"""Reflexion-style per-trade self-critique.

Shinn et al. 2023 (arXiv:2303.11366) showed that an LLM agent improves
substantially when it generates verbal reflections on prior failures and
keeps them in working memory. Our current weekly-close playbook rewrite is
this idea at weekly cadence. Reflexion proper runs much tighter: after
every outcome, the agent reflects on what went wrong, distills a verbal
lesson, and adds it to a reflection store the next decision retrieves from.

We do this per-fill: when a position closes (either by exit or by hitting
a stop), the agent emits a Reflexion entry. The next tick reads the most
recent reflections as part of context. This is the missing tight feedback
loop between the journal (passive log) and the playbook (weekly rewrite).
"""
import json
from datetime import datetime, timezone

import anthropic

import config
import playbook


REFLECT_SYSTEM = """You are a Reflexion module for a trading agent.

You'll be shown one completed trade — the entry rationale, fill prices,
exit reason, P&L, and the relevant market context. Output a terse verbal
reflection (≤ 150 words) that the agent's next-tick decision should read.

Format your reflection as:

OUTCOME: [win | loss | scratch] of $X.XX (+/-X.XX%)
ROOT CAUSE: (one sentence — what specifically caused the outcome)
LESSON: (one sentence — what would change next time)
GENERALIZES TO: (one short phrase — the setup class this lesson applies to)

Do not editorialize. Do not propose new strategies. The playbook is
already being rewritten weekly. Your job is the tight feedback loop:
specific trade → specific lesson, archived.
"""


def reflect_on_trade(trade_record: dict) -> str:
    """Generate a Reflexion entry for one completed trade."""
    client = anthropic.Anthropic(**config.resolve_anthropic_credentials())
    user_prompt = f"COMPLETED TRADE:\n{json.dumps(trade_record, indent=2, default=str)}\n\nWrite the reflection."
    resp = client.messages.create(
        model=config.MODEL,
        max_tokens=600,
        system=REFLECT_SYSTEM,
        thinking={"type": "adaptive"},
        messages=[{"role": "user", "content": user_prompt}],
    )
    for block in resp.content:
        if block.type == "text":
            return block.text
    return ""


REFLECTIONS_PATH = config.DATA_DIR / "reflections.jsonl"


def append(reflection_text: str, trade_id: str = "") -> None:
    entry = {
        "t": datetime.now(timezone.utc).isoformat(),
        "trade_id": trade_id,
        "reflection": reflection_text,
    }
    with REFLECTIONS_PATH.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def recent(n: int = 10) -> list[dict]:
    if not REFLECTIONS_PATH.exists():
        return []
    lines = [json.loads(l) for l in REFLECTIONS_PATH.read_text().splitlines() if l.strip()]
    return lines[-n:]
