"""Probe whether the always-2-or-3 conflicts in the multi-agent output is
real conflict detection or anchoring on the example count in the prompt.

Strategy: re-run the Sequencer step (only) with two prompt variants on
the same already-collected stakeholder constraints:
  A) original prompt (current cli.py)
  B) stripped: explicit "list 0..N conflicts, do NOT pick a target count"
Compare the conflict counts.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

from openai import OpenAI

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "rollout-rehearsal" / "reports"
PROBE_OUT = ROOT / "rollout-rehearsal" / "probes"
PROBE_OUT.mkdir(parents=True, exist_ok=True)


PROMPT_A = """You receive a merged list of constraints from multiple
stakeholder agents and produce a partial-order rollout plan. Your output
is a JSON object:

{{
  "summary": "<= 200 chars, what the rollout achieves",
  "steps": [
    {{"id":"S1","action":"...","owner":"...","depends_on":[],
      "gate":"wait_for:... | monitor:... | approval:... | window:... | none",
      "rollback":"...","observability":"..."}}
  ],
  "open_questions":[],
  "conflicts":[{{"between":["A","B"],"issue":"..."}}]
}}

Wrap in ```json fenced block. 5-15 steps. Honour every BLOCKING
constraint. Don't invent constraints not in the input.

# Migration intent
{intent}

# Stakeholder constraints
```json
{constraints}
```
"""

PROMPT_B = """You receive a merged list of constraints from multiple
stakeholder agents and produce a partial-order rollout plan. Your output
is a JSON object:

{{
  "summary": "<= 200 chars",
  "steps": [
    {{"id":"S1","action":"...","owner":"...","depends_on":[],
      "gate":"...","rollback":"...","observability":"..."}}
  ],
  "open_questions":[],
  "conflicts":[]
}}

CRITICAL CONFLICT INSTRUCTION:
- Look at every PAIR of stakeholder constraints in the input.
- A conflict exists when two BLOCKING constraints from different owners
  pull in opposite directions (e.g. owner A requires X before step Z and
  owner B requires Y after step Z, and X is incompatible with Y).
- List EVERY such conflict. There is NO target count. Some inputs have
  zero conflicts; some have many. Do not invent conflicts to fill space
  and do not omit real ones to be brief.
- For each conflict include "between" (the two owners) and "issue".

Wrap in ```json fenced block. 5-15 steps.

# Migration intent
{intent}

# Stakeholder constraints
```json
{constraints}
```
"""


def _extract_json(text: str):
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    body = fence.group(1) if fence else text
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return None


def probe(intent_path: Path, report_json: Path, client: OpenAI, model: str) -> dict:
    intent = intent_path.read_text()
    rj = json.loads(report_json.read_text())
    constraints = json.dumps(rj.get("constraints", []), indent=2)

    out = {"intent": intent_path.stem, "model": model}
    for label, prompt_template in [("A_original", PROMPT_A), ("B_strict", PROMPT_B)]:
        msg = prompt_template.format(intent=intent, constraints=constraints)
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": msg}],
            max_completion_tokens=3500,
        )
        text = resp.choices[0].message.content or ""
        plan = _extract_json(text) or {}
        n_steps = len(plan.get("steps") or [])
        n_conflicts = len(plan.get("conflicts") or [])
        out[label] = {
            "steps": n_steps,
            "conflicts": n_conflicts,
            "raw_conflicts": plan.get("conflicts", []),
        }
        print(f"  {intent_path.stem} {label}: steps={n_steps} conflicts={n_conflicts}",
              file=sys.stderr)
    return out


def main() -> None:
    client = OpenAI()
    model = os.environ.get("MODEL", "gpt-5.4-mini")

    targets = [
        ("intent_blastradius_javascript_support", "Larger change, many constraint axes"),
        ("intent_adversarial_findings_history", "Smaller, simpler change"),
        ("intent_sqlite_memory_migration", "Storage change with cross-cutting impact"),
    ]
    results = []
    for stem, _label in targets:
        intent_path = ROOT / "fixtures" / f"{stem}.md"
        report_path = REPORTS / f"{stem}.json"
        if not intent_path.exists() or not report_path.exists():
            print(f"[skip] {stem}", file=sys.stderr)
            continue
        out = probe(intent_path, report_path, client, model)
        out_path = PROBE_OUT / f"{stem}.probe.json"
        out_path.write_text(json.dumps(out, indent=2))
        results.append(out)

    print("\n=== conflict-count anchoring probe ===")
    print(f"{'INTENT':<48} {'A_orig (s/c)':>14} {'B_strict (s/c)':>16}")
    for r in results:
        a = r["A_original"]
        b = r["B_strict"]
        print(f"{r['intent']:<48} {a['steps']:>4}/{a['conflicts']:>3}        "
              f"{b['steps']:>4}/{b['conflicts']:>3}")


if __name__ == "__main__":
    main()
