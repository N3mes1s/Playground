"""LLM-as-judge scorer for the bench runner.

Replaces literal-token / file-overlap matching with a semantic
verdict produced by a separate LLM call per element. The judge
reads the intent, the ground truth, and a compact summary of the
pipeline's output and emits caught / partial / missed plus a
rationale and lists of which ground-truth signals were captured
or missed.

Why this matters: the literal scorer punishes the pipeline for
saying "BGP rollout in the spine layer" when the post-mortem tag
is `cloudflare`. The judge knows the synonym.

Cost: one extra LLM call per scored element (~$0.001 on
gpt-5.4-mini). For a 200-element bench that's ~$0.20.

Output schema:

  {
    "verdict": "caught" | "partial" | "missed" | "no_ground_truth",
    "rationale": "<= 200 chars",
    "captured": ["list of ground-truth signals the plan captured"],
    "missed": ["list of ground-truth signals the plan missed"],
    "judge_confidence": "high" | "medium" | "low"
  }
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from mirofish_lab.config import load_config, make_openai_client


JUDGE_SYSTEM_PROMPT = (
    "You are a strict but fair judge evaluating whether a generated "
    "rollout plan adequately captured the ground truth of a real or "
    "synthetic migration scenario. You output ONLY JSON.\n\n"
    "Verdict scale:\n"
    "  - caught: the plan demonstrably reflects the ground-truth\n"
    "    signals (right files, right root cause, right stakeholders).\n"
    "    Synonyms count: 'BGP rollout in the spine layer' captures\n"
    "    a Cloudflare-tagged outage even without the literal word\n"
    "    'cloudflare'.\n"
    "  - partial: the plan captures SOME signals but misses material\n"
    "    parts of the ground truth.\n"
    "  - missed: the plan is unrelated, generic, or actively wrong.\n"
    "  - no_ground_truth: the input has no usable ground truth.\n\n"
    "Output JSON object only (wrap in ```json fence):\n"
    "{\n"
    '  "verdict": "caught"|"partial"|"missed"|"no_ground_truth",\n'
    '  "rationale": "<= 200 chars; the SINGLE strongest reason",\n'
    '  "captured": ["specific GT signals reflected in the plan"],\n'
    '  "missed":   ["specific GT signals the plan does not reflect"],\n'
    '  "judge_confidence": "high"|"medium"|"low"\n'
    "}\n\n"
    "Rules:\n"
    "- Be specific. 'plan mentions database' is too vague; "
    "  'plan step S3 references the SQLite cache.db file' is good.\n"
    "- 'caught' requires concrete textual evidence; 'partial' if some\n"
    "  signals are clearly present but others materially missing.\n"
    "- Judge by semantic match, not literal token overlap.\n"
    "- Do NOT inflate to 'caught' to be charitable. The point is to\n"
    "  be honest about pipeline performance."
)


def _summarise_pipeline_output(sidecar: dict, max_chars: int = 4000) -> str:
    """Compact view of what the pipeline produced for the judge."""
    if not sidecar:
        return "(empty)"
    pareto = sidecar.get("pareto") or {}
    winner = pareto.get("winner") or sidecar.get("winner") or (
        sidecar.get("recommendation") or {}).get("winner")
    plans = sidecar.get("plans") or {}
    constraints = sidecar.get("constraints") or []

    lines = []
    if winner:
        lines.append(f"Recommended plan: {winner}")
    if winner and winner in plans:
        plan = plans[winner]
        if isinstance(plan, dict):
            lines.append(f"Summary: {plan.get('summary', '')[:300]}")
            for s in (plan.get("steps") or [])[:8]:
                if isinstance(s, dict):
                    lines.append(
                        f"  {s.get('id','?')}: {s.get('action','')[:120]}"
                    )
    if constraints:
        lines.append("Constraints (top 8):")
        for c in constraints[:8]:
            if isinstance(c, dict):
                lines.append(
                    f"  [{c.get('owner','?')}] {c.get('summary','')[:120]}"
                )
    out = "\n".join(lines)
    return out[:max_chars]


def _summarise_ground_truth(elem: dict) -> str:
    gt = elem.get("ground_truth") or {}
    md = elem.get("metadata") or {}
    parts = []
    if gt.get("kind"):
        parts.append(f"GT kind: {gt['kind']}")
    if gt.get("files_touched"):
        parts.append(f"Files touched in canonical patch: {gt['files_touched'][:8]}")
    if gt.get("root_cause_keywords"):
        parts.append(f"Root-cause / distinctive keywords: {gt['root_cause_keywords'][:15]}")
    if gt.get("outcome"):
        parts.append(f"Actual outcome: {gt['outcome']}")
    if gt.get("patch_uri"):
        parts.append(f"External pointer: {gt['patch_uri']}")
    if md.get("expected_stakeholders"):
        parts.append(f"Expected stakeholders: {md['expected_stakeholders']}")
    if md.get("tags"):
        parts.append(f"Tags: {md['tags']}")
    return "\n".join(parts) or "(no ground truth signals)"


_FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)```")


def _extract_json(text: str) -> dict | None:
    m = _FENCE_RE.search(text or "")
    body = m.group(1) if m else (text or "")
    try:
        return json.loads(body)
    except Exception:
        return None


def judge_element(elem: dict, sidecar: dict, *, cfg=None) -> dict:
    """Run an LLM judge on (element, pipeline output) → verdict dict."""
    if cfg is None:
        cfg = load_config()
    client = make_openai_client(cfg)

    intent_excerpt = (elem.get("intent_md") or "")[:2500]
    gt_summary = _summarise_ground_truth(elem)
    pipeline_summary = _summarise_pipeline_output(sidecar)

    user_msg = (
        f"# Element\n\n"
        f"id: `{elem.get('id')}`\n"
        f"source: `{elem.get('source')}`\n\n"
        f"## Intent (excerpt)\n\n{intent_excerpt}\n\n"
        f"## Ground truth\n\n{gt_summary}\n\n"
        f"## Pipeline output (summary)\n\n{pipeline_summary}\n\n"
        f"Produce the JSON verdict per your schema."
    )

    try:
        resp = client.chat.completions.create(
            model=cfg.model,
            messages=[
                {"role": "system", "content": JUDGE_SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ],
            max_completion_tokens=600,
        )
        text = resp.choices[0].message.content or ""
    except Exception as e:
        return {
            "verdict": "missed",
            "rationale": f"judge call failed: {e.__class__.__name__}",
            "captured": [],
            "missed": [],
            "judge_confidence": "low",
            "_error": str(e)[:200],
        }

    parsed = _extract_json(text) or {}
    verdict = parsed.get("verdict")
    if verdict not in ("caught", "partial", "missed", "no_ground_truth"):
        verdict = "missed"
    return {
        "verdict": verdict,
        "rationale": str(parsed.get("rationale", ""))[:200],
        "captured": parsed.get("captured") or [],
        "missed": parsed.get("missed") or [],
        "judge_confidence": parsed.get("judge_confidence", "low"),
    }


def main(argv: list[str] | None = None) -> int:
    """CLI: judge a single element + sidecar pair (for debugging)."""
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--element-jsonl-line", required=True,
                        help="A single JSON line representing the element")
    parser.add_argument("--sidecar-json", type=Path, required=True)
    args = parser.parse_args(argv)

    elem = json.loads(args.element_jsonl_line)
    sidecar = json.loads(args.sidecar_json.read_text())
    verdict = judge_element(elem, sidecar)
    print(json.dumps(verdict, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
