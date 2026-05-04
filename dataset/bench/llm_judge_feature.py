"""LLM-as-judge scorer for feature-planning bench runs.

Mirror of dataset/bench/llm_judge.py, scoped to feature-planning ground
truth signals (which differ from rollout ground truth):

  - expected_blocking_stakeholders: which personas MUST flag blocking
    constraints. Caught iff ALL appear with at least one blocking
    constraint each.
  - expected_axes: which constraint axes should be present.
  - expected_launch_strategy: feature_flag / gradual_rollout /
    beta_program / full_release. Reasonable substitutes count
    (beta_program ~ gradual_rollout for risky features).
  - min_estimated_days / max_estimated_days: total days should land
    inside this band. Order-of-magnitude check, not strict.
  - regulated: if True, the plan MUST include a security/compliance
    review step.

Verdict scale (same as rollout judge):
  - caught:  all expected stakeholders + axes covered, launch strategy
             matches, total days in band, security step present (if
             regulated).
  - partial: some signals captured, others materially missing.
  - missed:  unrelated, generic, or contradicts the ground truth.
  - no_ground_truth: ground_truth absent.
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
    "You are a strict but fair judge evaluating a feature-planning "
    "pipeline output against synthetic ground truth. You output ONLY JSON.\n\n"
    "Verdict scale:\n"
    "  - caught: ALL expected blocking stakeholders flagged blocking "
    "constraints, ALL expected axes appear, launch strategy matches "
    "(or is a reasonable substitute), total days are within the GT band, "
    "and (if regulated) a security/compliance review step is present.\n"
    "  - partial: SOME signals captured but material parts missing.\n"
    "  - missed: plan unrelated to the feature or actively wrong.\n"
    "  - no_ground_truth: ground_truth absent.\n\n"
    "Output JSON only (wrap in ```json fence):\n"
    "{\n"
    '  "verdict": "caught"|"partial"|"missed"|"no_ground_truth",\n'
    '  "rationale": "<= 200 chars; SINGLE strongest reason",\n'
    '  "captured":           ["specific GT signals reflected in the plan"],\n'
    '  "missed":             ["specific GT signals the plan misses"],\n'
    '  "stakeholders_hit":   <int 0..N>,\n'
    '  "stakeholders_total": <int N>,\n'
    '  "axes_hit":           <int 0..N>,\n'
    '  "axes_total":         <int N>,\n'
    '  "days_in_band":       true|false,\n'
    '  "launch_strategy_ok": true|false,\n'
    '  "security_step_present": true|false,\n'
    '  "judge_confidence":   "high"|"medium"|"low"\n'
    "}\n\n"
    "Be specific. Synonyms count: 'gradual ramp behind a flag' captures\n"
    "`gradual_rollout`. Don't inflate to 'caught' to be charitable."
)


def _summarise_pipeline_output(sidecar: dict, max_chars: int = 4500) -> str:
    """Compact view of feature-planning sidecar for the judge."""
    if not sidecar:
        return "(empty)"
    constraints = sidecar.get("constraints") or []
    plans = sidecar.get("plans") or {}
    winner = sidecar.get("winner")

    lines = []
    if winner:
        lines.append(f"Recommended plan: {winner}")
    if winner and winner in plans:
        plan = plans[winner]
        if isinstance(plan, dict):
            lines.append(f"Summary: {plan.get('summary', '')[:300]}")
            for s in (plan.get("steps") or [])[:12]:
                if isinstance(s, dict):
                    lines.append(
                        f"  {s.get('id','?')} [{s.get('owner','?')}] "
                        f"({s.get('launch_strategy','?')}, "
                        f"{s.get('estimated_days','?')}d): "
                        f"{s.get('action','')[:120]}"
                    )
    if constraints:
        # Owner -> blocking-or-not summary
        from collections import Counter
        owner_blocking: Counter = Counter()
        owner_total: Counter = Counter()
        for c in constraints:
            if not isinstance(c, dict):
                continue
            owner_total[c.get("owner", "?")] += 1
            if c.get("blocking"):
                owner_blocking[c.get("owner", "?")] += 1
        lines.append("Constraint distribution (blocking / total):")
        for o, total in owner_total.items():
            lines.append(f"  {o}: {owner_blocking.get(o, 0)}/{total}")
        # axes
        axes = Counter(c.get("axis", "?") for c in constraints if isinstance(c, dict))
        lines.append(f"Axes seen: {dict(axes)}")
    return "\n".join(lines)[:max_chars]


def _summarise_ground_truth(elem: dict) -> str:
    gt = elem.get("ground_truth") or {}
    parts = [
        f"GT kind: {gt.get('kind', '?')}",
        f"Feature slug: {gt.get('feature_slug', '?')}",
        f"Expected blocking stakeholders: {gt.get('expected_blocking_stakeholders', [])}",
        f"Expected axes: {gt.get('expected_axes', [])}",
        f"Expected launch strategy: {gt.get('expected_launch_strategy', '?')}",
        f"Estimated-days band: [{gt.get('min_estimated_days', '?')}, "
        f"{gt.get('max_estimated_days', '?')}]",
        f"Regulated: {gt.get('regulated', False)} "
        f"(if True, plan MUST have a security / compliance review step)",
    ]
    return "\n".join(parts)


_FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)```")


def _extract_json(text: str) -> dict | None:
    m = _FENCE_RE.search(text or "")
    body = m.group(1) if m else (text or "")
    try:
        return json.loads(body)
    except Exception:
        return None


def judge_feature_element(elem: dict, sidecar: dict, *, cfg=None) -> dict:
    """Run a feature-planning LLM judge on (element, pipeline output)."""
    if cfg is None:
        cfg = load_config()
    client = make_openai_client(cfg)

    intent_excerpt = (elem.get("intent_md") or "")[:2500]
    gt_summary = _summarise_ground_truth(elem)
    pipeline_summary = _summarise_pipeline_output(sidecar)

    user_msg = (
        f"# Element\n\n"
        f"id: `{elem.get('id')}`\nsource: `{elem.get('source')}`\n\n"
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
            max_completion_tokens=700,
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
        "stakeholders_hit": int(parsed.get("stakeholders_hit", 0) or 0),
        "stakeholders_total": int(parsed.get("stakeholders_total", 0) or 0),
        "axes_hit": int(parsed.get("axes_hit", 0) or 0),
        "axes_total": int(parsed.get("axes_total", 0) or 0),
        "days_in_band": bool(parsed.get("days_in_band", False)),
        "launch_strategy_ok": bool(parsed.get("launch_strategy_ok", False)),
        "security_step_present": bool(parsed.get("security_step_present", False)),
        "judge_confidence": parsed.get("judge_confidence", "low"),
    }
