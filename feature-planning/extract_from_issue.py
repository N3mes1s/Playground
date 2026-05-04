"""GitHub Issue → feature intent.md extractor.

Lowers the bar for using cli_feature: a PM doesn't need to write a
structured intent.md; they paste a GitHub issue URL and an LLM
extracts the structured fields.

The extractor:
  1. Fetches issue title + body + labels (or loads a fixture file).
  2. Asks an LLM to fill in {what, why, scope_in, scope_out, existing,
     constraints[], success[]} from whatever's in the issue body.
  3. Renders to feature-planning's intent.md template.

Fields the LLM can't determine from the issue text are left as
explicit "_(not specified in issue; please clarify)_" markers
rather than hallucinated. The PM still gets a useful skeleton.

Usage:
    python feature-planning/extract_from_issue.py \
        --url https://github.com/owner/repo/issues/123 \
        --out feature-planning/intents/extracted.md

    python feature-planning/extract_from_issue.py \
        --from-file fixtures/issue.json \
        --out feature-planning/intents/extracted.md
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mirofish_lab.config import load_config, make_openai_client
from mirofish_lab.github import (
    Issue,
    fetch_issue,
    load_issue_from_file,
)


EXTRACTOR_SYSTEM_PROMPT = (
    "You convert a GitHub issue into a structured feature intent that a "
    "feature-planning pipeline can consume. You output ONLY JSON.\n\n"
    "Rules:\n"
    "- Extract what the issue actually says. Do NOT invent constraints.\n"
    "- For fields the issue doesn't specify, return the literal string "
    '"_(not specified in issue; please clarify)_". Do NOT guess.\n'
    "- 'what' should be a single paragraph stating the proposed feature.\n"
    "- 'why' should capture the customer outcome / business reason.\n"
    "- 'scope_in' is a comma-separated list of explicit in-scope items.\n"
    "- 'scope_out' is the same for explicit OUT-of-scope items.\n"
    "- 'existing_constraints' captures technical-debt or system-state "
    "facts the issue mentions (auth model, infra, deps).\n"
    "- 'constraints' is a list of declarative constraints the feature "
    "must satisfy (compliance, deadlines, performance, accessibility, etc).\n"
    "- 'success' is a list of measurable outcome statements.\n\n"
    "Output JSON object only (wrap in ```json fence):\n"
    "{\n"
    '  "title": "<= 80 chars, the feature title",\n'
    '  "what": "<single paragraph>",\n'
    '  "why":  "<single paragraph>",\n'
    '  "scope_in":  "<comma-separated items>",\n'
    '  "scope_out": "<comma-separated items>",\n'
    '  "existing_constraints": "<short text>",\n'
    '  "constraints": ["<constraint 1>", ...],\n'
    '  "success":     ["<success criterion 1>", ...],\n'
    '  "extraction_confidence": "high"|"medium"|"low",\n'
    '  "needs_clarification": ["<list of fields the issue did NOT specify>"]\n'
    "}\n"
)


INTENT_MD_TEMPLATE = """# {title}

## What

{what}

## Why

{why}

## Scope

- **In scope:** {scope_in}
- **Out of scope:** {scope_out}
- **Existing constraints:** {existing}

## Constraints

{constraints}

## What success looks like

{success}

---

_Extracted from GitHub issue {issue_url} (extraction confidence: {confidence})._
{clarifications}
"""


_FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)```")


def _extract_json(text: str) -> dict | None:
    m = _FENCE_RE.search(text or "")
    body = m.group(1) if m else (text or "")
    try:
        return json.loads(body)
    except Exception:
        return None


def extract(issue: Issue, *, cfg=None) -> dict:
    """Run the LLM extractor and return the parsed JSON."""
    if cfg is None:
        cfg = load_config()
    client = make_openai_client(cfg)

    user_msg = (
        f"# GitHub issue\n\n"
        f"URL: {issue.url}\n"
        f"Title: {issue.title}\n"
        f"Labels: {', '.join(issue.labels) if issue.labels else '(none)'}\n\n"
        f"## Body\n\n{issue.body[:8000]}\n\n"
        f"Produce the JSON extraction per your schema."
    )

    resp = client.chat.completions.create(
        model=cfg.model,
        messages=[
            {"role": "system", "content": EXTRACTOR_SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        max_completion_tokens=1200,
    )
    text = resp.choices[0].message.content or ""
    parsed = _extract_json(text) or {}

    # Apply default 'unspecified' marker for missing fields.
    UNSPEC = "_(not specified in issue; please clarify)_"
    return {
        "title": parsed.get("title") or issue.title or UNSPEC,
        "what": parsed.get("what") or UNSPEC,
        "why":  parsed.get("why")  or UNSPEC,
        "scope_in":  parsed.get("scope_in")  or UNSPEC,
        "scope_out": parsed.get("scope_out") or UNSPEC,
        "existing_constraints": parsed.get("existing_constraints") or UNSPEC,
        "constraints": parsed.get("constraints") or [],
        "success":     parsed.get("success")     or [],
        "extraction_confidence": parsed.get("extraction_confidence", "low"),
        "needs_clarification": parsed.get("needs_clarification") or [],
    }


def render_intent(extracted: dict, *, issue_url: str = "") -> str:
    constraints_block = "\n".join(f"- {c}" for c in extracted["constraints"]) \
        or "_(none extracted)_"
    success_block = "\n".join(f"- {s}" for s in extracted["success"]) \
        or "_(none extracted)_"

    clarifications_md = ""
    if extracted["needs_clarification"]:
        clarifications_md = (
            "\n_Fields needing clarification: "
            + ", ".join(extracted["needs_clarification"])
            + "._"
        )

    return INTENT_MD_TEMPLATE.format(
        title=extracted["title"],
        what=extracted["what"],
        why=extracted["why"],
        scope_in=extracted["scope_in"],
        scope_out=extracted["scope_out"],
        existing=extracted["existing_constraints"],
        constraints=constraints_block,
        success=success_block,
        issue_url=issue_url,
        confidence=extracted["extraction_confidence"],
        clarifications=clarifications_md,
    )


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="Extract a feature intent.md from a GitHub issue"
    )
    grp = p.add_mutually_exclusive_group(required=True)
    grp.add_argument("--url", help="GitHub issue URL")
    grp.add_argument("--from-file", type=Path,
                     help="Pre-fetched issue JSON (offline mode)")
    p.add_argument("--out", type=Path,
                   default=ROOT / "feature-planning" / "intents" / "extracted.md")
    args = p.parse_args(argv)

    if args.url:
        issue = fetch_issue(args.url)
    else:
        issue = load_issue_from_file(args.from_file)

    extracted = extract(issue)
    intent = render_intent(extracted, issue_url=issue.url)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(intent)

    sidecar = args.out.with_suffix(".extraction.json")
    sidecar.write_text(json.dumps({
        "source_issue": {
            "url": issue.url, "title": issue.title,
            "labels": issue.labels,
        },
        "extracted": extracted,
    }, indent=2))

    print(f"[done] wrote {args.out}")
    print(f"  extraction confidence: {extracted['extraction_confidence']}")
    if extracted["needs_clarification"]:
        print(f"  needs clarification: {extracted['needs_clarification']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
