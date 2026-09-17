"""Report writers for triage results (markdown + JSON)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from triage import TriageResult


def write_json(path: str | Path, results: list[TriageResult], args: Any) -> None:
    payload = {
        "tool": "jev-triage",
        "model": getattr(args, "model", "jev-latest"),
        "thresholds": {
            "is_real": getattr(args, "is_real_threshold", None),
            "reachable": getattr(args, "reachable_threshold", None),
        },
        "kept": [r.to_dict() for r in results if r.keep],
        "dropped": [r.to_dict() for r in results if not r.keep],
    }
    Path(path).write_text(json.dumps(payload, indent=2))


def write_markdown(path: str | Path, results: list[TriageResult], args: Any) -> None:
    kept = [r for r in results if r.keep]
    dropped = [r for r in results if not r.keep]

    lines: list[str] = []
    lines.append("# Jev Triage Report")
    lines.append("")
    lines.append(
        f"Triaged **{len(results)}** scanner finding(s): "
        f"**{len(kept)} kept**, **{len(dropped)} dropped** "
        f"(P(real) >= {getattr(args, 'is_real_threshold', '?')}, "
        f"P(reachable) >= {getattr(args, 'reachable_threshold', '?')})."
    )
    lines.append("")
    lines.append(
        "> Jev returns *calibrated* probabilities, not verdicts. Treat kept "
        "findings as prioritized leads for human review, not confirmed bugs."
    )
    lines.append("")

    lines.append("## Kept findings")
    lines.append("")
    if kept:
        lines.append("| ID | Severity | P(real) | P(reach) | Category | Title |")
        lines.append("|----|----------|--------:|---------:|----------|-------|")
        for r in kept:
            lines.append(
                f"| {r.finding.id} | {r.severity_label or '?'} | "
                f"{_p(r.is_real)} | {_p(r.reachable)} | "
                f"{r.category or '?'} | {_esc(r.finding.title)} |"
            )
    else:
        lines.append("_None met the thresholds._")
    lines.append("")

    for r in kept:
        lines.append(f"### {r.finding.id}: {r.finding.title}")
        lines.append("")
        lines.append(
            f"- **Jev severity**: {r.severity_label} "
            f"(score {_n(r.severity_score)}, confidence {_p(r.severity_confidence)})"
        )
        lines.append(f"- **Scanner severity**: {r.finding.severity}")
        lines.append(f"- **P(real)**: {_p(r.is_real)}  |  **P(reachable)**: {_p(r.reachable)}")
        lines.append(f"- **Category**: {r.category} (confidence {_p(r.category_confidence)})")
        if r.finding.file:
            lines.append(f"- **Location**: `{r.finding.file}`")
        if r.finding.cwe:
            lines.append(f"- **CWE**: {r.finding.cwe}")
        lines.append("")

    lines.append("## Dropped findings")
    lines.append("")
    if dropped:
        lines.append("| ID | Severity(scanner) | Reason |")
        lines.append("|----|-------------------|--------|")
        for r in dropped:
            lines.append(
                f"| {r.finding.id} | {r.finding.severity} | {_esc(r.reason)} |"
            )
    else:
        lines.append("_Nothing dropped._")
    lines.append("")

    Path(path).write_text("\n".join(lines))


def _p(x) -> str:
    return f"{x:.2f}" if isinstance(x, (int, float)) else "n/a"


def _n(x) -> str:
    return f"{x:.2f}" if isinstance(x, (int, float)) else "n/a"


def _esc(s: str) -> str:
    return str(s).replace("|", "\\|")
