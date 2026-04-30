"""Mechanical detection of dead SearchPlanner patterns.

For every grounded run, the SearchPlanner LLM emits a list of patterns
(regex / AST queries) and the deterministic scanner reports how many
matches each found. Patterns that find ZERO matches across multiple
runs are dead -- the LLM keeps proposing them but they never hit. The
right fix is either (a) revise the SearchPlanner system prompt to
discourage them, or (b) add a hand-curated "anti-list" of patterns
known to be useless.

This script identifies them.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN_DIRS = [ROOT / "validation", ROOT / "verified-rollout" / "reports"]

MIN_RUNS = 2          # only flag patterns seen in ≥ this many runs
ZERO_THRESHOLD = 0.0  # define "dead" as exactly 0 matches; could be > 0 for "rarely useful"


def main() -> None:
    pattern_runs: dict[str, list[tuple[str, int]]] = defaultdict(list)
    grounded_runs = 0
    for d in SCAN_DIRS:
        if not d.exists():
            continue
        for p in d.rglob("*.json"):
            try:
                j = json.loads(p.read_text())
            except Exception:
                continue
            sp = j.get("search_plan")
            findings = j.get("findings")
            if not isinstance(sp, dict) or not isinstance(findings, dict):
                continue
            grounded_runs += 1
            mbp = findings.get("matches_by_pattern") or {}
            for pat in sp.get("patterns") or []:
                desc = pat.get("description") or ""
                if not desc:
                    continue
                n_matches = len(mbp.get(desc) or [])
                pattern_runs[desc].append((str(p.relative_to(ROOT)), n_matches))

    if not pattern_runs:
        print("no grounded runs found", file=sys.stderr)
        return

    # Flag patterns that:
    # 1. Appeared in >= MIN_RUNS runs
    # 2. Found ZERO matches in EVERY one of those runs
    dead: list[tuple[str, list[tuple[str, int]]]] = []
    rare: list[tuple[str, list[tuple[str, int]]]] = []
    for desc, runs in pattern_runs.items():
        if len(runs) < MIN_RUNS:
            continue
        zero_hits = sum(1 for _, n in runs if n <= ZERO_THRESHOLD)
        if zero_hits == len(runs):
            dead.append((desc, runs))
        elif zero_hits / len(runs) >= 0.75:
            rare.append((desc, runs))

    out = [
        "# Dead-pattern detector",
        "",
        f"_{grounded_runs} grounded runs scanned across `validation/` and `verified-rollout/reports/`._",
        "",
        f"Patterns considered: **{len(pattern_runs)}** distinct descriptions.",
        f"- Dead (>= {MIN_RUNS} runs, ZERO matches in every one): **{len(dead)}**",
        f"- Rarely useful (>= 75% zero-hit rate, but not always): **{len(rare)}**",
        "",
    ]
    if dead:
        out.append("## Dead patterns (recommend dropping or rewriting)")
        out.append("")
        for desc, runs in sorted(dead, key=lambda kv: -len(kv[1])):
            out.append(f"### `{desc}`")
            out.append("")
            out.append(f"- seen in **{len(runs)}** runs, all 0 matches:")
            for run_path, _ in runs[:5]:
                out.append(f"  - {run_path}")
            out.append("")
        out.append(
            "**Action**: revise the SearchPlanner system prompt in "
            "`mirofish_lab/grounding.py` to discourage these descriptions, "
            "or add an explicit anti-list to `_parse_search_plan`."
        )
        out.append("")
    if rare:
        out.append("## Rarely useful patterns (>= 75% zero-hit rate)")
        out.append("")
        for desc, runs in sorted(rare, key=lambda kv: -len(kv[1])):
            zeros = sum(1 for _, n in runs if n == 0)
            out.append(f"- `{desc}` — {zeros}/{len(runs)} zero")
        out.append("")
    if not dead and not rare:
        out.append("✅ No dead or rarely-useful patterns detected. SearchPlanner output is clean.")

    target = ROOT / "validation" / "DEAD_PATTERNS.md"
    target.write_text("\n".join(out))
    json_target = ROOT / "validation" / "DEAD_PATTERNS.json"
    json_target.write_text(json.dumps({
        "n_grounded_runs": grounded_runs,
        "n_unique_patterns": len(pattern_runs),
        "dead": [{"description": d, "runs": r} for d, r in dead],
        "rare": [{"description": d, "runs": r} for d, r in rare],
    }, indent=2))
    print(f"[done] wrote {target} and {json_target}", file=sys.stderr)


if __name__ == "__main__":
    main()
