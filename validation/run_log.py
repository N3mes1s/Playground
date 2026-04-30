"""Meta-analysis over every committed pipeline run.

The continuous-improvement loop needs visibility: are recommendations
biased toward one Pareto label? Are SMT-infeasibility rates trending
up? Is the chaos probe stable? This script scans every JSON sidecar
under `validation/` and `verified-rollout/reports/` and emits a
markdown report on those cross-run statistics.

Run after every batch of new runs to spot systemic issues before
they become entrenched.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SCAN_DIRS = [
    ROOT / "validation",
    ROOT / "verified-rollout" / "reports",
]


def _load_all() -> list[tuple[Path, dict]]:
    out: list[tuple[Path, dict]] = []
    seen = set()
    for d in SCAN_DIRS:
        if not d.exists():
            continue
        for p in d.rglob("*.json"):
            try:
                j = json.loads(p.read_text())
            except Exception:
                continue
            if not isinstance(j, dict):
                continue
            key = str(p.relative_to(ROOT))
            if key in seen:
                continue
            seen.add(key)
            out.append((p, j))
    return out


def _row_for(path: Path, j: dict) -> dict | None:
    """Best-effort extraction of (winner, plans, scores) from any of our
    sidecar shapes."""
    plans = j.get("plans") or {}
    scores = j.get("scores") or {}
    chaos = j.get("chaos") or {}
    smt = j.get("smt") or {}
    pareto = j.get("pareto") or {}
    winner = pareto.get("winner") or j.get("winner") or (
        j.get("recommendation") or {}
    ).get("winner")
    n_plans = max(len(plans), len(scores), len(chaos))
    if n_plans < 3 or not winner:
        return None
    smt_feasible = sum(
        1 for v in smt.values()
        if isinstance(v, dict) and v.get("feasible", True)
    )
    if winner in scores:
        winner_fragility = scores[winner].get("fragility")
    elif winner in chaos:
        winner_fragility = chaos[winner].get("fragility")
    else:
        winner_fragility = None
    return {
        "path": str(path.relative_to(ROOT)),
        "winner": winner,
        "n_plans": n_plans,
        "smt_feasible_count": smt_feasible,
        "winner_fragility": winner_fragility,
    }


def _latest_rebaseline_snapshot() -> list[str] | None:
    """Render a 'Latest snapshot' section from the newest REBASELINE_*.json
    sidecar in validation/. Returns markdown lines or None if absent.

    The all-time aggregate weights every historical run equally, so old
    runs from before a fix landed dominate. The snapshot section gives
    the freshest cohort visibility so the calibrator and the README can
    reconcile against it.
    """
    snaps = sorted((ROOT / "validation").glob("REBASELINE_*.json"))
    if not snaps:
        return None
    latest = snaps[-1]
    try:
        j = json.loads(latest.read_text())
    except Exception:
        return None
    scores = j.get("scores") or []
    if not scores:
        return None
    total = len(scores)
    by_family: Counter[str] = Counter()
    for r in scores:
        fam = r.get("winner_family") or "other"
        by_family[fam] += 1
    plans_total = sum(r.get("n_plans", 0) for r in scores)
    smt_total = sum(r.get("smt_feasible_count", 0) for r in scores)
    smt_pct = 100 * smt_total / max(1, plans_total)
    lines = [
        f"## Latest snapshot — {latest.stem}",
        "",
        f"_N={total}, timestamp `{j.get('timestamp', '?')}`. "
        "Use these numbers (not the all-time aggregate) for current-state checks._",
        "",
        "| Family | Wins |",
        "|---|---|",
    ]
    for fam, count in by_family.most_common():
        pct = 100 * count / total
        warn = " ⚠️ over 40%" if pct > 40 else ""
        lines.append(f"| {fam} | {count} ({pct:.0f}%){warn} |")
    lines.append("")
    lines.append(
        f"- SMT-feasible (snapshot): **{smt_total}** / {plans_total} "
        f"({smt_pct:.0f}%)"
    )
    return lines


def main() -> None:
    rows = []
    for path, j in _load_all():
        r = _row_for(path, j)
        if r:
            rows.append(r)

    if not rows:
        print("no eligible runs found", file=sys.stderr)
        return

    winners = Counter(r["winner"] for r in rows)
    by_family: dict[str, int] = {}
    for label, count in winners.items():
        for fam in ("speed", "safety", "cost", "balanced"):
            if fam in label.lower():
                by_family[fam] = by_family.get(fam, 0) + count
                break
        else:
            by_family["other"] = by_family.get("other", 0) + count

    smt_total = sum(r["smt_feasible_count"] for r in rows)
    plans_total = sum(r["n_plans"] for r in rows)

    avg_winner_fragility = (
        sum(r["winner_fragility"] for r in rows if r["winner_fragility"] is not None)
        / max(1, sum(1 for r in rows if r["winner_fragility"] is not None))
    )

    snapshot_md = _latest_rebaseline_snapshot()

    out = [
        "# Pipeline run log — meta-analysis",
        "",
        f"_All-time aggregate: {len(rows)} eligible runs across `validation/` "
        "and `verified-rollout/reports/`. Older runs may dominate; for the "
        "latest snapshot see the section below._",
        "",
    ]
    if snapshot_md:
        out.extend(snapshot_md)
        out.append("")
    out += [
        "## Bias check: winner family distribution (all-time)",
        "",
        "| Family | Wins |",
        "|---|---|",
    ]
    for fam, count in sorted(by_family.items(), key=lambda kv: -kv[1]):
        pct = 100 * count / max(1, len(rows))
        warn = " ⚠️ over 40%" if pct > 40 else ""
        out.append(f"| {fam} | {count} ({pct:.0f}%){warn} |")
    out.append("")
    out.append(
        "If any one family wins >40%, the recommendation logic likely has a "
        "bias and the utility weights / preset defaults should be reviewed."
    )
    out.append("")

    out.append("## SMT feasibility rate (all-time)")
    out.append("")
    out.append(
        f"- Plans across all runs: **{plans_total}**"
    )
    out.append(
        f"- SMT-feasible: **{smt_total}** ({100 * smt_total / max(1, plans_total):.0f}%)"
    )
    out.append(
        "- A low feasibility rate (<50%) suggests the Sequencer is producing "
        "ordering contradictions; review the constraint-mapping heuristics."
    )
    out.append("")

    out.append("## Winner fragility distribution")
    out.append("")
    out.append(
        f"- Average winner fragility: **{avg_winner_fragility:.3f}**"
    )
    out.append(
        "- If average winner fragility is below ~0.20, the recommender is "
        "plausibly over-weighting cascade-fragility (which rewards "
        "parallelism) at the expense of operationally-safer sequential plans."
    )
    out.append("")

    out.append("## Per-run summary")
    out.append("")
    out.append("| Run | Winner | Plans | SMT feas. | Winner fragility |")
    out.append("|---|---|---|---|---|")
    for r in rows:
        out.append(
            f"| `{r['path']}` | {r['winner']} | {r['n_plans']} | "
            f"{r['smt_feasible_count']}/{r['n_plans']} | "
            f"{r['winner_fragility'] if r['winner_fragility'] is not None else '—'} |"
        )

    target = ROOT / "validation" / "RUN_LOG.md"
    target.write_text("\n".join(out))
    print(f"[done] wrote {target}", file=sys.stderr)


if __name__ == "__main__":
    main()
