"""A/B harness for the rollout-rehearsal pipeline.

Runs a suite of intents under config A vs config B, aggregates the
resulting metrics, and reports a delta. This is the foundation of
responsible calibration: any change to UtilityWeights, persona system
prompts, or other knobs must demonstrate metric improvement on this
harness before being committed.

Configs are JSON dicts with the same shape:

    {
        "name": "old-fragility-dominated",
        "utility_weights": {"fragility": 0.40, "coverage": 0.30,
                            "steps": 0.10, "severity": 0.15,
                            "rollback_failure": 0.05},
        "intents": ["validation/postmortems/intents/04_gitlab_db_replica.md",
                    "validation/real_world_demo/intent_teleport_sqlite_cache.md"],
        "n_plans": 4,
        "repo_for": {                # optional: --repo per-intent
            "validation/real_world_demo/intent_teleport_sqlite_cache.md":
                ".clones/claude-teleport-analyzer"
        }
    }

Usage:
    python validation/ab_harness.py \\
        --a config_a.json --b config_b.json \\
        --out validation/ab_<run-id>.md
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run_pipeline(intent: Path, *, repo: Path | None,
                  utility_weights: dict, n_plans: int) -> dict:
    """Run cli_grounded.py (if repo given) or cli_pro.py (otherwise) and
    return the resulting JSON sidecar contents."""
    out_dir = ROOT / ".ab_runs"
    out_dir.mkdir(exist_ok=True)
    suffix = "grounded" if repo else "pro"
    out_path = out_dir / f"{intent.stem}_{suffix}_{os.getpid()}_{id(intent)}.md"
    json_path = out_path.with_suffix(".json")

    weight_str = ",".join(f"{k}={v}" for k, v in utility_weights.items())

    if repo:
        cmd = [
            sys.executable,
            str(ROOT / "verified-rollout" / "cli_grounded.py"),
            str(intent),
            "--repo", str(repo),
            "--n-plans", str(n_plans),
            "--utility", weight_str,
            "--out", str(out_path),
        ]
    else:
        cmd = [
            sys.executable,
            str(ROOT / "verified-rollout" / "cli_pro.py"),
            str(intent),
            "--n-plans", str(n_plans),
            "--utility", weight_str,
            "--out", str(out_path),
        ]
    env = dict(os.environ)
    env.setdefault("MODEL", "gpt-5.4-mini")
    env.setdefault("MAX_TOKENS", "2200")
    res = subprocess.run(cmd, env=env, cwd=str(ROOT),
                         capture_output=True, text=True, timeout=600)
    if res.returncode != 0:
        print(f"  [run failed] {intent.name}: {res.stderr[-400:]}",
              file=sys.stderr)
        return {}
    if not json_path.exists():
        return {}
    return json.loads(json_path.read_text())


def _extract_row(j: dict) -> dict | None:
    if not j:
        return None
    plans = j.get("plans") or {}
    smt = j.get("smt") or {}
    chaos = j.get("chaos") or {}
    scores = j.get("scores") or {}
    pareto = j.get("pareto") or {}
    winner = pareto.get("winner") or j.get("winner") or (
        j.get("recommendation") or {}).get("winner")
    if not winner:
        return None
    smt_feasible = sum(
        1 for v in smt.values() if isinstance(v, dict) and v.get("feasible", True)
    )
    n_plans = max(len(plans), len(smt), len(chaos), len(scores))
    if winner in scores:
        winner_frag = scores[winner].get("fragility")
    elif winner in chaos:
        winner_frag = chaos[winner].get("fragility")
    else:
        winner_frag = None
    return {
        "winner": winner,
        "n_plans": n_plans,
        "smt_feasible_count": smt_feasible,
        "winner_fragility": winner_frag,
    }


def _winner_family(label: str) -> str:
    for fam in ("speed", "safety", "cost", "balanced"):
        if fam in label.lower():
            return fam
    return "other"


def run_config(config: dict) -> dict:
    """Run every intent under this config; return aggregated results."""
    rows = []
    for intent_path in config["intents"]:
        intent = Path(intent_path)
        repo = config.get("repo_for", {}).get(intent_path)
        repo_path = Path(repo) if repo else None
        print(f"  [run] {intent.name}"
              + (f" --repo {repo}" if repo else ""), file=sys.stderr)
        j = _run_pipeline(
            intent,
            repo=repo_path,
            utility_weights=config["utility_weights"],
            n_plans=config.get("n_plans", 4),
        )
        row = _extract_row(j)
        if row:
            rows.append({"intent": intent_path, **row})
    return {
        "config_name": config["name"],
        "n_runs": len(rows),
        "rows": rows,
    }


def aggregate(rows: list[dict]) -> dict:
    if not rows:
        return {}
    fams = Counter(_winner_family(r["winner"]) for r in rows)
    smt_total = sum(r["smt_feasible_count"] for r in rows)
    plans_total = sum(r["n_plans"] for r in rows)
    fragilities = [r["winner_fragility"] for r in rows
                   if r["winner_fragility"] is not None]
    return {
        "n_runs": len(rows),
        "winner_family_dist": dict(fams),
        "max_family_share": max(c / len(rows) for c in fams.values())
                            if fams else 0.0,
        "smt_feasibility_rate": smt_total / max(1, plans_total),
        "avg_winner_fragility": statistics.mean(fragilities) if fragilities else 0.0,
        "median_winner_fragility": statistics.median(fragilities) if fragilities else 0.0,
        "winner_fragility_p90": (
            statistics.quantiles(fragilities, n=10)[-1]
            if len(fragilities) >= 10 else (max(fragilities) if fragilities else 0.0)
        ),
    }


def render_report(result_a: dict, result_b: dict, *, criterion: str) -> str:
    agg_a = aggregate(result_a["rows"])
    agg_b = aggregate(result_b["rows"])

    def fmt(d: dict, k: str, scale: float = 1.0, suffix: str = "") -> str:
        v = d.get(k)
        if v is None:
            return "—"
        return f"{v * scale:.3f}{suffix}"

    lines = [
        f"# A/B harness: `{result_a['config_name']}` vs `{result_b['config_name']}`",
        "",
        f"_Generated {datetime.utcnow().isoformat(timespec='seconds')}Z_",
        "",
        f"Criterion: **{criterion}**",
        "",
        "## Summary",
        "",
        f"| Metric | A: `{result_a['config_name']}` | B: `{result_b['config_name']}` | Δ (B − A) |",
        "|---|---|---|---|",
    ]
    metrics = [
        ("n runs", "n_runs", 1, ""),
        ("max winner-family share", "max_family_share", 100, "%"),
        ("SMT feasibility rate", "smt_feasibility_rate", 100, "%"),
        ("avg winner fragility", "avg_winner_fragility", 1, ""),
        ("median winner fragility", "median_winner_fragility", 1, ""),
        ("winner fragility p90", "winner_fragility_p90", 1, ""),
    ]
    for label, key, scale, suffix in metrics:
        a_v = agg_a.get(key, 0)
        b_v = agg_b.get(key, 0)
        delta = b_v - a_v
        lines.append(
            f"| {label} | {a_v * scale:.2f}{suffix} | {b_v * scale:.2f}{suffix} | "
            f"{delta * scale:+.2f}{suffix} |"
        )
    lines.append("")

    # Verdict
    verdict = _verdict(agg_a, agg_b, criterion)
    lines.append("## Verdict")
    lines.append("")
    lines.append(f"**{verdict['label']}** — {verdict['reason']}")
    lines.append("")

    # Per-intent table.
    lines.append("## Per-intent")
    lines.append("")
    lines.append("| Intent | A winner | A frag | B winner | B frag |")
    lines.append("|---|---|---|---|---|")
    by_intent = {}
    for r in result_a["rows"]:
        by_intent.setdefault(r["intent"], {})["a"] = r
    for r in result_b["rows"]:
        by_intent.setdefault(r["intent"], {})["b"] = r
    for intent, sides in by_intent.items():
        a = sides.get("a", {})
        b = sides.get("b", {})
        lines.append(
            f"| `{Path(intent).name}` | "
            f"{a.get('winner', '—')} | {a.get('winner_fragility', '—')} | "
            f"{b.get('winner', '—')} | {b.get('winner_fragility', '—')} |"
        )
    lines.append("")
    lines.append("## Family distributions")
    lines.append("")
    lines.append("| Family | A count | B count |")
    lines.append("|---|---|---|")
    fams_all = set(agg_a.get("winner_family_dist", {}).keys()) | set(
        agg_b.get("winner_family_dist", {}).keys()
    )
    for fam in sorted(fams_all):
        a = agg_a.get("winner_family_dist", {}).get(fam, 0)
        b = agg_b.get("winner_family_dist", {}).get(fam, 0)
        lines.append(f"| {fam} | {a} | {b} |")
    return "\n".join(lines)


def _verdict(agg_a: dict, agg_b: dict, criterion: str) -> dict:
    """Given two aggregates and a criterion, decide if B is an improvement.

    Criteria:
      - "minimise_max_family_share" : best when no one family dominates
      - "maximise_smt_feasibility"  : best when more plans are formally feasible
      - "minimise_avg_fragility"    : best when avg winner fragility is lower
      - "maximise_avg_fragility"    : opposite (rarely useful)
      - "balanced"                  : composite of all three above
    """
    def cmp(a, b, lower_is_better=True):
        if a == b:
            return "tie"
        if lower_is_better:
            return "B better" if b < a else "A better"
        return "B better" if b > a else "A better"

    if criterion == "minimise_max_family_share":
        a, b = agg_a.get("max_family_share", 1), agg_b.get("max_family_share", 1)
        return {"label": cmp(a, b, lower_is_better=True),
                "reason": f"max family share A={a:.0%} → B={b:.0%}"}
    if criterion == "maximise_smt_feasibility":
        a, b = agg_a.get("smt_feasibility_rate", 0), agg_b.get("smt_feasibility_rate", 0)
        return {"label": cmp(a, b, lower_is_better=False),
                "reason": f"SMT feasibility A={a:.0%} → B={b:.0%}"}
    if criterion == "minimise_avg_fragility":
        a, b = agg_a.get("avg_winner_fragility", 0), agg_b.get("avg_winner_fragility", 0)
        return {"label": cmp(a, b, lower_is_better=True),
                "reason": f"avg fragility A={a:.3f} → B={b:.3f}"}
    if criterion == "balanced":
        # Composite: -family_share + smt_feasibility - avg_fragility
        # Positive ∆ means improvement.
        sa = (-agg_a.get("max_family_share", 1) + agg_a.get("smt_feasibility_rate", 0)
              - agg_a.get("avg_winner_fragility", 0))
        sb = (-agg_b.get("max_family_share", 1) + agg_b.get("smt_feasibility_rate", 0)
              - agg_b.get("avg_winner_fragility", 0))
        return {"label": cmp(sa, sb, lower_is_better=False),
                "reason": f"composite score A={sa:.3f} → B={sb:.3f}"}
    return {"label": "unknown criterion", "reason": criterion}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A/B harness for the rollout pipeline.")
    parser.add_argument("--a", type=Path, required=True, help="Config A JSON")
    parser.add_argument("--b", type=Path, required=True, help="Config B JSON")
    parser.add_argument(
        "--criterion",
        default="balanced",
        choices=["minimise_max_family_share", "maximise_smt_feasibility",
                 "minimise_avg_fragility", "balanced"],
    )
    parser.add_argument("--out", type=Path, default=ROOT / "validation" / "AB_REPORT.md")
    args = parser.parse_args(argv)

    config_a = json.loads(args.a.read_text())
    config_b = json.loads(args.b.read_text())

    print(f"=== A: {config_a['name']} ===", file=sys.stderr)
    result_a = run_config(config_a)
    print(f"=== B: {config_b['name']} ===", file=sys.stderr)
    result_b = run_config(config_b)

    md = render_report(result_a, result_b, criterion=args.criterion)
    args.out.write_text(md)

    json_path = args.out.with_suffix(".json")
    json_path.write_text(json.dumps({
        "criterion": args.criterion,
        "a": result_a,
        "b": result_b,
        "agg_a": aggregate(result_a["rows"]),
        "agg_b": aggregate(result_b["rows"]),
        "verdict": _verdict(aggregate(result_a["rows"]),
                            aggregate(result_b["rows"]),
                            args.criterion),
    }, indent=2))
    print(f"\n[done] wrote {args.out} and {json_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
