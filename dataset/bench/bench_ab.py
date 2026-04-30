"""Bench-driven A/B harness.

Replaces the 2-intent internal-metric A/B (validation/ab_harness.py)
with a stratified bench-runner sample scored by the LLM judge. Each
config (utility-weight string) runs the pipeline + judge on the SAME
N elements; we compare caught/partial/missed rates.

Usage:
    python dataset/bench/bench_ab.py \\
        --a "fragility=0.20,coverage=0.25,steps=0.10,severity=0.20,rollback_failure=0.25" \\
        --b "fragility=0.15,coverage=0.25,steps=0.10,severity=0.20,rollback_failure=0.30" \\
        --n 8 \\
        --sources swebench_verified danluu_postmortems synthetic \\
        --out validation/AB_BENCH_<id>.md

Produces a markdown report + JSON sidecar with verdict, plus the
per-element table so a human can spot where the configs diverge.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _run_bench(*, utility: str, n: int, sources: list[str],
               run_label: str, out_md: Path, judge: bool = True) -> dict:
    """Invoke bench_runner.py once with the given utility config."""
    cmd = [
        sys.executable,
        str(ROOT / "dataset" / "bench" / "bench_runner.py"),
        "--n", str(n),
        "--sources", *sources,
        "--pipeline", "cli_pro",
        "--max-tokens", "1200",
        "--n-plans", "3",
        "--utility", utility,
        "--run-label", run_label,
        "--out", str(out_md),
    ]
    if judge:
        cmd.append("--judge")
    env = dict(os.environ)
    env.setdefault("MODEL", "gpt-5.4-mini")
    res = subprocess.run(cmd, env=env, cwd=str(ROOT), capture_output=True,
                         text=True)
    if res.returncode != 0:
        print("--- bench_runner stderr ---\n" + res.stderr[-1000:],
              file=sys.stderr)
        raise RuntimeError(f"bench_runner failed for {run_label}")
    return json.loads(out_md.with_suffix(".json").read_text())


def _aggregate(scores: list[dict], *, judge: bool) -> dict:
    """Aggregate per-element scores into summary metrics."""
    verdict_key = "verdict_judge" if judge else "verdict"
    fams = Counter()
    verdicts = Counter()
    smt_feasible = 0
    plans = 0
    for s in scores:
        verdicts[s.get(verdict_key, "?")] += 1
        fams[s.get("winner_family", "?")] += 1
        smt_feasible += s.get("smt_feasible_count", 0)
        plans += s.get("n_plans", 0)
    n = max(1, len(scores))
    return {
        "n": len(scores),
        "verdicts": dict(verdicts),
        "caught_rate": verdicts.get("caught", 0) / n,
        "partial_rate": verdicts.get("partial", 0) / n,
        "missed_rate": verdicts.get("missed", 0) / n,
        "useful_rate": (verdicts.get("caught", 0) + verdicts.get("partial", 0)) / n,
        "winner_family_dist": dict(fams),
        "max_family_share": max(fams.values()) / n if fams else 0.0,
        "smt_feasibility_rate": smt_feasible / max(1, plans),
    }


def _verdict(agg_a: dict, agg_b: dict, criterion: str) -> dict:
    """Pick A/B winner under the given criterion."""
    if criterion == "useful_rate":
        a, b = agg_a["useful_rate"], agg_b["useful_rate"]
        return {
            "label": "B better" if b > a + 0.02 else (
                "A better" if a > b + 0.02 else "tie"
            ),
            "reason": f"useful (caught+partial) rate A={a:.0%} → B={b:.0%}",
        }
    if criterion == "caught_rate":
        a, b = agg_a["caught_rate"], agg_b["caught_rate"]
        return {
            "label": "B better" if b > a + 0.02 else (
                "A better" if a > b + 0.02 else "tie"
            ),
            "reason": f"caught rate A={a:.0%} → B={b:.0%}",
        }
    if criterion == "balanced":
        sa = (agg_a["useful_rate"]
              + agg_a["smt_feasibility_rate"] * 0.5
              - agg_a["max_family_share"] * 0.5)
        sb = (agg_b["useful_rate"]
              + agg_b["smt_feasibility_rate"] * 0.5
              - agg_b["max_family_share"] * 0.5)
        return {
            "label": "B better" if sb > sa + 0.02 else (
                "A better" if sa > sb + 0.02 else "tie"
            ),
            "reason": f"composite useful + 0.5*smt - 0.5*family-bias: "
                      f"A={sa:.3f} → B={sb:.3f}",
        }
    return {"label": "unknown", "reason": criterion}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bench-driven A/B harness")
    parser.add_argument("--a", required=True,
                        help="Utility-weight string for config A")
    parser.add_argument("--b", required=True,
                        help="Utility-weight string for config B")
    parser.add_argument("--n", type=int, default=8,
                        help="Sample size PER config (total = 2*n bench runs)")
    parser.add_argument(
        "--sources", nargs="+",
        default=["swebench_verified", "danluu_postmortems", "synthetic"],
    )
    parser.add_argument("--criterion", default="useful_rate",
                        choices=["useful_rate", "caught_rate", "balanced"])
    parser.add_argument(
        "--out", type=Path,
        default=ROOT / "validation" / "AB_BENCH.md",
    )
    args = parser.parse_args(argv)

    out_a = ROOT / ".bench_runs" / "ab_a.md"
    out_b = ROOT / ".bench_runs" / "ab_b.md"
    out_a.parent.mkdir(parents=True, exist_ok=True)

    print(f"=== A: {args.a} ===", file=sys.stderr)
    res_a = _run_bench(
        utility=args.a, n=args.n, sources=args.sources,
        run_label="ab_a", out_md=out_a,
    )
    print(f"=== B: {args.b} ===", file=sys.stderr)
    res_b = _run_bench(
        utility=args.b, n=args.n, sources=args.sources,
        run_label="ab_b", out_md=out_b,
    )

    agg_a = _aggregate(res_a["scores"], judge=True)
    agg_b = _aggregate(res_b["scores"], judge=True)
    verdict = _verdict(agg_a, agg_b, args.criterion)

    lines = [
        f"# Bench-driven A/B — {datetime.utcnow().isoformat(timespec='seconds')}Z",
        "",
        f"Sample size per config: **{args.n}**. Sources: {args.sources}. "
        f"Criterion: **{args.criterion}**.",
        "",
        "## Configs",
        "",
        f"- **A**: `{args.a}`",
        f"- **B**: `{args.b}`",
        "",
        "## Aggregate verdict",
        "",
        f"**{verdict['label']}** — {verdict['reason']}",
        "",
        "## Metrics A vs B",
        "",
        "| Metric | A | B | Δ (B − A) |",
        "|---|---|---|---|",
    ]
    for label, key, scale in [
        ("caught rate", "caught_rate", 100),
        ("partial rate", "partial_rate", 100),
        ("missed rate", "missed_rate", 100),
        ("useful (caught+partial) rate", "useful_rate", 100),
        ("SMT feasibility rate", "smt_feasibility_rate", 100),
        ("max family share", "max_family_share", 100),
    ]:
        a_v = agg_a.get(key, 0)
        b_v = agg_b.get(key, 0)
        lines.append(
            f"| {label} | {a_v * scale:.1f}% | {b_v * scale:.1f}% | "
            f"{(b_v - a_v) * scale:+.1f}% |"
        )

    lines.append("")
    lines.append("## Per-element verdicts")
    lines.append("")
    lines.append("| Element | A verdict | B verdict |")
    lines.append("|---|---|---|")
    by_id = {}
    for s in res_a["scores"]:
        by_id.setdefault(s["id"], {})["a"] = s.get("verdict_judge", s.get("verdict"))
    for s in res_b["scores"]:
        by_id.setdefault(s["id"], {})["b"] = s.get("verdict_judge", s.get("verdict"))
    for elem_id, sides in by_id.items():
        lines.append(
            f"| `{elem_id[:60]}` | {sides.get('a', '—')} | {sides.get('b', '—')} |"
        )

    args.out.write_text("\n".join(lines))
    args.out.with_suffix(".json").write_text(json.dumps({
        "config_a": args.a,
        "config_b": args.b,
        "n": args.n,
        "sources": args.sources,
        "criterion": args.criterion,
        "agg_a": agg_a,
        "agg_b": agg_b,
        "verdict": verdict,
        "scores_a": res_a["scores"],
        "scores_b": res_b["scores"],
    }, indent=2))
    print(f"\n[done] wrote {args.out}", file=sys.stderr)
    print(f"[verdict] {verdict['label']} — {verdict['reason']}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
