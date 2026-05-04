"""Feature-planning bench runner.

Mirror of dataset/bench/bench_runner.py, scoped to the feature-planning
pipeline. Loads feature_synthetic.jsonl, samples N stratified across
feature_kind + product_context, runs cli_feature on each, scores with
the feature LLM judge, writes a markdown report + JSON sidecar.

Usage:
    python dataset/bench/feature_bench.py --n 6
    python dataset/bench/feature_bench.py --n 30 --judge --out validation/feature_baseline.md
"""

from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "dataset" / "data" / "synthetic" / "feature_synthetic.jsonl"
RUN_OUT_DIR = ROOT / ".bench_runs_feature"


sys.path.insert(0, str(ROOT))


def _load() -> list[dict]:
    if not DATA.exists():
        print(f"feature dataset not found at {DATA}; "
              "run dataset/synthetic/feature_generator.py first",
              file=sys.stderr)
        sys.exit(2)
    out = []
    for line in DATA.open():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def _stratified_sample(items: list[dict], n: int, *, seed: int) -> list[dict]:
    rng = random.Random(seed)
    by_kind = defaultdict(list)
    for it in items:
        by_kind[it["metadata"]["feature_kind"]].append(it)
    per = max(1, n // max(1, len(by_kind)))
    out = []
    for k, lst in by_kind.items():
        rng.shuffle(lst)
        out.extend(lst[:per])
    rng.shuffle(out)
    return out[:n]


def _run_one(elem: dict, *, prefer: str | None) -> tuple[dict | None, float]:
    """Run cli_feature on the element's intent and return the sidecar."""
    RUN_OUT_DIR.mkdir(parents=True, exist_ok=True)
    safe_id = elem["id"].replace("/", "_")[:120]
    intent_path = RUN_OUT_DIR / f"{safe_id}.intent.md"
    intent_path.write_text(elem["intent_md"])
    out_md = RUN_OUT_DIR / f"{safe_id}.feature.md"
    out_json = out_md.with_suffix(".json")

    cmd = [
        sys.executable,
        str(ROOT / "feature-planning" / "cli_feature.py"),
        str(intent_path),
        "--out", str(out_md),
    ]
    if prefer:
        cmd += ["--prefer", prefer]

    t0 = time.time()
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    elapsed = time.time() - t0
    if res.returncode != 0:
        print(f"  [error] {elem['id']}: {res.stderr[-300:]}", file=sys.stderr)
        return None, elapsed

    try:
        sidecar = json.loads(out_json.read_text())
    except Exception as e:
        print(f"  [error] {elem['id']}: failed to read sidecar: {e}", file=sys.stderr)
        return None, elapsed
    return sidecar, elapsed


def _score_literal(elem: dict, sidecar: dict) -> dict:
    """Quick literal checks against ground truth — cheap signal we can
    compute without the LLM judge."""
    gt = elem.get("ground_truth") or {}
    expected_stakeholders = set(gt.get("expected_blocking_stakeholders") or [])
    expected_axes = set(gt.get("expected_axes") or [])
    min_d = gt.get("min_estimated_days") or 0
    max_d = gt.get("max_estimated_days") or 999
    regulated = gt.get("regulated", False)
    expected_strategy = gt.get("expected_launch_strategy")

    constraints = sidecar.get("constraints") or []
    plans = sidecar.get("plans") or {}
    winner = sidecar.get("winner")
    timeline = sidecar.get("timeline") or {}

    # which owners produced at least one BLOCKING constraint?
    blocking_owners = {
        c.get("owner") for c in constraints
        if isinstance(c, dict) and c.get("blocking")
    }
    stakeholders_hit = len(expected_stakeholders & blocking_owners)

    axes_seen = {c.get("axis") for c in constraints if isinstance(c, dict)}
    axes_hit = len(expected_axes & axes_seen)

    winner_plan = plans.get(winner) if winner else None
    days_in_band = False
    launch_strategy_ok = False
    security_step_present = False
    if isinstance(winner_plan, dict):
        steps = winner_plan.get("steps") or []
        total_days = sum(int(s.get("estimated_days", 0) or 0)
                         for s in steps if isinstance(s, dict))
        # Use critical-path days when available; falls back to sum.
        cp_days = (timeline.get(winner) or {}).get("base_total_days", total_days)
        days_in_band = (min_d * 0.5) <= cp_days <= (max_d * 1.5)
        # Launch strategy match: any step using the expected strategy.
        strategies = {(s.get("launch_strategy") or "").lower()
                      for s in steps if isinstance(s, dict)}
        launch_strategy_ok = (expected_strategy or "").lower() in strategies
        # Security step: any step with owner="Security" or strong text match.
        security_step_present = any(
            (s.get("owner") == "Security"
             or "security" in (s.get("action") or "").lower()
             or "compliance" in (s.get("action") or "").lower())
            for s in steps if isinstance(s, dict)
        )

    # Literal verdict — strict pass needs all four checks
    if (stakeholders_hit == len(expected_stakeholders)
            and axes_hit == len(expected_axes)
            and days_in_band
            and launch_strategy_ok
            and (not regulated or security_step_present)):
        verdict = "caught"
    elif (stakeholders_hit >= max(1, len(expected_stakeholders) // 2)
          and axes_hit >= max(1, len(expected_axes) // 2)):
        verdict = "partial"
    else:
        verdict = "missed"

    return {
        "verdict": verdict,
        "stakeholders_hit": stakeholders_hit,
        "stakeholders_total": len(expected_stakeholders),
        "axes_hit": axes_hit,
        "axes_total": len(expected_axes),
        "days_in_band": days_in_band,
        "launch_strategy_ok": launch_strategy_ok,
        "security_step_present": security_step_present,
        "regulated": regulated,
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Feature-planning bench runner")
    p.add_argument("--n", type=int, default=6)
    p.add_argument("--seed", type=int, default=2026)
    p.add_argument("--prefer", default=None,
                   choices=["fast", "polished", "safe", "balanced"])
    p.add_argument("--judge", action="store_true",
                   help="Add LLM-judge verdict alongside the literal one")
    p.add_argument("--out", type=Path,
                   default=ROOT / "validation" / "FEATURE_BENCH.md")
    args = p.parse_args(argv)

    items = _load()
    print(f"[load] {len(items)} feature elements available", file=sys.stderr)
    sample = _stratified_sample(items, args.n, seed=args.seed)
    print(f"[sample] {len(sample)} elements (stratified, seed {args.seed})",
          file=sys.stderr)

    judge_fn = None
    if args.judge:
        from llm_judge_feature import judge_feature_element
        from mirofish_lab.config import load_config
        cfg = load_config()
        judge_fn = lambda e, s: judge_feature_element(e, s, cfg=cfg)

    scores = []
    for i, elem in enumerate(sample, 1):
        print(f"[run {i}/{len(sample)}] {elem['id']}", file=sys.stderr)
        sidecar, elapsed = _run_one(elem, prefer=args.prefer)
        if sidecar is None:
            scores.append({"id": elem["id"], "error": "pipeline_failed",
                           "elapsed_s": elapsed})
            continue
        lit = _score_literal(elem, sidecar)
        rec = {
            "id": elem["id"],
            "feature_kind": elem["metadata"]["feature_kind"],
            "context": elem["metadata"]["product_context"],
            "scale": elem["metadata"]["scale_tier"],
            "winner": sidecar.get("winner"),
            "elapsed_s": elapsed,
            "literal": lit,
        }
        if judge_fn:
            rec["judge"] = judge_fn(elem, sidecar)
        scores.append(rec)

    # Aggregate
    lit_verdicts = Counter(s["literal"]["verdict"] for s in scores
                           if "literal" in s)
    judge_verdicts = Counter(
        (s.get("judge") or {}).get("verdict", "?") for s in scores
        if "judge" in s
    )
    by_kind = defaultdict(lambda: Counter())
    for s in scores:
        if "literal" in s:
            by_kind[s["feature_kind"]][s["literal"]["verdict"]] += 1
    n = len([s for s in scores if "literal" in s])

    # Render report
    lines = [
        f"# Feature-planning bench — n={args.n} (seed {args.seed})",
        "",
        f"_Pipeline: cli_feature · prefer={args.prefer or 'balanced'}._",
        "",
        "## Aggregate verdicts",
        "",
        f"- literal: {dict(lit_verdicts)} (n={n})",
    ]
    if judge_verdicts:
        lines.append(f"- judge:   {dict(judge_verdicts)}")
    lines += ["", "## Per-feature-kind verdicts", "",
              "| kind | caught | partial | missed |",
              "|---|---|---|---|"]
    for k, ctr in sorted(by_kind.items()):
        lines.append(
            f"| {k} | {ctr.get('caught',0)} | "
            f"{ctr.get('partial',0)} | {ctr.get('missed',0)} |"
        )
    lines += ["", "## Per-element scores", "",
              "| id | winner | literal | judge | days_band | strat_ok | sec |",
              "|---|---|---|---|---|---|---|"]
    for s in scores:
        if "error" in s:
            lines.append(f"| `{s['id']}` | — | ERROR | — | — | — | — |")
            continue
        lit = s["literal"]
        j = (s.get("judge") or {}).get("verdict", "—")
        lines.append(
            f"| `{s['id']}` | {s.get('winner','?')} | {lit['verdict']} | "
            f"{j} | {'Y' if lit['days_in_band'] else 'N'} | "
            f"{'Y' if lit['launch_strategy_ok'] else 'N'} | "
            f"{'Y' if lit['security_step_present'] else 'N'} |"
        )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(lines))
    args.out.with_suffix(".json").write_text(json.dumps({
        "args": vars(args) | {"out": str(args.out)},
        "scores": scores,
        "literal_verdicts": dict(lit_verdicts),
        "judge_verdicts": dict(judge_verdicts) if judge_verdicts else None,
        "by_kind": {k: dict(v) for k, v in by_kind.items()},
    }, indent=2, default=str))
    print(f"\n[done] wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
