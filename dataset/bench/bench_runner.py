"""Bench runner: evaluate the rollout-rehearsal pipeline against the
unified 20k-element dataset.

Usage:
    python dataset/bench/bench_runner.py \\
        --n 50 \\
        --sources swebench_verified swebench_pro danluu_postmortems synthetic \\
        --pipeline cli_pro \\
        --out dataset/reports/bench_<timestamp>.md

The runner samples N elements stratified across the requested
sources, runs the chosen pipeline (cli_pro / cli_grounded / cli_chaos
/ cli_harden) on each, and produces an aggregated report:

  - per-source verdicts (caught / partial / missed for elements with
    ground truth)
  - SMT feasibility rate per source
  - winner-family distribution per source
  - winner fragility distribution per source
  - per-source token / time cost
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import statistics
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA_DIRS = [
    ROOT / "dataset" / "data" / "real",
    ROOT / "dataset" / "data" / "synthetic",
]
REPORTS_DIR = ROOT / "dataset" / "reports"
RUN_OUT_DIR = ROOT / ".bench_runs"


_TOK = re.compile(r"[A-Za-z][A-Za-z0-9_]+")


def _toks(s: str) -> set[str]:
    return {t.lower() for t in _TOK.findall(s or "") if len(t) > 2}


def _load_dataset(sources: list[str] | None) -> list[dict]:
    out: list[dict] = []
    for d in DATA_DIRS:
        if not d.exists():
            continue
        for f in d.glob("*.jsonl"):
            for line in f.open():
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                if sources and e.get("source") not in sources:
                    continue
                out.append(e)
    return out


def _stratified_sample(items: list[dict], n: int, *,
                       seed: int = 1337) -> list[dict]:
    rng = random.Random(seed)
    by_source: dict[str, list[dict]] = defaultdict(list)
    for it in items:
        by_source[it.get("source", "unknown")].append(it)
    per_source = max(1, n // max(1, len(by_source)))
    out: list[dict] = []
    for src, lst in by_source.items():
        rng.shuffle(lst)
        out.extend(lst[:per_source])
    rng.shuffle(out)
    return out[:n]


def _run_pipeline_for(elem: dict, *, pipeline: str,
                      max_tokens: int = 1500,
                      n_plans: int = 4,
                      utility: str | None = None,
                      run_label: str = "") -> dict:
    """Write the intent_md to a temp file, run the chosen pipeline,
    return the JSON sidecar.

    `utility` is passed through to cli_pro/cli_grounded as --utility
    so the bench can A/B test different weight configurations.
    `run_label` lets concurrent A/B runs avoid output-file collisions.
    """
    RUN_OUT_DIR.mkdir(parents=True, exist_ok=True)
    safe_id = elem["id"].replace("/", "_").replace("\\", "_")[:120]
    if run_label:
        safe_id = f"{run_label}__{safe_id}"
    intent_path = RUN_OUT_DIR / f"{safe_id}.intent.md"
    intent_path.write_text(elem["intent_md"])

    out_path = RUN_OUT_DIR / f"{safe_id}.{pipeline}.md"
    json_path = out_path.with_suffix(".json")

    if pipeline == "cli_pro":
        cmd = [
            sys.executable,
            str(ROOT / "verified-rollout" / "cli_pro.py"),
            str(intent_path),
            "--n-plans", str(n_plans),
            "--out", str(out_path),
        ]
        if utility:
            cmd += ["--utility", utility]
    elif pipeline == "cli_grounded":
        if not elem.get("repo_clone_url"):
            return {"_skipped": "no repo for grounded pipeline"}
        # We do NOT clone here — too expensive for bulk bench. Skip.
        return {"_skipped": "cli_grounded skipped in bulk bench"}
    elif pipeline == "cli_chaos":
        cmd = [
            sys.executable,
            str(ROOT / "verified-rollout" / "cli_chaos.py"),
            str(intent_path),
            "--mc-samples", "100",
            "--search-rounds", "1",
            "--search-k", "2",
            "--out", str(out_path),
        ]
    elif pipeline == "cli_feature":
        # Run the feature-planning pipeline against the same intent_md.
        # Real-data GT shape (files_touched / root_cause_keywords) is
        # judged by llm_judge.py the same way cli_pro output is — both
        # produce the {plans, winner, constraints} sidecar shape.
        cmd = [
            sys.executable,
            str(ROOT / "feature-planning" / "cli_feature.py"),
            str(intent_path),
            "--out", str(out_path),
        ]
    else:
        return {"_skipped": f"unknown pipeline {pipeline}"}

    env = dict(os.environ)
    env.setdefault("MODEL", "gpt-5.4-mini")
    env["MAX_TOKENS"] = str(max_tokens)

    started = time.time()
    res = subprocess.run(cmd, env=env, cwd=str(ROOT),
                         capture_output=True, text=True, timeout=300)
    elapsed = time.time() - started
    if res.returncode != 0:
        return {"_failed": True, "_stderr": res.stderr[-400:],
                "_elapsed_s": elapsed}
    if not json_path.exists():
        return {"_failed": True, "_no_sidecar": True, "_elapsed_s": elapsed}
    sidecar = json.loads(json_path.read_text())
    sidecar["_elapsed_s"] = elapsed
    return sidecar


def _winner_family(label: str | None) -> str:
    if not label:
        return "?"
    for fam in ("speed", "safety", "cost", "balanced"):
        if fam in label.lower():
            return fam
    return "other"


def _score_element(elem: dict, sidecar: dict, *, judge: bool = False,
                    judge_cfg=None) -> dict:
    """Compute per-element score: ground-truth-aware where possible.

    If judge=True, ALSO run an LLM judge (mirofish_lab-aware) and
    record verdict_judge alongside verdict (the literal-overlap one).
    """
    if sidecar.get("_skipped") or sidecar.get("_failed"):
        return {"id": elem["id"], "verdict": "error",
                "details": {k: v for k, v in sidecar.items() if k.startswith("_")}}
    plans = sidecar.get("plans") or {}
    smt = sidecar.get("smt") or {}
    chaos = sidecar.get("chaos") or {}
    pareto = sidecar.get("pareto") or {}
    winner = pareto.get("winner") or sidecar.get("winner") or (
        sidecar.get("recommendation") or {}).get("winner")
    n_plans = max(len(plans), len(smt), len(chaos))
    smt_feasible = sum(
        1 for v in smt.values() if isinstance(v, dict) and v.get("feasible", True)
    )

    gt = elem.get("ground_truth") or {}
    files_overlap = 0
    files_total = 0
    keyword_hits = 0
    keyword_total = 0
    expected_stakeholders_hit = 0
    expected_stakeholders_total = 0

    if winner and winner in plans:
        winner_plan = plans[winner]
        winner_text = json.dumps(winner_plan).lower()
        for f in (gt.get("files_touched") or []):
            files_total += 1
            if f.lower() in winner_text or Path(f).name.lower() in winner_text:
                files_overlap += 1
        for kw in (gt.get("root_cause_keywords") or []):
            keyword_total += 1
            if str(kw).lower() in winner_text:
                keyword_hits += 1

    constraints = sidecar.get("constraints") or []
    expected = (elem.get("metadata") or {}).get("expected_stakeholders") or []
    if expected:
        owners_present = {str(c.get("owner", "")).lower() for c in constraints}
        expected_stakeholders_total = len(expected)
        for stk in expected:
            for owner in owners_present:
                if stk.lower() in owner:
                    expected_stakeholders_hit += 1
                    break

    # Verdict heuristics
    if files_total > 0:
        ratio = files_overlap / files_total
        verdict = "caught" if ratio >= 0.5 else ("partial" if ratio > 0 else "missed")
    elif keyword_total > 0:
        ratio = keyword_hits / keyword_total
        verdict = "caught" if ratio >= 0.3 else ("partial" if ratio > 0 else "missed")
    elif expected_stakeholders_total > 0:
        ratio = expected_stakeholders_hit / expected_stakeholders_total
        verdict = "caught" if ratio >= 0.6 else ("partial" if ratio > 0 else "missed")
    else:
        verdict = "no_ground_truth"

    out = {
        "id": elem["id"],
        "source": elem["source"],
        "winner": winner,
        "winner_family": _winner_family(winner),
        "n_plans": n_plans,
        "smt_feasible_count": smt_feasible,
        "files_overlap": files_overlap,
        "files_total": files_total,
        "keyword_hits": keyword_hits,
        "keyword_total": keyword_total,
        "expected_stakeholders_hit": expected_stakeholders_hit,
        "expected_stakeholders_total": expected_stakeholders_total,
        "verdict": verdict,                 # literal-overlap verdict
        "elapsed_s": sidecar.get("_elapsed_s"),
    }
    if judge and not (sidecar.get("_skipped") or sidecar.get("_failed")):
        try:
            from llm_judge import judge_element
        except ImportError:
            sys.path.insert(0, str(ROOT / "dataset" / "bench"))
            from llm_judge import judge_element
        judge_result = judge_element(elem, sidecar, cfg=judge_cfg)
        out["verdict_judge"] = judge_result["verdict"]
        out["judge_rationale"] = judge_result["rationale"]
        out["judge_captured"] = judge_result["captured"]
        out["judge_missed"] = judge_result["missed"]
        out["judge_confidence"] = judge_result["judge_confidence"]
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the rollout pipeline against the bench dataset")
    parser.add_argument("--n", type=int, default=20)
    parser.add_argument("--sources", nargs="+", default=None,
                        help="Subset of sources to sample from")
    parser.add_argument("--pipeline", default="cli_pro",
                        choices=["cli_pro", "cli_chaos", "cli_feature"])
    parser.add_argument("--max-tokens", type=int, default=1500)
    parser.add_argument("--n-plans", type=int, default=4)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--judge", action="store_true",
                        help="Add an LLM judge verdict alongside the literal verdict")
    parser.add_argument("--utility", default=None,
                        help='UtilityWeights string for cli_pro, e.g. "fragility=0.2,coverage=0.25,..."')
    parser.add_argument("--run-label", default="",
                        help="Prefix for per-element run output files (used by A/B)")
    parser.add_argument("--ids-file", type=Path, default=None,
                        help="Path to a file with one element id per line. When "
                             "given, the bench runs ONLY on those elements (in "
                             "order) and ignores --n / --seed. Used by GEPA to "
                             "pin disjoint eval and holdout slices.")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)

    items = _load_dataset(args.sources)
    print(f"[load] {len(items)} elements available", file=sys.stderr)
    if args.ids_file and args.ids_file.exists():
        wanted = [
            line.strip()
            for line in args.ids_file.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        wanted_set = set(wanted)
        by_id = {it.get("id"): it for it in items}
        sample = [by_id[w] for w in wanted if w in by_id]
        missing = [w for w in wanted if w not in by_id]
        if missing:
            print(f"[ids-file] WARNING: {len(missing)} ids not found in corpus",
                  file=sys.stderr)
        print(f"[ids-file] resolved {len(sample)} of {len(wanted)} requested",
              file=sys.stderr)
    else:
        sample = _stratified_sample(items, args.n, seed=args.seed)
        print(f"[sample] {len(sample)} elements (stratified, seed {args.seed})",
              file=sys.stderr)

    judge_cfg = None
    if args.judge:
        sys.path.insert(0, str(ROOT))
        from mirofish_lab.config import load_config
        judge_cfg = load_config()

    scores = []
    for i, elem in enumerate(sample, 1):
        print(f"[run {i}/{len(sample)}] {elem['id'][:80]}", file=sys.stderr)
        try:
            sidecar = _run_pipeline_for(
                elem, pipeline=args.pipeline,
                max_tokens=args.max_tokens, n_plans=args.n_plans,
                utility=args.utility, run_label=args.run_label,
            )
        except Exception as e:
            sidecar = {"_failed": True, "_exc": str(e)}
        scores.append(_score_element(elem, sidecar, judge=args.judge,
                                     judge_cfg=judge_cfg))

    # Aggregate.
    by_source: dict[str, list[dict]] = defaultdict(list)
    for s in scores:
        by_source[s.get("source", "?")].append(s)

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    out_md = args.out or (REPORTS_DIR / f"bench_{timestamp}.md")
    out_json = out_md.with_suffix(".json")

    lines = [
        f"# Bench run — {timestamp}",
        "",
        f"_Pipeline: `{args.pipeline}`. Sample size: {args.n}. Seed: {args.seed}._",
        "",
        "## Per-source verdicts",
        "",
        "| Source | N | caught | partial | missed | error | no GT | smt feas. | avg time (s) |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for src, scs in sorted(by_source.items()):
        verdicts = Counter(s["verdict"] for s in scs)
        smt_feas = sum(s.get("smt_feasible_count", 0) for s in scs)
        smt_total = sum(s.get("n_plans", 0) for s in scs) or 1
        times = [s.get("elapsed_s") for s in scs if s.get("elapsed_s") is not None]
        avg_time = statistics.mean(times) if times else 0
        lines.append(
            f"| `{src}` | {len(scs)} | "
            f"{verdicts.get('caught', 0)} | {verdicts.get('partial', 0)} | "
            f"{verdicts.get('missed', 0)} | {verdicts.get('error', 0)} | "
            f"{verdicts.get('no_ground_truth', 0)} | "
            f"{smt_feas}/{smt_total} ({100*smt_feas/smt_total:.0f}%) | "
            f"{avg_time:.1f} |"
        )

    lines.append("")
    lines.append("## Winner-family distribution per source")
    lines.append("")
    lines.append("| Source | speed | safety | cost | balanced | other / ? |")
    lines.append("|---|---|---|---|---|---|")
    for src, scs in sorted(by_source.items()):
        fams = Counter(s.get("winner_family", "?") for s in scs)
        lines.append(
            f"| `{src}` | {fams.get('speed', 0)} | {fams.get('safety', 0)} | "
            f"{fams.get('cost', 0)} | {fams.get('balanced', 0)} | "
            f"{fams.get('other', 0) + fams.get('?', 0)} |"
        )

    overall = Counter(s["verdict"] for s in scores)
    lines.append("")
    lines.append(f"## Overall (literal scorer): caught={overall.get('caught', 0)}, "
                 f"partial={overall.get('partial', 0)}, "
                 f"missed={overall.get('missed', 0)}, "
                 f"error={overall.get('error', 0)}, "
                 f"no_GT={overall.get('no_ground_truth', 0)}")

    if args.judge:
        overall_j = Counter(s.get("verdict_judge", "?") for s in scores)
        lines.append("")
        lines.append("## Overall (LLM judge)")
        lines.append("")
        lines.append(
            f"caught={overall_j.get('caught', 0)}, "
            f"partial={overall_j.get('partial', 0)}, "
            f"missed={overall_j.get('missed', 0)}, "
            f"no_GT={overall_j.get('no_ground_truth', 0)}"
        )
        lines.append("")
        lines.append("## Per-element verdicts (literal vs judge)")
        lines.append("")
        lines.append("| Element | literal | judge | judge rationale |")
        lines.append("|---|---|---|---|")
        for s in scores:
            lit = s.get("verdict", "—")
            jud = s.get("verdict_judge", "—")
            rat = (s.get("judge_rationale", "") or "")[:80]
            lines.append(
                f"| `{s.get('id', '?')[:60]}` | {lit} | {jud} | {rat} |"
            )

    out_md.write_text("\n".join(lines))
    out_json.write_text(json.dumps({
        "timestamp": timestamp,
        "args": vars(args) | {"out": str(args.out) if args.out else None},
        "scores": scores,
    }, indent=2, default=str))
    print(f"\n[done] wrote {out_md} and {out_json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
