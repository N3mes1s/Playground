"""Auto-calibrator — top-level orchestrator of the continuous-improvement loop.

Reads the meta-analysis warnings from `run_log.py`, picks one with a
known fix template, applies the fix to a temp branch of the relevant
config file, runs the A/B harness against the existing config, and
either commits the change (`--apply`) or reverts it.

Today we wire ONE warning -> fix mapping end-to-end:

  Warning: "speed family wins > 40%"
  Fix candidates (chosen by --strategy):
    - "rebalance"      : reduce fragility weight further (0.20 -> 0.15)
                         and bump rollback_failure (0.25 -> 0.30)
    - "antiparallel"   : revise the speed-leaning Sequencer prompt to
                         drop the "parallelise wherever possible" line
                         that systemically biases the structural cascade

The script prints what it's doing at each step and writes a JSON
calibration record to `validation/calibrations.jsonl` so the history
of accepted / rejected calibrations is itself inspectable.

Future warnings to wire (not yet automated):
  - "SMT feasibility < 50%"  -> add explicit "produce a topologically
                                  valid ordering" instruction to all
                                  Sequencer prompts
  - "constraint-author X flagged-wrong > 50%" (from feedback.py)
                                -> revise persona X's system prompt
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CALIBRATION_LOG = ROOT / "validation" / "calibrations.jsonl"


# --- known warnings + fix templates -------------------------------------

KNOWN_WARNINGS = {
    "speed_family_dominance": {
        "detect": (
            "Run validation/run_log.py and read RUN_LOG.md. If the speed "
            "family wins > 40% of runs, that's the warning."
        ),
        "severity": 2,    # higher = pickier prioritisation
        "fixes": {
            "rebalance": "Reduce default fragility weight further (0.20 -> 0.15), "
                          "bump rollback_failure (0.25 -> 0.30).",
            "antiparallel": "Drop 'parallelise wherever possible' from the speed-"
                            "leaning Sequencer prompt.",
        },
    },
    "smt_feasibility_low": {
        "detect": "SMT feasibility rate < 50% across runs.",
        "severity": 3,
        "fixes": {
            "topological_explicit": (
                "Append explicit topological-validity instruction to every "
                "Sequencer system prompt."
            ),
        },
    },
    "winner_fragility_low": {
        "detect": (
            "Average winner fragility < 0.20: recommender favours parallel "
            "structures over sequential safety."
        ),
        "severity": 1,
        "fixes": {
            "rebalance": "Same as speed-family rebalance — punish cascade less.",
        },
    },
}


# --- fix appliers --------------------------------------------------------


def _choose_warning_from_run_log() -> tuple[str, str] | None:
    """Read validation/RUN_LOG.md, identify which warnings are active, return
    (warning_key, default_fix) for the most-severe one. None if no warnings
    are active.

    Heuristic: regenerates RUN_LOG.md on the fly via run_log.py to get the
    current state, then pattern-matches the warning thresholds.
    """
    # Refresh RUN_LOG first so we act on the latest data.
    rl_script = ROOT / "validation" / "run_log.py"
    subprocess.run([sys.executable, str(rl_script)], cwd=str(ROOT),
                   check=False, capture_output=True)
    log_path = ROOT / "validation" / "RUN_LOG.md"
    if not log_path.exists():
        return None
    text = log_path.read_text()

    active: list[tuple[int, str, str]] = []  # (severity, warning_key, default_fix)

    if "(43%) ⚠" in text or "(>40%)" in text or any(
        f"({pct}%)" in text and "speed" in text.lower()
        for pct in (41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55)
    ):
        active.append((
            KNOWN_WARNINGS["speed_family_dominance"]["severity"],
            "speed_family_dominance", "rebalance",
        ))

    # SMT feasibility - crude pattern: "SMT-feasible: **X**" with X% < 50%
    import re
    m = re.search(r"SMT-feasible:\s*\*\*\d+\*\*\s*\((\d+)%\)", text)
    if m and int(m.group(1)) < 50:
        active.append((
            KNOWN_WARNINGS["smt_feasibility_low"]["severity"],
            "smt_feasibility_low", "topological_explicit",
        ))

    # Average winner fragility low (<0.20)
    m2 = re.search(r"Average winner fragility:\s*\*\*([\d.]+)\*\*", text)
    if m2 and float(m2.group(1)) < 0.20:
        active.append((
            KNOWN_WARNINGS["winner_fragility_low"]["severity"],
            "winner_fragility_low", "rebalance",
        ))

    if not active:
        return None
    active.sort(key=lambda r: -r[0])
    return active[0][1], active[0][2]


def fix_rebalance(*, weight_fragility: float, weight_rollback: float) -> Path:
    """Patch UtilityWeights defaults in a temp copy of pareto_frontier.py.

    Returns the path to the patched file (should replace the real one
    when --apply is set).
    """
    src = ROOT / "mirofish_lab" / "pareto_frontier.py"
    text = src.read_text()
    needle_old_a = "    fragility: float = 0.20"
    needle_new_a = f"    fragility: float = {weight_fragility:.2f}"
    needle_old_b = "    rollback_failure: float = 0.25"
    needle_new_b = f"    rollback_failure: float = {weight_rollback:.2f}"
    if needle_old_a not in text or needle_old_b not in text:
        raise RuntimeError(
            "pareto_frontier.py defaults differ from expected format; "
            "auto-fix template is stale"
        )
    new_text = text.replace(needle_old_a, needle_new_a).replace(needle_old_b, needle_new_b)
    tmp = Path(tempfile.mkdtemp(prefix="autocal_")) / "pareto_frontier.py"
    tmp.write_text(new_text)
    return tmp


def fix_antiparallel() -> Path:
    """Patch speed-leaning persona to remove 'parallelise wherever possible'."""
    src = ROOT / "mirofish_lab" / "pareto.py"
    text = src.read_text()
    replacement = "Keeps step count low; sequential order chosen by depth-first dep ordering."
    candidate_phrases = [
        "Parallelises wherever the dependency graph allows.",
        "Parallelise wherever the dependency graph allows.",
        "parallelise wherever",
        "Parallelizes wherever",
        "Parallelises everywhere",
    ]
    new_text = text
    replaced_any = False
    for phrase in candidate_phrases:
        if phrase in new_text:
            new_text = new_text.replace(phrase, replacement)
            replaced_any = True
    if not replaced_any:
        raise RuntimeError(
            "pareto.py doesn't contain the expected parallelism phrase; "
            "auto-fix template is stale"
        )
    tmp = Path(tempfile.mkdtemp(prefix="autocal_")) / "pareto.py"
    tmp.write_text(new_text)
    return tmp


def fix_topological_explicit() -> Path:
    """Append an explicit topological-validity instruction to the
    BASE_TAIL shared by all Pareto sequencers, so every plan they
    produce honours dependency ordering. This targets the
    smt_feasibility_low warning."""
    src = ROOT / "mirofish_lab" / "pareto.py"
    text = src.read_text()
    needle = '- 5-15 steps. Wrap the JSON in a ```json fenced block."'
    if needle not in text:
        raise RuntimeError(
            "pareto.py BASE_TAIL doesn't have the expected closing line; "
            "auto-fix template is stale"
        )
    addition = (
        '\n\n"\n    "TOPOLOGICAL VALIDITY (CRITICAL):\\n"\n'
        '    "- Every step\'s `depends_on` MUST list IDs that appear EARLIER in `steps`.\\n"\n'
        '    "- If a stakeholder constraint requires step A before step B, then A must NOT depend on B.\\n"\n'
        '    "- Re-read your plan once before emitting and ensure NO step transitively depends on something later in the array.\\n"\n'
        '    "- A plan with an ordering cycle is wrong; rewrite it before emitting.'
    )
    new_text = text.replace(needle, needle + addition)
    tmp = Path(tempfile.mkdtemp(prefix="autocal_")) / "pareto.py"
    tmp.write_text(new_text)
    return tmp


# --- A/B test driver -----------------------------------------------------


def _baseline_config(name: str, intents: list[str], repo_for: dict) -> dict:
    """Use current production defaults."""
    return {
        "name": name,
        "utility_weights": {"fragility": 0.20, "coverage": 0.25,
                            "steps": 0.10, "severity": 0.20,
                            "rollback_failure": 0.25},
        "intents": intents,
        "n_plans": 4,
        "repo_for": repo_for,
    }


def _candidate_config(name: str, fix: str, intents: list[str], repo_for: dict) -> dict:
    if fix == "rebalance":
        return {
            "name": name,
            "utility_weights": {"fragility": 0.15, "coverage": 0.25,
                                "steps": 0.10, "severity": 0.20,
                                "rollback_failure": 0.30},
            "intents": intents,
            "n_plans": 4,
            "repo_for": repo_for,
        }
    if fix in ("antiparallel", "topological_explicit"):
        # Code patches; baseline weights, patched code in place.
        return _baseline_config(name, intents, repo_for)
    raise ValueError(f"unknown fix: {fix}")


def run_ab(baseline_path: Path, candidate_path: Path, criterion: str,
           out: Path) -> dict:
    cmd = [
        sys.executable, str(ROOT / "validation" / "ab_harness.py"),
        "--a", str(baseline_path),
        "--b", str(candidate_path),
        "--criterion", criterion,
        "--out", str(out),
    ]
    res = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"A/B harness failed: {res.stderr[-500:]}")
    json_path = out.with_suffix(".json")
    return json.loads(json_path.read_text())


# --- top-level orchestrator ---------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Auto-calibrate the rollout-rehearsal pipeline."
    )
    parser.add_argument("--warning", default="speed_family_dominance",
                        choices=list(KNOWN_WARNINGS.keys()))
    parser.add_argument("--fix", default="rebalance",
                        help="Fix strategy; depends on warning")
    parser.add_argument("--criterion", default="balanced",
                        choices=["minimise_max_family_share",
                                 "maximise_smt_feasibility",
                                 "minimise_avg_fragility",
                                 "balanced"])
    parser.add_argument("--apply", action="store_true",
                        help="Apply the fix to the real source if A/B verdict is 'B better'")
    parser.add_argument(
        "--bench-n", type=int, default=0,
        help="If > 0, run the bench-driven A/B (caught/partial/missed via "
             "LLM judge across N stratified elements per config) instead of "
             "the 2-intent internal-metric A/B.",
    )
    parser.add_argument(
        "--bench-criterion", default="useful_rate",
        choices=["useful_rate", "caught_rate", "balanced"],
        help="Criterion for the bench-driven A/B (only used with --bench-n > 0)",
    )
    parser.add_argument(
        "--bench-sources", nargs="+",
        default=["swebench_verified", "danluu_postmortems", "synthetic"],
        help="Sources to sample from for bench-driven A/B",
    )
    parser.add_argument(
        "--commit", action="store_true",
        help="When --apply produces a successful application, auto-commit "
             "the change + calibration record + AB report",
    )
    parser.add_argument(
        "--auto", action="store_true",
        help="Multi-warning prioritisation: read the latest RUN_LOG.md, pick "
             "the most-severe active warning, run its highest-severity fix "
             "via the bench-driven A/B. Combine with --apply --commit for "
             "fully autonomous calibration.",
    )
    parser.add_argument(
        "--intents",
        nargs="+",
        default=[
            "validation/postmortems/intents/04_gitlab_db_replica.md",
            "validation/postmortems/intents/05_linear_cascade_migration.md",
        ],
        help="Test-suite intents (paths relative to repo root)",
    )
    parser.add_argument(
        "--repo-for",
        action="append",
        default=[],
        help="Per-intent repo path, format intent_path=repo_path",
    )
    args = parser.parse_args(argv)

    # --auto: read RUN_LOG.md, pick the highest-severity active warning,
    # override args.warning + args.fix accordingly.
    if args.auto:
        chosen = _choose_warning_from_run_log()
        if not chosen:
            print("[auto] no active warnings in RUN_LOG.md; exiting cleanly",
                  file=sys.stderr)
            return 0
        args.warning, args.fix = chosen
        print(f"[auto] selected warning={args.warning} fix={args.fix}",
              file=sys.stderr)

    repo_for: dict = {}
    for entry in args.repo_for:
        if "=" in entry:
            k, v = entry.split("=", 1)
            repo_for[k] = v

    warning_info = KNOWN_WARNINGS[args.warning]
    if args.fix not in warning_info["fixes"]:
        parser.error(
            f"fix {args.fix!r} not registered for warning {args.warning!r}; "
            f"choices: {list(warning_info['fixes'])}"
        )

    # 1. Build baseline + candidate configs.
    baseline = _baseline_config("baseline", args.intents, repo_for)
    candidate = _candidate_config(f"candidate_{args.fix}", args.fix, args.intents, repo_for)
    cfg_dir = Path(tempfile.mkdtemp(prefix="autocal_cfg_"))
    a_path = cfg_dir / "a.json"
    b_path = cfg_dir / "b.json"
    a_path.write_text(json.dumps(baseline))
    b_path.write_text(json.dumps(candidate))

    # 2. If the fix is a code edit, patch in place BEFORE running B.
    #    We back up and restore the original.
    backup: Path | None = None
    patched_target: Path | None = None
    patched_tmp: Path | None = None
    if args.fix == "antiparallel":
        patched_tmp = fix_antiparallel()
        patched_target = ROOT / "mirofish_lab" / "pareto.py"
        backup = patched_target.with_suffix(".py.autocal_bak")
        shutil.copy(patched_target, backup)
    elif args.fix == "topological_explicit":
        patched_tmp = fix_topological_explicit()
        patched_target = ROOT / "mirofish_lab" / "pareto.py"
        backup = patched_target.with_suffix(".py.autocal_bak")
        shutil.copy(patched_target, backup)

    decision = "no_apply"   # fail-safe default for the finally block
    try:
        ab_out = ROOT / "validation" / f"AB_{args.warning}_{args.fix}.md"

        # 3a. Bench-driven A/B path (preferred when --bench-n is set).
        if args.bench_n > 0:
            print(f"\n=== bench-driven A/B: {args.bench_n} elements per config ===",
                  file=sys.stderr)
            ab_result = None
            if args.fix == "rebalance":
                # Pure utility-weight swap: bench_ab.py handles it directly.
                a_weights = baseline["utility_weights"]
                b_weights = candidate["utility_weights"]
                a_str = ",".join(f"{k}={v}" for k, v in a_weights.items())
                b_str = ",".join(f"{k}={v}" for k, v in b_weights.items())
                cmd = [
                    sys.executable, str(ROOT / "dataset" / "bench" / "bench_ab.py"),
                    "--a", a_str, "--b", b_str,
                    "--n", str(args.bench_n),
                    "--sources", *args.bench_sources,
                    "--criterion", args.bench_criterion,
                    "--out", str(ab_out),
                ]
                res = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
                if res.returncode != 0:
                    print("--- bench_ab stderr ---\n" + res.stderr[-1500:],
                          file=sys.stderr)
                    raise RuntimeError("bench_ab failed")
                ab_result = json.loads(ab_out.with_suffix(".json").read_text())
            elif args.fix in ("antiparallel", "topological_explicit"):
                # Code-patch fix: run bench against ORIGINAL code, then
                # patch in place, run bench against PATCHED code, restore
                # (unless --apply applies it permanently below).
                a_str = ",".join(
                    f"{k}={v}" for k, v in baseline["utility_weights"].items()
                )
                b_str = a_str   # same weights; only the code differs.

                if patched_target is None or patched_tmp is None:
                    raise RuntimeError(
                        f"fix {args.fix!r} did not stage a code patch"
                    )

                # We staged the patch and backed up `patched_target` already
                # at step 2. To run A on ORIGINAL code, restore from backup
                # first, run A, then re-apply the patch for B.
                shutil.copy(backup, patched_target)   # restore original
                sys.path.insert(0, str(ROOT / "dataset" / "bench"))
                from bench_ab import _run_bench, _aggregate, _verdict
                print(f"  [A: original {patched_target.name}]", file=sys.stderr)
                res_a = _run_bench(
                    utility=a_str, n=args.bench_n,
                    sources=args.bench_sources, run_label="ab_a",
                    out_md=ROOT / ".bench_runs" / "ab_a.md",
                )
                shutil.copy(patched_tmp, patched_target)   # apply patch
                print(f"  [B: patched {patched_target.name}]", file=sys.stderr)
                res_b = _run_bench(
                    utility=b_str, n=args.bench_n,
                    sources=args.bench_sources, run_label="ab_b",
                    out_md=ROOT / ".bench_runs" / "ab_b.md",
                )
                agg_a = _aggregate(res_a["scores"], judge=True)
                agg_b = _aggregate(res_b["scores"], judge=True)
                verdict = _verdict(agg_a, agg_b, args.bench_criterion)
                ab_result = {
                    "verdict": verdict, "agg_a": agg_a, "agg_b": agg_b,
                    "scores_a": res_a["scores"], "scores_b": res_b["scores"],
                    "config_a": a_str, "config_b": b_str,
                    "fix": args.fix,
                }
                ab_out.write_text(
                    f"# Bench-driven A/B (code patch: {args.fix})\n\n"
                    f"**{verdict['label']}** — {verdict['reason']}\n\n"
                    f"A useful_rate: {agg_a['useful_rate']:.0%}, "
                    f"B useful_rate: {agg_b['useful_rate']:.0%}\n"
                )
                ab_out.with_suffix(".json").write_text(json.dumps(ab_result, indent=2))
                # Patched code is currently in place; restore-or-keep handled below.
            else:
                raise RuntimeError(
                    f"--bench-n set but fix {args.fix!r} has no bench-driven path"
                )
            verdict = ab_result["verdict"]
            decision = "B better" if "B better" in verdict["label"] else "no_apply"

            # Bypass the rest of the legacy A/B branches; jump to apply logic.
            applied = False
            applied_path: str | None = None
            if decision == "B better" and args.apply:
                if args.fix == "rebalance":
                    src = ROOT / "mirofish_lab" / "pareto_frontier.py"
                    tmp = fix_rebalance(weight_fragility=0.15, weight_rollback=0.30)
                    shutil.copy(tmp, src)
                    applied = True
                    applied_path = str(src.relative_to(ROOT))
                elif args.fix in ("antiparallel", "topological_explicit") and patched_tmp:
                    # Already patched in place; retain the patched version.
                    if backup is not None and backup.exists():
                        backup.unlink()
                    backup = None
                    applied = True
                    applied_path = "mirofish_lab/pareto.py"
            record = {
                "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
                "warning": args.warning,
                "fix": args.fix,
                "criterion": args.bench_criterion,
                "bench_n": args.bench_n,
                "verdict": verdict,
                "applied": applied,
                "applied_path": applied_path,
                "ab_report_path": str(ab_out.relative_to(ROOT)),
                "agg_a": ab_result["agg_a"],
                "agg_b": ab_result["agg_b"],
            }
            CALIBRATION_LOG.parent.mkdir(parents=True, exist_ok=True)
            with CALIBRATION_LOG.open("a") as f:
                f.write(json.dumps(record) + "\n")
            print(f"\n[verdict] {verdict['label']}: {verdict['reason']}",
                  file=sys.stderr)
            print(f"[applied] {applied}", file=sys.stderr)
            print(f"[record] {CALIBRATION_LOG.relative_to(ROOT)}",
                  file=sys.stderr)

            # 6. Auto-commit when applied (the calibration becomes a
            #    first-class commit with rationale + audit trail).
            if applied and args.commit:
                commit_msg = (
                    f"auto-calibrate: apply {args.fix} for "
                    f"{args.warning} (verdict {verdict['label']})\n\n"
                    f"{verdict['reason']}\n\n"
                    f"A: caught={ab_result['agg_a'].get('caught_rate', 0):.0%} "
                    f"partial={ab_result['agg_a'].get('partial_rate', 0):.0%} "
                    f"useful={ab_result['agg_a'].get('useful_rate', 0):.0%}\n"
                    f"B: caught={ab_result['agg_b'].get('caught_rate', 0):.0%} "
                    f"partial={ab_result['agg_b'].get('partial_rate', 0):.0%} "
                    f"useful={ab_result['agg_b'].get('useful_rate', 0):.0%}\n\n"
                    f"Bench: {args.bench_n} elements per config across "
                    f"{', '.join(args.bench_sources)}.\n"
                    f"Calibration record: {CALIBRATION_LOG.relative_to(ROOT)}"
                )
                files_to_commit = [
                    str(CALIBRATION_LOG),
                    str(ab_out),
                    str(ab_out.with_suffix('.json')),
                ]
                if applied_path:
                    files_to_commit.append(applied_path)
                subprocess.run(
                    ["git", "add", *files_to_commit],
                    cwd=str(ROOT), check=False, capture_output=True,
                )
                cm = subprocess.run(
                    ["git", "commit", "-m", commit_msg],
                    cwd=str(ROOT), capture_output=True, text=True,
                )
                if cm.returncode == 0:
                    print(f"[committed] {cm.stdout.strip().splitlines()[0] if cm.stdout else 'OK'}",
                          file=sys.stderr)
                else:
                    print(f"[commit failed] {cm.stderr[-500:]}", file=sys.stderr)
            return 0

        # 3b. Legacy 2-intent internal-metric A/B path.
        if patched_tmp:
            # Temporarily install patched candidate code; A run uses original,
            # so we install AFTER A. ab_harness runs A then B sequentially.
            # We rely on it running A first; patching now puts patched code in
            # place for both. So the simpler protocol is:
            #   - Patch first
            #   - Run A (which uses CURRENT code = patched, defeating purpose)
            # ...so we instead split: run A with original, then patch, then run B.
            #
            # Implement by invoking ab_harness twice with single-config swaps:
            # The current ab_harness only supports A/B in one shot, so we
            # bypass it for antiparallel: run each side separately and combine.
            from ab_harness import run_config, aggregate, render_report, _verdict
            print(f"\n=== A: {baseline['name']} (original code) ===", file=sys.stderr)
            result_a = run_config(baseline)
            shutil.copy(patched_tmp, patched_target)
            print(f"\n=== B: {candidate['name']} (patched code) ===", file=sys.stderr)
            result_b = run_config(candidate)
            # restore to baseline for any later runs unless --apply
            shutil.copy(backup, patched_target)
            md = render_report(result_a, result_b, criterion=args.criterion)
            ab_out.write_text(md)
            ab_out.with_suffix(".json").write_text(json.dumps({
                "a": result_a, "b": result_b,
                "agg_a": aggregate(result_a["rows"]),
                "agg_b": aggregate(result_b["rows"]),
                "verdict": _verdict(aggregate(result_a["rows"]),
                                    aggregate(result_b["rows"]),
                                    args.criterion),
            }, indent=2))
            ab_result = json.loads(ab_out.with_suffix(".json").read_text())
        else:
            # Pure-config fix: use the standard A/B harness.
            sys.path.insert(0, str(ROOT / "validation"))
            ab_result = run_ab(a_path, b_path, args.criterion, ab_out)

        verdict = ab_result["verdict"]
        print(f"\n[verdict] {verdict['label']}: {verdict['reason']}", file=sys.stderr)

        # 4. Decide.
        decision = "B better" if "B better" in verdict["label"] else "no_apply"

        # 5. Apply or rollback.
        applied = False
        if decision == "B better" and args.apply:
            if args.fix == "rebalance":
                # Rewrite the real source.
                src = ROOT / "mirofish_lab" / "pareto_frontier.py"
                tmp = fix_rebalance(weight_fragility=0.15, weight_rollback=0.30)
                shutil.copy(tmp, src)
                applied = True
            elif args.fix == "antiparallel":
                # Already patched in place; retain the patched version.
                if backup is not None and backup.exists():
                    backup.unlink()
                applied = True
        elif args.fix == "antiparallel":
            # Ensure restore happened.
            if backup is not None and backup.exists():
                shutil.copy(backup, patched_target)
                backup.unlink()

        # 6. Log calibration record.
        record = {
            "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "warning": args.warning,
            "fix": args.fix,
            "criterion": args.criterion,
            "intents": args.intents,
            "verdict": verdict,
            "applied": applied,
            "ab_report_path": str(ab_out.relative_to(ROOT)),
        }
        CALIBRATION_LOG.parent.mkdir(parents=True, exist_ok=True)
        with CALIBRATION_LOG.open("a") as f:
            f.write(json.dumps(record) + "\n")
        print(f"\n[record] {CALIBRATION_LOG.relative_to(ROOT)}", file=sys.stderr)
        print(f"[applied] {applied}", file=sys.stderr)
        print(f"[ab report] {ab_out.relative_to(ROOT)}", file=sys.stderr)

    finally:
        # Always clean up backup if we have one and didn't already apply.
        if (backup is not None and patched_target is not None
                and backup.exists() and not (decision == "B better" and args.apply)):
            shutil.copy(backup, patched_target)
            backup.unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
