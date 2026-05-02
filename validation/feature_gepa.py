"""GEPA-style optimizer for feature-planning sequencer prompts.

Mirror of validation/gepa_optimizer.py, scoped to the feature pipeline.
Targets the feature_launch_strategy_mismatch warning specifically: 29%
of plans pick a launch_strategy that doesn't match GT, and weight
tuning was empirically shown not to fix it (see calibrations.jsonl
2026-05-02 record after the riskward rebalance).

Architecture (identical to rollout GEPA):
  1. Collect failure traces from validation/FEATURE_BASELINE_*.json
     (scores where literal.launch_strategy_ok=False).
  2. Ask a reflector LLM to diagnose the dominant failure mode and
     propose 2-3 candidate extension_text mutations to FEATURE_SEQUENCERS.
  3. Bench-evaluate each candidate by running feature_bench with the
     candidate text exported via MIROFISH_FEATURE_TAIL_EXTRA env var.
     Source file mirofish_lab/feature_planning.py is NEVER patched.
  4. Pick the winner that maximises composite score:
       useful_rate + 0.5 * launch_strategy_ok_rate - 0.5 * max_family_share
  5. If --apply, write winner to mirofish_lab/feature_pareto_extra.txt.
     Per-cycle env-var path keeps source clean across stop-hook restarts.

Defaults (n>=20 floor encoded same as rollout GEPA after cycle-4
retrospective):
  --n 20         per-candidate eval slice
  --holdout-n 12 disjoint validation slice (skip with 0)
  --max-candidates 2

Cost: ~$2.50 / cycle on gpt-5.4-mini (1 reflector call + ~50 bench rows).
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "dataset" / "bench"))

from mirofish_lab.config import load_config, make_openai_client


REFLECTOR_SYSTEM_PROMPT = """\
You are a prompt engineer optimising LLM Sequencers that produce
feature-shipping plans (feature flags / gradual rollouts / beta
programs / full releases). You read failure traces from a bench
evaluation where the Sequencer picked the WRONG launch_strategy
relative to ground truth. Your job: propose textual extensions to
the FEATURE_SEQUENCERS prompts that would fix the observed
launch_strategy mismatch failure mode.

You output ONLY a JSON object wrapped in a ```json fenced block:

{
  "diagnosis": "<= 240 chars: why is launch_strategy mismatch happening?",
  "candidates": [
    {
      "name": "short label (kebab-case, <= 24 chars)",
      "theory": "<= 200 chars: what this mutation will fix and why",
      "extension_text": "raw text appended after BASE_TAIL of every FEATURE_SEQUENCER prompt"
    }
  ]
}

Rules for `extension_text`:
- Plain text (NOT Python source). Use real newlines.
- Should start with `\\n` for visual separation.
- Use ALL CAPS HEADER lines like "LAUNCH STRATEGY DECISION:" so the
  rule stands out in the combined prompt.
- 6-12 short bullet lines.
- The five strategies are: feature_flag, gradual_rollout,
  dark_launch, beta_program, full_release. Plus not_applicable for
  internal-only steps.
- Be SPECIFIC about WHEN to pick each. "Use feature_flag for new
  user-facing functionality" + "use full_release when the change is
  required by compliance / contract / regulator" is good. "Pick
  carefully" is bad.

Rules for diversity:
- Propose 2 DIFFERENT THEORIES. Don't write variations of the same rule.
- Cite the specific failure mode from the traces ("4 of 6 mismatches
  picked feature_flag for compliance_audit cases where GT was full_release").

Output ONLY the JSON.
"""


# --- trace collection -----------------------------------------------------


def _collect_traces(min_traces: int = 8) -> tuple[list[dict], Path]:
    """Pull launch_strategy mismatch traces from the freshest
    FEATURE_BASELINE_*.json file. Returns (traces, source_path).
    """
    candidates: list[tuple[int, Path, dict]] = []
    for p in (ROOT / "validation").glob("FEATURE_BASELINE_*.json"):
        try:
            j = json.loads(p.read_text())
        except Exception:
            continue
        scores = j.get("scores") or []
        if scores:
            candidates.append((len(scores), p, j))
    if not candidates:
        raise RuntimeError("no FEATURE_BASELINE_*.json with scores; "
                           "run dataset/bench/feature_bench.py first")
    candidates.sort(key=lambda t: -t[0])
    _, src, j = candidates[0]

    traces: list[dict] = []
    for s in j.get("scores", []):
        if "literal" not in s:
            continue
        lit = s["literal"]
        if lit.get("launch_strategy_ok") is False:
            traces.append({
                "id": s["id"],
                "feature_kind": s.get("feature_kind"),
                "context": s.get("context"),
                "winner": s.get("winner"),
                "stakeholders_hit": lit.get("stakeholders_hit"),
                "stakeholders_total": lit.get("stakeholders_total"),
                "axes_hit": lit.get("axes_hit"),
                "axes_total": lit.get("axes_total"),
                "days_in_band": lit.get("days_in_band"),
                "regulated": lit.get("regulated"),
                "judge_verdict": (s.get("judge") or {}).get("verdict"),
                "judge_rationale": (s.get("judge") or {}).get("rationale", "")[:200],
                "judge_missed": (s.get("judge") or {}).get("missed", []),
            })
    print(f"[trace] collected {len(traces)} launch_strategy mismatches "
          f"from {src.name}", file=sys.stderr)
    if len(traces) < min_traces:
        print(f"[trace] WARNING: only {len(traces)} mismatches available "
              f"(min {min_traces}); reflector signal may be thin",
              file=sys.stderr)
    # Cap to keep the reflector context reasonable
    return traces[:20], src


# --- reflector ------------------------------------------------------------


_FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)```")


def _extract_json(text: str) -> dict | None:
    m = _FENCE_RE.search(text or "")
    body = m.group(1) if m else (text or "")
    try:
        return json.loads(body)
    except Exception:
        return None


def _call_reflector(traces: list[dict], cfg, max_candidates: int) -> dict:
    user_msg = (
        "# Failure traces (launch_strategy_ok=False)\n\n"
        f"```json\n{json.dumps(traces, indent=2)[:8000]}\n```\n\n"
        f"Propose up to {max_candidates} candidate extension_text "
        "mutations per your schema. Output JSON only."
    )
    client = make_openai_client(cfg)
    resp = client.chat.completions.create(
        model=cfg.model,
        messages=[
            {"role": "system", "content": REFLECTOR_SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        max_completion_tokens=2000,
    )
    text = resp.choices[0].message.content or ""
    parsed = _extract_json(text) or {}
    return parsed


# --- bench evaluation -----------------------------------------------------


def _bench_with_extension(
    extension_text: str | None,
    *,
    n: int,
    seed: int,
    label: str,
    out_md: Path,
) -> dict:
    """Run feature_bench in a subprocess with MIROFISH_FEATURE_TAIL_EXTRA
    set to `extension_text`. None means incumbent (no extension)."""
    env = os.environ.copy()
    if extension_text is not None:
        env["MIROFISH_FEATURE_TAIL_EXTRA"] = extension_text
    # When incumbent, force-clear the env var so a stale value can't bleed in.
    elif "MIROFISH_FEATURE_TAIL_EXTRA" in env:
        env.pop("MIROFISH_FEATURE_TAIL_EXTRA")

    cmd = [
        sys.executable, str(ROOT / "dataset" / "bench" / "feature_bench.py"),
        "--n", str(n), "--seed", str(seed), "--judge",
        "--out", str(out_md),
    ]
    print(f"[bench:{label}] starting {n}-element bench (seed {seed})",
          file=sys.stderr)
    t0 = time.time()
    res = subprocess.run(cmd, capture_output=True, text=True, env=env,
                         timeout=3600)
    elapsed = time.time() - t0
    if res.returncode != 0:
        raise RuntimeError(
            f"feature_bench failed for {label}: {res.stderr[-1000:]}"
        )
    j = json.loads(out_md.with_suffix(".json").read_text())
    print(f"[bench:{label}] done in {elapsed:.0f}s", file=sys.stderr)
    return j


def _aggregate(j: dict) -> dict:
    scores = j.get("scores") or []
    n = len(scores)
    lit = j.get("literal_verdicts") or {}
    jud = j.get("judge_verdicts") or {}
    winners = Counter(s.get("winner", "?") for s in scores
                      if s.get("winner"))
    strat_ok = sum(1 for s in scores
                   if "literal" in s
                   and s["literal"].get("launch_strategy_ok"))
    return {
        "n": n,
        "literal_caught_rate":  lit.get("caught", 0) / max(1, n),
        "literal_useful_rate":  (lit.get("caught", 0) + lit.get("partial", 0)) / max(1, n),
        "judge_caught_rate":    jud.get("caught", 0) / max(1, n),
        "judge_useful_rate":    (jud.get("caught", 0) + jud.get("partial", 0)) / max(1, n),
        "max_family_share":     max(winners.values()) / max(1, n) if winners else 0.0,
        "launch_strategy_ok_rate": strat_ok / max(1, n),
    }


def _composite(agg: dict) -> float:
    return (agg["judge_useful_rate"]
            + 0.5 * agg["launch_strategy_ok_rate"]
            - 0.5 * agg["max_family_share"])


# --- cycle ----------------------------------------------------------------


def run_cycle(
    *, n: int, seed: int, holdout_n: int, max_candidates: int,
) -> dict:
    cfg = load_config()
    traces, trace_src = _collect_traces()
    if not traces:
        return {"error": "no failure traces; nothing to optimise"}

    if n < 20:
        print(f"[gepa] WARNING: --n={n} below n=20 floor learned from "
              "rollout cycle 4; winners NOT for apply.", file=sys.stderr)

    print("[gepa] calling reflector ...", file=sys.stderr)
    parsed = _call_reflector(traces, cfg, max_candidates)
    diagnosis = parsed.get("diagnosis", "(none)")
    candidates = parsed.get("candidates") or []
    candidates = candidates[:max_candidates]
    print(f"[gepa] diagnosis: {diagnosis}", file=sys.stderr)
    for c in candidates:
        print(f"[gepa]   candidate: {c.get('name')} — {c.get('theory','')[:120]}",
              file=sys.stderr)

    bench_dir = ROOT / "validation" / "feature_gepa_runs"
    bench_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

    # Incumbent on eval slice
    incumbent_md = bench_dir / f"{ts}_incumbent.md"
    inc_j = _bench_with_extension(None, n=n, seed=seed, label="incumbent",
                                  out_md=incumbent_md)
    inc_agg = _aggregate(inc_j)
    inc_score = _composite(inc_agg)
    print(f"[gepa] incumbent score={inc_score:.3f} useful={inc_agg['judge_useful_rate']:.0%} "
          f"strat_ok={inc_agg['launch_strategy_ok_rate']:.0%} "
          f"family={inc_agg['max_family_share']:.0%}", file=sys.stderr)

    candidate_results = []
    for i, c in enumerate(candidates, 1):
        ext_text = c.get("extension_text", "")
        if not ext_text:
            continue
        c_md = bench_dir / f"{ts}_candidate_{i}_{c.get('name','x')}.md"
        try:
            c_j = _bench_with_extension(ext_text, n=n, seed=seed,
                                        label=f"cand{i}-{c.get('name')}",
                                        out_md=c_md)
        except Exception as e:
            print(f"[gepa] candidate {c.get('name')} failed: {e}",
                  file=sys.stderr)
            continue
        c_agg = _aggregate(c_j)
        c_score = _composite(c_agg)
        candidate_results.append({
            "name": c.get("name"),
            "theory": c.get("theory"),
            "extension_text": ext_text,
            "agg": c_agg,
            "score": c_score,
            "out_md": str(c_md),
        })
        print(f"[gepa] {c.get('name')} score={c_score:.3f} useful={c_agg['judge_useful_rate']:.0%} "
              f"strat_ok={c_agg['launch_strategy_ok_rate']:.0%} "
              f"family={c_agg['max_family_share']:.0%}", file=sys.stderr)

    # Pick best candidate by composite score (must beat incumbent margin >=0.02)
    candidate_results.sort(key=lambda r: -r["score"])
    winner = None
    if candidate_results and candidate_results[0]["score"] > inc_score + 0.02:
        winner = candidate_results[0]
        print(f"[gepa] eval-slice winner: {winner['name']} "
              f"(+{(winner['score']-inc_score):.3f} composite)", file=sys.stderr)

    # Optional held-out validation
    holdout_winner = winner
    holdout_results = None
    if winner and holdout_n > 0:
        ho_seed = seed + 7919  # disjoint from eval
        ho_inc_md = bench_dir / f"{ts}_holdout_incumbent.md"
        ho_inc_j = _bench_with_extension(None, n=holdout_n, seed=ho_seed,
                                         label="holdout-incumbent",
                                         out_md=ho_inc_md)
        ho_inc_agg = _aggregate(ho_inc_j)
        ho_inc_score = _composite(ho_inc_agg)

        ho_cand_md = bench_dir / f"{ts}_holdout_winner.md"
        ho_cand_j = _bench_with_extension(winner["extension_text"],
                                          n=holdout_n, seed=ho_seed,
                                          label=f"holdout-{winner['name']}",
                                          out_md=ho_cand_md)
        ho_cand_agg = _aggregate(ho_cand_j)
        ho_cand_score = _composite(ho_cand_agg)
        holdout_results = {
            "n": holdout_n,
            "seed": ho_seed,
            "incumbent": {"agg": ho_inc_agg, "score": ho_inc_score},
            "candidate": {"agg": ho_cand_agg, "score": ho_cand_score},
            "candidate_beats": ho_cand_score > ho_inc_score + 0.02,
        }
        print(f"[gepa] holdout incumbent={ho_inc_score:.3f} "
              f"candidate={ho_cand_score:.3f} "
              f"beats={'Y' if holdout_results['candidate_beats'] else 'N'}",
              file=sys.stderr)
        if not holdout_results["candidate_beats"]:
            holdout_winner = None
            print(f"[gepa] held-out validation REJECTS {winner['name']}; "
                  "not applying", file=sys.stderr)

    return {
        "timestamp": ts,
        "trace_source": str(trace_src.relative_to(ROOT)),
        "n_traces": len(traces),
        "diagnosis": diagnosis,
        "incumbent": {"agg": inc_agg, "score": inc_score},
        "candidates": candidate_results,
        "eval_winner": winner,
        "holdout": holdout_results,
        "applied_winner": holdout_winner,
    }


def write_report(result: dict, *, out_md: Path) -> None:
    inc = result.get("incumbent", {})
    inc_agg = inc.get("agg", {})
    lines = [
        f"# Feature GEPA cycle — {result.get('timestamp', '?')}",
        "",
        f"_Trace source: `{result.get('trace_source')}` ({result.get('n_traces', 0)} mismatch traces)._",
        "",
        f"## Diagnosis\n\n{result.get('diagnosis', '(none)')}",
        "",
        "## Scoreboard",
        "",
        "| Variant | Score | Useful | Caught | Strat-OK | Family |",
        "|---|---|---|---|---|---|",
    ]
    if inc_agg:
        lines.append(
            f"| incumbent | {inc.get('score', 0):.3f} | "
            f"{inc_agg.get('judge_useful_rate', 0):.0%} | "
            f"{inc_agg.get('judge_caught_rate', 0):.0%} | "
            f"{inc_agg.get('launch_strategy_ok_rate', 0):.0%} | "
            f"{inc_agg.get('max_family_share', 0):.0%} |"
        )
    for c in result.get("candidates", []):
        agg = c.get("agg", {})
        lines.append(
            f"| `{c.get('name')}` | {c.get('score', 0):.3f} | "
            f"{agg.get('judge_useful_rate', 0):.0%} | "
            f"{agg.get('judge_caught_rate', 0):.0%} | "
            f"{agg.get('launch_strategy_ok_rate', 0):.0%} | "
            f"{agg.get('max_family_share', 0):.0%} |"
        )

    ho = result.get("holdout")
    if ho:
        lines += ["", f"## Held-out validation (n={ho['n']}, seed={ho['seed']})", ""]
        lines.append(
            f"- Incumbent score {ho['incumbent']['score']:.3f}, "
            f"candidate score {ho['candidate']['score']:.3f}, "
            f"candidate beats: **{'YES' if ho['candidate_beats'] else 'NO'}**"
        )

    applied = result.get("applied_winner")
    lines += ["", "## Verdict", ""]
    if applied:
        lines.append(
            f"**APPLY** `{applied['name']}` — beats incumbent on eval AND holdout."
        )
        lines.append("")
        lines.append("```")
        lines.append(applied["extension_text"])
        lines.append("```")
    elif result.get("eval_winner"):
        lines.append(
            f"**Eval winner `{result['eval_winner']['name']}` "
            "REJECTED at holdout** (per cycle-4 discipline). "
            "Not applying."
        )
    else:
        lines.append(
            "**No candidate beat incumbent on eval slice.** "
            "Diagnosis recorded; calibration not applied."
        )

    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text("\n".join(lines))
    out_md.with_suffix(".json").write_text(json.dumps(result, indent=2, default=str))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="GEPA-style optimizer for feature-planning sequencers"
    )
    p.add_argument("--n", type=int, default=20,
                   help="Per-candidate eval slice size (default 20; "
                        "cycle-4 discipline: don't apply winners from <20).")
    p.add_argument("--seed", type=int, default=4242)
    p.add_argument("--holdout-n", type=int, default=12,
                   help="Held-out validation size (0 = skip; cycle-4 "
                        "lesson: holdout is what catches eval-slice bias).")
    p.add_argument("--max-candidates", type=int, default=2)
    p.add_argument("--apply", action="store_true",
                   help="If a winner survives eval+holdout, write it to "
                        "mirofish_lab/feature_pareto_extra.txt.")
    p.add_argument("--out", type=Path,
                   default=ROOT / "validation" / "FEATURE_GEPA_REPORT.md")
    args = p.parse_args(argv)

    if args.n < 20:
        print(f"[gepa] WARNING: --n={args.n} is below the n=20 floor learned "
              "from the rollout cycle-4 retrospective. Cycles below n=20 are "
              "exploratory; their winners are NOT-FOR-APPLY.", file=sys.stderr)

    result = run_cycle(
        n=args.n, seed=args.seed,
        holdout_n=args.holdout_n,
        max_candidates=args.max_candidates,
    )
    write_report(result, out_md=args.out)

    if args.apply and result.get("applied_winner"):
        winner = result["applied_winner"]
        target = ROOT / "mirofish_lab" / "feature_pareto_extra.txt"
        target.write_text(winner["extension_text"])
        print(f"[gepa] APPLIED winner '{winner['name']}' to {target}",
              file=sys.stderr)
        # Append calibration record
        rec = {
            "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "warning": "feature_launch_strategy_mismatch",
            "fix": "gepa_revise (feature)",
            "criterion": "feature_gepa_composite",
            "bench_n": args.n,
            "holdout_n": args.holdout_n,
            "verdict": {
                "label": "B better — APPLIED",
                "reason": f"winner={winner['name']} score={winner['score']:.3f} "
                          f"vs incumbent {result['incumbent']['score']:.3f}",
            },
            "applied": True,
            "applied_path": str(target.relative_to(ROOT)),
            "ab_report_path": str(args.out.relative_to(ROOT)),
        }
        with (ROOT / "validation" / "calibrations.jsonl").open("a") as f:
            f.write(json.dumps(rec) + "\n")
    elif args.apply:
        print("[gepa] --apply set but no winner to apply", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
