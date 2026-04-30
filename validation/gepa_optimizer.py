"""GEPA-style autonomous prompt optimisation for the Pareto Sequencers.

Implements the loop the GEPA paper (arXiv 2507.19457, ICLR 2026 Oral)
describes: read full execution traces, let an LLM reflect on the
failure modes, propose mutations, evaluate via the bench, keep the
winners on a Pareto frontier.

Cycle:

  1. **Trace collection** — walk recent bench JSON sidecars
     (`dataset/reports/bench_*.json` and `validation/AB_*.json`),
     extract each scored element where the LLM judge said
     "partial" or "missed". Each trace bundles: intent excerpt,
     judge_rationale, judge_captured signals, judge_missed signals,
     winner plan summary.

  2. **Reflector** — one LLM call that reads the current Sequencer
     BASE_TAIL prompt + a sample of failure traces and emits K
     candidate prompt mutations as Python-source `patch_block`s
     suitable for `auto_calibrate._patch_base_tail()`.

  3. **Evaluation** — for each candidate, apply the patch into
     `mirofish_lab/pareto.py`, run `dataset/bench/bench_runner.py
     --judge` on N stratified elements, restore the original.
     Score each candidate by useful_rate − max_family_share.

  4. **Pareto frontier** — keep the top-K by score across
     {generations}. (This MVP runs a single generation; future
     iterations can carry the frontier into successive reflect+
     evaluate rounds.)

  5. **Logging** — every candidate written to
     `validation/gepa_runs/<timestamp>/`, the cycle's verdict
     appended to `validation/calibrations.jsonl`.

The script is designed to be invoked directly OR as a fix strategy
(`--fix gepa_revise`) from `auto_calibrate.py`.

Honest limits documented in the report:
  - Single-generation MVP. GEPA paper does multi-generation; we'll
    add that once the single-generation case proves itself.
  - No held-out validation slice — winners are picked on the same
    bench sample they're scored on, so good performance can be
    overfit to the trace sample. Future iteration: sample two
    disjoint bench slices, score on slice A, validate on slice B.
  - Reflector sees ~12 traces per cycle; GEPA's published numbers
    use richer trace bundles. We chose 12 to keep latency tractable.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Reuse helpers from auto_calibrate.
sys.path.insert(0, str(ROOT / "validation"))
from auto_calibrate import _patch_base_tail  # type: ignore

# Reuse the bench helpers.
sys.path.insert(0, str(ROOT / "dataset" / "bench"))


REFLECTOR_SYSTEM_PROMPT = """\
You are a prompt engineer optimising an LLM Sequencer that produces
rollout plans for migration / breaking-change scenarios. You read
failure traces from a bench evaluation (each trace has: intent
excerpt, judge verdict, judge rationale, captured / missed
ground-truth signals) and propose mutations to the Sequencer
system prompt that would fix the observed failure modes.

You output ONLY a JSON object wrapped in a ```json fenced block:

{
  "diagnosis": "<= 240 chars: dominant failure mode across the traces",
  "candidates": [
    {
      "name": "short label (kebab-case, <= 24 chars)",
      "theory": "<= 200 chars: what this mutation hypothesises will fix",
      "patch_block": "valid Python source-string-concatenation lines"
    }
  ]
}

Rules for `patch_block`:
- It will be APPENDED to BASE_TAIL inside `pareto.py`, between the
  closing `"... fenced block.\\n"` line and the closing `)`.
- Format: each line is exactly `    "<text>\\n"` (four-space indent,
  double quotes, content escaped to single line, ends with `\\n`).
- The first line should be `    "\\n"` to give the new block visual
  separation from the existing instructions.
- Use ALL CAPS HEADER lines (e.g. "ANTI-VAGUENESS:" or "DEP-AWARE:")
  to make the new directives stand out for the LLM that will read
  the prompt.
- Keep each patch ~6-12 lines; longer is fine if justified.

Rules for diversity:
- Propose 2-3 DIFFERENT THEORIES. Don't all variations of one
  directive.
- Cite specific failure modes from the traces in the `theory` field
  ("traces show 'generic feature flags' rationale 4x → forbid
  vague gates").

Output ONLY the JSON. No prose around it.
"""


# ---------------------------------------------------------------------------
# Trace collection
# ---------------------------------------------------------------------------


def _collect_from_path(path: Path) -> list[dict]:
    try:
        d = json.loads(path.read_text())
    except Exception:
        return []
    out: list[dict] = []
    scores = d.get("scores") or []
    if not scores:
        # AB_*.json shape has scores_a / scores_b
        for k in ("scores_a", "scores_b"):
            scores = scores + (d.get(k) or [])
    for s in scores:
        if not isinstance(s, dict):
            continue
        verdict = s.get("verdict_judge") or s.get("verdict")
        if verdict not in ("partial", "missed"):
            continue
        rationale = s.get("judge_rationale") or s.get("rationale") or ""
        if not rationale:
            continue
        out.append({
            "source_file": str(path.relative_to(ROOT)),
            "element_id": s.get("id"),
            "verdict": verdict,
            "rationale": rationale[:400],
            "captured": s.get("judge_captured") or [],
            "missed": s.get("judge_missed") or [],
            "winner": s.get("winner"),
            "winner_family": s.get("winner_family"),
        })
    return out


def collect_traces(n_max: int = 12) -> list[dict]:
    """Walk all bench JSONs + AB JSONs, return up to n_max failure traces."""
    paths = list((ROOT / "dataset" / "reports").glob("bench_*.json")) \
          + list((ROOT / "validation").glob("AB_*.json")) \
          + list((ROOT / "validation").glob("AB_BENCH*.json"))
    all_traces: list[dict] = []
    for p in paths:
        all_traces.extend(_collect_from_path(p))
    # Diversity: prefer one trace per element_id, then up to n_max.
    seen_ids: set[str] = set()
    deduped: list[dict] = []
    for t in all_traces:
        eid = t.get("element_id") or "?"
        if eid in seen_ids:
            continue
        seen_ids.add(eid)
        deduped.append(t)
    return deduped[:n_max]


# ---------------------------------------------------------------------------
# Reflector
# ---------------------------------------------------------------------------


def _read_current_base_tail() -> str:
    """Extract the current BASE_TAIL string from pareto.py for the reflector."""
    src = (ROOT / "mirofish_lab" / "pareto.py").read_text()
    # The BASE_TAIL is bracketed by "_BASE_TAIL = (" and the matching ")".
    start = src.find("_BASE_TAIL = (")
    if start == -1:
        return ""
    depth = 0
    i = start
    while i < len(src):
        if src[i] == "(":
            depth += 1
        elif src[i] == ")":
            depth -= 1
            if depth == 0:
                return src[start : i + 1]
        i += 1
    return ""


def reflect(traces: list[dict], cfg=None) -> dict:
    """Call the reflector LLM; return parsed candidates."""
    sys.path.insert(0, str(ROOT))
    from mirofish_lab.config import load_config, make_openai_client
    cfg = cfg or load_config()
    client = make_openai_client(cfg)

    base_tail = _read_current_base_tail()

    user_msg = (
        "# Current Sequencer BASE_TAIL\n\n"
        f"```python\n{base_tail}\n```\n\n"
        "# Failure traces\n\n"
        + "\n\n".join(
            f"### {t['element_id']} (verdict={t['verdict']})\n"
            f"- judge rationale: {t['rationale']}\n"
            f"- captured signals: {t['captured'][:5]}\n"
            f"- missed signals: {t['missed'][:5]}"
            for t in traces
        )
        + "\n\nProduce the JSON output per your schema."
    )

    resp = client.chat.completions.create(
        model=cfg.model,
        messages=[
            {"role": "system", "content": REFLECTOR_SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        max_completion_tokens=2000,
    )
    text = resp.choices[0].message.content or ""

    import re
    m = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    body = m.group(1) if m else text
    try:
        return json.loads(body)
    except Exception:
        return {"diagnosis": "(parse failed)", "candidates": []}


# ---------------------------------------------------------------------------
# Evaluation: one candidate via bench
# ---------------------------------------------------------------------------


def _bench_single_config(*, n: int, sources: list[str], run_label: str) -> dict:
    """Run bench_runner.py once with current code, return the JSON sidecar."""
    out_md = ROOT / ".bench_runs" / f"gepa_{run_label}.md"
    cmd = [
        sys.executable, str(ROOT / "dataset" / "bench" / "bench_runner.py"),
        "--n", str(n),
        "--sources", *sources,
        "--pipeline", "cli_pro",
        "--max-tokens", "1200",
        "--n-plans", "3",
        "--judge",
        "--run-label", f"gepa_{run_label}",
        "--out", str(out_md),
    ]
    env = dict(os.environ)
    env.setdefault("MODEL", "gpt-5.4-mini")
    # 1800s = 30 min per bench-runner subprocess. Empirical: a 15-element
    # judge-scored bench takes 8-15 min on the incumbent and longer when a
    # candidate's patched prompt produces verbose plans. Setting the
    # timeout too tight (was 900s) silently disqualifies "better but
    # slower" candidates and biases GEPA toward terse fixes -- a real ops
    # issue we hit on the patch-grounding candidate's first run.
    res = subprocess.run(cmd, env=env, cwd=str(ROOT),
                         capture_output=True, text=True, timeout=1800)
    if res.returncode != 0:
        raise RuntimeError(f"bench failed for {run_label}: {res.stderr[-400:]}")
    return json.loads(out_md.with_suffix(".json").read_text())


def _aggregate(scores: list[dict]) -> dict:
    fams = Counter()
    verdicts = Counter()
    smt_feasible = 0
    plans = 0
    for s in scores:
        verdicts[s.get("verdict_judge", "?")] += 1
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
        "max_family_share": max(fams.values()) / n if fams else 0.0,
        "smt_feasibility_rate": smt_feasible / max(1, plans),
    }


def _composite_score(agg: dict) -> float:
    """Score = useful_rate − 0.5 * max_family_share + 0.3 * smt_feasibility."""
    return (
        agg.get("useful_rate", 0.0)
        - 0.5 * agg.get("max_family_share", 0.0)
        + 0.3 * agg.get("smt_feasibility_rate", 0.0)
    )


def evaluate_candidate(
    *, name: str, patch_block: str, n: int, sources: list[str],
    backup: Path, target: Path,
) -> dict:
    """Apply the candidate patch to pareto.py, run bench, restore."""
    tmp = _patch_base_tail(patch_block)
    shutil.copy(tmp, target)
    try:
        result = _bench_single_config(
            n=n, sources=sources, run_label=name,
        )
    finally:
        shutil.copy(backup, target)   # always restore
    agg = _aggregate(result["scores"])
    return {
        "name": name,
        "patch_block": patch_block,
        "agg": agg,
        "score": _composite_score(agg),
        "scores": result["scores"],
    }


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def run_cycle(*, n_per_candidate: int, max_candidates: int,
              sources: list[str], n_traces: int) -> dict:
    print(f"[gepa] collecting up to {n_traces} failure traces", file=sys.stderr)
    traces = collect_traces(n_max=n_traces)
    if not traces:
        print("[gepa] no failure traces found in existing bench output",
              file=sys.stderr)
        return {"_no_traces": True}
    print(f"[gepa] {len(traces)} traces gathered", file=sys.stderr)

    print("[gepa] reflecting...", file=sys.stderr)
    reflection = reflect(traces)
    diagnosis = reflection.get("diagnosis", "")
    candidates = reflection.get("candidates") or []
    if not candidates:
        return {"_no_candidates": True, "reflection": reflection}
    candidates = candidates[:max_candidates]
    print(f"[gepa] reflector diagnosed: {diagnosis[:120]}", file=sys.stderr)
    print(f"[gepa] {len(candidates)} candidate mutations:", file=sys.stderr)
    for c in candidates:
        print(f"  - {c.get('name')}: {c.get('theory','')[:80]}", file=sys.stderr)

    target = ROOT / "mirofish_lab" / "pareto.py"
    backup = target.with_suffix(".py.gepa_bak")
    shutil.copy(target, backup)

    incumbent_run = None
    eval_results: list[dict] = []
    try:
        # Evaluate the incumbent (no patch) once.
        print("[gepa] evaluating incumbent (no patch)", file=sys.stderr)
        incumbent_result = _bench_single_config(
            n=n_per_candidate, sources=sources, run_label="incumbent",
        )
        incumbent_agg = _aggregate(incumbent_result["scores"])
        incumbent_score = _composite_score(incumbent_agg)
        incumbent_run = {
            "name": "incumbent",
            "patch_block": "(none)",
            "agg": incumbent_agg,
            "score": incumbent_score,
            "scores": incumbent_result["scores"],
        }
        print(f"[gepa] incumbent score = {incumbent_score:.3f} "
              f"(useful={incumbent_agg['useful_rate']:.0%})",
              file=sys.stderr)

        # Evaluate each candidate.
        for c in candidates:
            try:
                er = evaluate_candidate(
                    name=c["name"], patch_block=c["patch_block"],
                    n=n_per_candidate, sources=sources,
                    backup=backup, target=target,
                )
                er["theory"] = c.get("theory", "")
                eval_results.append(er)
                print(
                    f"[gepa]   {c['name']} score={er['score']:.3f} "
                    f"useful={er['agg']['useful_rate']:.0%}",
                    file=sys.stderr,
                )
            except Exception as e:
                print(f"[gepa]   {c['name']} FAILED: {e}", file=sys.stderr)
    finally:
        # Always restore.
        shutil.copy(backup, target)
        backup.unlink(missing_ok=True)

    # Pick winner.
    all_runs = [incumbent_run] + eval_results if incumbent_run else eval_results
    winner = max(all_runs, key=lambda r: r["score"])
    winner_better = (
        incumbent_run is not None
        and winner["name"] != "incumbent"
        and winner["score"] > incumbent_run["score"] + 0.02
    )

    return {
        "n_traces": len(traces),
        "diagnosis": diagnosis,
        "incumbent": incumbent_run,
        "candidates": eval_results,
        "winner_name": winner["name"],
        "winner_score": winner["score"],
        "winner_beats_incumbent": winner_better,
        "winner_patch_block": winner.get("patch_block") if winner_better else None,
    }


def write_report(result: dict, *, out_md: Path) -> Path:
    if result.get("_no_traces"):
        out_md.write_text("# GEPA cycle\n\nNo failure traces; nothing to do.\n")
        return out_md
    lines = [
        f"# GEPA optimizer cycle — {datetime.utcnow().isoformat(timespec='seconds')}Z",
        "",
        f"_Diagnosis_: {result.get('diagnosis', '')}",
        "",
        f"_Traces_: {result.get('n_traces', 0)} failure traces collected.",
        "",
        "## Scoreboard",
        "",
        "| Variant | Score | Useful | Caught | Missed | SMT feas. | Family bias |",
        "|---|---|---|---|---|---|---|",
    ]
    inc = result.get("incumbent")
    rows = [inc] + (result.get("candidates") or [])
    for r in rows:
        if not r:
            continue
        a = r.get("agg", {})
        lines.append(
            f"| {r.get('name','?')} | {r.get('score', 0):.3f} | "
            f"{a.get('useful_rate', 0):.0%} | "
            f"{a.get('caught_rate', 0):.0%} | "
            f"{a.get('missed_rate', 0):.0%} | "
            f"{a.get('smt_feasibility_rate', 0):.0%} | "
            f"{a.get('max_family_share', 0):.0%} |"
        )
    lines.append("")
    lines.append(f"**Winner**: `{result.get('winner_name', '?')}` "
                 f"(score {result.get('winner_score', 0):.3f})")
    lines.append("")
    if result.get("winner_beats_incumbent"):
        lines.append("**Verdict**: B better than incumbent.")
    else:
        lines.append("**Verdict**: incumbent retained (no candidate clears the +0.02 threshold).")
    lines.append("")
    for r in result.get("candidates") or []:
        lines.append(f"### Candidate `{r.get('name')}`")
        lines.append("")
        lines.append(f"_Theory_: {r.get('theory','')}")
        lines.append("")
        lines.append("```python\n" + (r.get("patch_block") or "") + "\n```")
        lines.append("")
    out_md.write_text("\n".join(lines))
    return out_md


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="GEPA-style autonomous prompt optimisation")
    parser.add_argument("--n", type=int, default=20,
                        help="Bench-sample size per candidate (default 20 ≈ "
                             "$0.40/cycle on gpt-5.4-mini, ~30 min wall)")
    parser.add_argument("--max-candidates", type=int, default=2,
                        help="Max candidates from one reflector call")
    parser.add_argument("--sources", nargs="+",
                        default=["swebench_verified", "danluu_postmortems",
                                 "synthetic"])
    parser.add_argument("--n-traces", type=int, default=10,
                        help="Number of failure traces to feed the reflector")
    parser.add_argument(
        "--out", type=Path,
        default=ROOT / "validation" / "GEPA_REPORT.md",
    )
    parser.add_argument("--apply", action="store_true",
                        help="If a candidate beats the incumbent, write the "
                             "patch into mirofish_lab/pareto.py.")
    args = parser.parse_args(argv)

    result = run_cycle(
        n_per_candidate=args.n,
        max_candidates=args.max_candidates,
        sources=args.sources,
        n_traces=args.n_traces,
    )
    write_report(result, out_md=args.out)
    args.out.with_suffix(".json").write_text(json.dumps(result, indent=2,
                                                       default=str))

    # Calibration record
    cal = ROOT / "validation" / "calibrations.jsonl"
    record = {
        "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "warning": "low_specificity",
        "fix": "gepa_revise",
        "criterion": "gepa_composite",
        "bench_n": args.n,
        "verdict": {
            "label": "B better" if result.get("winner_beats_incumbent") else "incumbent retained",
            "reason": (
                f"winner={result.get('winner_name')} "
                f"score={result.get('winner_score', 0):.3f}"
            ),
        },
        "applied": False,
        "ab_report_path": str(args.out.relative_to(ROOT)),
    }
    cal.parent.mkdir(parents=True, exist_ok=True)
    with cal.open("a") as f:
        f.write(json.dumps(record) + "\n")

    if args.apply and result.get("winner_beats_incumbent"):
        patch = result.get("winner_patch_block")
        if patch:
            tmp = _patch_base_tail(patch)
            target = ROOT / "mirofish_lab" / "pareto.py"
            shutil.copy(tmp, target)
            print(f"[gepa] APPLIED winner '{result.get('winner_name')}' "
                  f"to {target.relative_to(ROOT)}", file=sys.stderr)

    print(f"\n[gepa] verdict: {record['verdict']['label']} "
          f"({record['verdict']['reason']})", file=sys.stderr)
    print(f"[gepa] report: {args.out.relative_to(ROOT)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
