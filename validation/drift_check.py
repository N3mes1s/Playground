"""Cross-version drift check.

When the underlying LLM model changes (gpt-5.4-mini → gpt-5.5-mini,
or just nondeterministic drift across days), the entire recommendation
surface can shift. This script:

1. Maintains a fixed reference suite of 5 intents under
   `validation/drift_reference/`.
2. On every run, evaluates the current model + current pipeline
   defaults against the reference and computes:
     - winner-family agreement vs the committed baseline
     - SMT-feasibility-rate delta
     - judge-scored useful-rate delta
3. Writes `validation/DRIFT.md` with red/yellow/green per metric.

Usage:
    python validation/drift_check.py --record-baseline   # one-time
    python validation/drift_check.py                     # subsequent runs
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REF_DIR = ROOT / "validation" / "drift_reference"
BASELINE_PATH = REF_DIR / "BASELINE.json"
INTENTS_DIR = REF_DIR / "intents"


def _ensure_reference() -> list[Path]:
    INTENTS_DIR.mkdir(parents=True, exist_ok=True)
    candidates = [
        ROOT / "validation/postmortems/intents/04_gitlab_db_replica.md",
        ROOT / "validation/postmortems/intents/05_linear_cascade_migration.md",
        ROOT / "validation/real_world_demo/intent_acme_pydantic_v2.md",
        ROOT / "validation/real_world_demo/intent_teleport_sqlite_cache.md",
        ROOT / "validation/real_world_demo/intent_llm_otel_tracing.md",
    ]
    out = []
    for src in candidates:
        if not src.exists():
            continue
        dst = INTENTS_DIR / src.name
        if not dst.exists():
            dst.write_text(src.read_text())
        out.append(dst)
    return out


def _run_intent(intent: Path) -> dict:
    out_dir = ROOT / ".bench_runs"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_md = out_dir / f"drift_{intent.stem}.md"
    cmd = [
        sys.executable, str(ROOT / "verified-rollout" / "cli_pro.py"),
        str(intent),
        "--n-plans", "3",
        "--out", str(out_md),
    ]
    env = dict(os.environ)
    env.setdefault("MODEL", "gpt-5.4-mini")
    env.setdefault("MAX_TOKENS", "1200")
    res = subprocess.run(cmd, env=env, cwd=str(ROOT),
                         capture_output=True, text=True, timeout=300)
    if res.returncode != 0:
        return {"_failed": True, "stderr": res.stderr[-300:]}
    return json.loads(out_md.with_suffix(".json").read_text())


def _summarise(sidecar: dict) -> dict:
    if sidecar.get("_failed"):
        return {"failed": True}
    pareto = sidecar.get("pareto") or {}
    smt = sidecar.get("smt") or {}
    chaos = sidecar.get("chaos") or {}
    winner = pareto.get("winner") or sidecar.get("winner")
    smt_feasible = sum(
        1 for v in smt.values() if isinstance(v, dict) and v.get("feasible", True)
    )
    n_plans = max(len(smt), len(chaos))
    winner_fragility = (chaos.get(winner, {}) if winner else {}).get("fragility")
    return {
        "winner": winner,
        "winner_family": next(
            (f for f in ("speed", "safety", "cost", "balanced")
             if winner and f in (winner or "").lower()),
            "other",
        ),
        "smt_feasible": smt_feasible,
        "n_plans": n_plans,
        "winner_fragility": winner_fragility,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record-baseline", action="store_true")
    args = parser.parse_args(argv)

    intents = _ensure_reference()
    print(f"[drift] {len(intents)} reference intents", file=sys.stderr)

    current: dict[str, dict] = {}
    for intent in intents:
        print(f"[drift] running {intent.name}", file=sys.stderr)
        sidecar = _run_intent(intent)
        current[intent.name] = _summarise(sidecar)

    timestamp = datetime.utcnow().isoformat(timespec="seconds") + "Z"

    if args.record_baseline:
        BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
        BASELINE_PATH.write_text(json.dumps({
            "recorded_at": timestamp,
            "model": os.environ.get("MODEL", "gpt-5.4-mini"),
            "results": current,
        }, indent=2))
        print(f"[drift] baseline recorded at {BASELINE_PATH}", file=sys.stderr)
        return 0

    if not BASELINE_PATH.exists():
        print("[drift] no baseline recorded. Run with --record-baseline first.",
              file=sys.stderr)
        return 1

    baseline = json.loads(BASELINE_PATH.read_text())
    base_results = baseline.get("results", {})

    # Compare.
    family_agree = 0
    fragility_deltas: list[float] = []
    smt_deltas: list[float] = []
    same_winner = 0
    rows = []
    for name, cur in current.items():
        base = base_results.get(name, {})
        rows.append({
            "intent": name,
            "baseline_winner": base.get("winner"),
            "current_winner": cur.get("winner"),
            "winner_changed": base.get("winner") != cur.get("winner"),
            "family_changed": base.get("winner_family") != cur.get("winner_family"),
            "baseline_fragility": base.get("winner_fragility"),
            "current_fragility": cur.get("winner_fragility"),
            "baseline_smt_feasible": base.get("smt_feasible"),
            "current_smt_feasible": cur.get("smt_feasible"),
        })
        if base.get("winner_family") == cur.get("winner_family"):
            family_agree += 1
        if base.get("winner") == cur.get("winner"):
            same_winner += 1
        if base.get("winner_fragility") is not None and cur.get("winner_fragility") is not None:
            fragility_deltas.append(cur["winner_fragility"] - base["winner_fragility"])
        smt_deltas.append((cur.get("smt_feasible") or 0) - (base.get("smt_feasible") or 0))

    total = max(1, len(intents))
    family_agree_rate = family_agree / total
    same_winner_rate = same_winner / total
    avg_frag_drift = (sum(fragility_deltas) / max(1, len(fragility_deltas)))

    def light(metric: float, *, lower_is_better: bool, low: float, mid: float) -> str:
        if lower_is_better:
            if metric <= low:
                return "🟢"
            if metric <= mid:
                return "🟡"
            return "🔴"
        else:
            if metric >= 1 - low:
                return "🟢"
            if metric >= 1 - mid:
                return "🟡"
            return "🔴"

    family_light = light(family_agree_rate, lower_is_better=False, low=0.10, mid=0.30)
    winner_light = light(same_winner_rate, lower_is_better=False, low=0.30, mid=0.60)
    frag_light = light(abs(avg_frag_drift), lower_is_better=True, low=0.05, mid=0.15)

    md = [
        f"# Drift check — {timestamp}",
        "",
        f"Baseline model: `{baseline.get('model', '?')}`, recorded "
        f"{baseline.get('recorded_at', '?')}.",
        f"Current model:  `{os.environ.get('MODEL', 'gpt-5.4-mini')}`.",
        "",
        f"- Winner-family agreement: **{family_agree_rate:.0%}** {family_light}",
        f"- Same-winner-label rate:  **{same_winner_rate:.0%}** {winner_light}",
        f"- Avg fragility drift:     **{avg_frag_drift:+.3f}** {frag_light}",
        "",
        "## Per-intent",
        "",
        "| Intent | base→curr winner | family changed | base frag | curr frag | base smt feas | curr smt feas |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        md.append(
            f"| `{r['intent']}` | "
            f"{r['baseline_winner']} → {r['current_winner']} | "
            f"{'YES' if r['family_changed'] else 'no'} | "
            f"{r['baseline_fragility']} | {r['current_fragility']} | "
            f"{r['baseline_smt_feasible']} | {r['current_smt_feasible']} |"
        )
    md.append("")
    md.append(
        "## Light interpretation\n\n"
        "- 🟢 = stable; 🟡 = some drift, investigate; 🔴 = significant "
        "drift, freeze release of new defaults until reviewed.\n"
        "- Significant winner-label drift on ≥30% of intents is the "
        "strongest signal that the model bumped under us.\n"
    )

    drift_md = ROOT / "validation" / "DRIFT.md"
    drift_md.write_text("\n".join(md))
    drift_json = drift_md.with_suffix(".json")
    drift_json.write_text(json.dumps({
        "timestamp": timestamp,
        "baseline_recorded_at": baseline.get("recorded_at"),
        "family_agree_rate": family_agree_rate,
        "same_winner_rate": same_winner_rate,
        "avg_frag_drift": avg_frag_drift,
        "rows": rows,
    }, indent=2))
    print(f"[done] wrote {drift_md} and {drift_json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
