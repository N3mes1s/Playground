"""Quantitative comparison: multi-agent rollout-rehearsal output vs
single-prompt baseline. Per intent we measure:

- step count
- distinct owner roles
- distinct gate types
- concrete-gate ratio (specific values vs generic placeholders)
- concrete-rollback ratio (specific inverse vs 'redeploy_previous')
- open-questions count
- conflict count

Plus an aggregate summary across all intents.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MA_DIR = ROOT / "rollout-rehearsal" / "reports"
BL_DIR = ROOT / "rollout-rehearsal" / "baselines"


def _is_concrete_gate(g: str) -> bool:
    if not g or g.strip().lower() == "none":
        return False
    s = g.lower()
    # Concrete gates name a value, threshold, role, or window.
    if re.search(r"\d", s):
        return True
    if re.search(r"[<>%hms ]+\d", s):
        return True
    if any(k in s for k in ("error_rate", "lag", "iops", "p95", "p99", "budget",
                            "off-peak", "off_peak", "business hours",
                            "release_owner", "security review", "support_lead",
                            "comms", "canary")):
        return True
    return False


def _is_concrete_rollback(r: str) -> bool:
    if not r:
        return False
    if r.strip().lower() in ("redeploy_previous", "rollback", "revert"):
        return False
    return len(r) > 30


def _summarise_plan(plan: dict) -> dict:
    steps = plan.get("steps") or []
    owners = [s.get("owner", "") for s in steps if isinstance(s, dict)]
    gates = [s.get("gate", "") for s in steps if isinstance(s, dict)]
    rollbacks = [s.get("rollback", "") for s in steps if isinstance(s, dict)]
    n = len(steps)

    distinct_owners = len({o for o in owners if o})
    gate_types = Counter()
    for g in gates:
        for prefix in ("wait_for", "monitor", "approval", "window", "none"):
            if g.startswith(prefix):
                gate_types[prefix] += 1
                break
        else:
            gate_types["other"] += 1

    concrete_gates = sum(1 for g in gates if _is_concrete_gate(g))
    concrete_rollbacks = sum(1 for r in rollbacks if _is_concrete_rollback(r))

    return {
        "steps": n,
        "distinct_owners": distinct_owners,
        "gate_types": dict(gate_types),
        "concrete_gates_pct": round(100 * concrete_gates / n, 0) if n else 0,
        "concrete_rollbacks_pct": round(100 * concrete_rollbacks / n, 0) if n else 0,
        "open_questions": len(plan.get("open_questions") or []),
        "conflicts": len(plan.get("conflicts") or []),
    }


def main() -> None:
    rows = []
    for ma_path in sorted(MA_DIR.glob("intent_*.json")):
        stem = ma_path.stem
        ma_obj = json.loads(ma_path.read_text())
        ma_plan = ma_obj.get("plan") or {}
        ma_summary = _summarise_plan(ma_plan)

        bl_path = BL_DIR / f"{stem}.baseline.json"
        if not bl_path.exists():
            continue
        bl_obj = json.loads(bl_path.read_text())
        bl_plan = bl_obj.get("plan") or {}
        bl_summary = _summarise_plan(bl_plan)
        bl_summary["tokens_in"] = bl_obj.get("tokens_in")
        bl_summary["tokens_out"] = bl_obj.get("tokens_out")

        rows.append({"intent": stem, "multi_agent": ma_summary, "baseline": bl_summary})

    print(f"\n{'INTENT':<48} {'STEPS':>11} {'OWNERS':>11} {'GATES%':>11} {'ROLLBACK%':>11} {'OPEN_Q':>11} {'CONFL':>11}")
    print("-" * 130)
    for r in rows:
        ma, bl = r["multi_agent"], r["baseline"]
        print(f"{r['intent']:<48} ", end="")
        print(f"{ma['steps']:>4}/{bl['steps']:>4}  ", end="")
        print(f"{ma['distinct_owners']:>4}/{bl['distinct_owners']:>4}  ", end="")
        print(f"{ma['concrete_gates_pct']:>4.0f}/{bl['concrete_gates_pct']:>4.0f}  ", end="")
        print(f"{ma['concrete_rollbacks_pct']:>4.0f}/{bl['concrete_rollbacks_pct']:>4.0f}  ", end="")
        print(f"{ma['open_questions']:>4}/{bl['open_questions']:>4}  ", end="")
        print(f"{ma['conflicts']:>4}/{bl['conflicts']:>4}")

    # Aggregate.
    def avg(rows, side, key):
        vals = [r[side][key] for r in rows if isinstance(r[side][key], (int, float))]
        return round(sum(vals) / len(vals), 1) if vals else 0

    print(f"\n{'AVERAGE':<48} ", end="")
    for key in ["steps", "distinct_owners", "concrete_gates_pct", "concrete_rollbacks_pct", "open_questions", "conflicts"]:
        ma_avg = avg(rows, "multi_agent", key)
        bl_avg = avg(rows, "baseline", key)
        print(f"{ma_avg:>4.1f}/{bl_avg:>4.1f}  ", end="")
    print()

    # Token spend (baseline only — multi-agent we don't track end-to-end yet).
    tot_in = sum((r["baseline"].get("tokens_in") or 0) for r in rows)
    tot_out = sum((r["baseline"].get("tokens_out") or 0) for r in rows)
    print(f"\nBaseline aggregate: {tot_in} prompt tokens / {tot_out} completion tokens across {len(rows)} runs")
    print("Multi-agent: ~7 calls per run (6 personas + 1 sequencer); rough estimate = ~7x above")


if __name__ == "__main__":
    main()
