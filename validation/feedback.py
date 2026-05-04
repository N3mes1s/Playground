"""Outcome-feedback recorder: close the continuous-improvement loop.

After a real plan is executed (or a recommendation is rejected for
some reason), record the outcome here so the meta-analysis can flag
systemic blind spots.

Usage:
    python validation/feedback.py record \\
        --run validation/real_world_demo/teleport_cache.grounded.json \\
        --winner-was-followed yes \\
        --gate-violations "S5: monitor:err<0.1% threshold breached during canary" \\
        --constraint-was-wrong "DataPlatform's wait_for:secrets_rotation was not actually blocking" \\
        --notes "actually shipped; cache-hit logging worked first try"

    python validation/feedback.py summary
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FEEDBACK_DB = ROOT / "validation" / "feedback.jsonl"


def cmd_record(args) -> None:
    rec = {
        "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "run_path": args.run,
        "winner_was_followed": args.winner_was_followed,
        "gate_violations": args.gate_violations or [],
        "constraints_were_wrong": args.constraint_was_wrong or [],
        "constraints_were_useful": args.constraint_was_useful or [],
        "actual_recovery_class": args.actual_recovery_class,
        "actual_outcome": args.actual_outcome,
        "notes": args.notes or "",
    }
    FEEDBACK_DB.parent.mkdir(parents=True, exist_ok=True)
    with FEEDBACK_DB.open("a") as f:
        f.write(json.dumps(rec) + "\n")
    print(f"[recorded] {FEEDBACK_DB}", file=sys.stderr)


def cmd_summary(args) -> None:
    if not FEEDBACK_DB.exists():
        print("no feedback recorded yet", file=sys.stderr)
        return
    records = [
        json.loads(line)
        for line in FEEDBACK_DB.read_text().splitlines()
        if line.strip()
    ]
    if not records:
        print("no feedback records found", file=sys.stderr)
        return

    print(f"# Feedback summary across {len(records)} recorded outcomes")
    print()

    followed = sum(1 for r in records if r.get("winner_was_followed") == "yes")
    print(f"- Winner was followed: **{followed}/{len(records)}** "
          f"({100 * followed / len(records):.0f}%)")

    n_violations = sum(len(r.get("gate_violations") or []) for r in records)
    print(f"- Gate violations recorded: **{n_violations}**")

    n_wrong = sum(len(r.get("constraints_were_wrong") or []) for r in records)
    n_useful = sum(len(r.get("constraints_were_useful") or []) for r in records)
    print(f"- Constraints flagged wrong: **{n_wrong}**, useful: **{n_useful}**")
    print()

    # Aggregate which constraint owners get flagged wrong most often.
    wrong_owners: dict[str, int] = {}
    for r in records:
        for w in r.get("constraints_were_wrong") or []:
            for owner in ("BackendOwner", "DataPlatform", "SRE", "Security",
                          "ProductPM", "ConsumerSubsystem"):
                if owner.lower() in str(w).lower():
                    wrong_owners[owner] = wrong_owners.get(owner, 0) + 1
                    break
    if wrong_owners:
        print("## Constraint-author bias")
        print()
        for owner, count in sorted(wrong_owners.items(), key=lambda kv: -kv[1]):
            print(f"- {owner}: flagged-wrong {count} times")
        print()
        print(
            "If one persona is consistently flagged wrong, its system prompt "
            "needs revision (probably too generic / too aggressive)."
        )

    print()
    print("## Raw records")
    print()
    print("| Timestamp | Run | Followed | Outcome | Notes |")
    print("|---|---|---|---|---|")
    for r in records:
        print(
            f"| {r['timestamp']} | `{Path(r['run_path']).name}` | "
            f"{r['winner_was_followed']} | "
            f"{r.get('actual_outcome', '—')} | "
            f"{r['notes'][:80]} |"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Outcome feedback for the rollout pipeline.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    rec_p = sub.add_parser("record")
    rec_p.add_argument("--run", required=True, help="Path to the run JSON sidecar")
    rec_p.add_argument("--winner-was-followed", choices=["yes", "no", "modified"], default="yes")
    rec_p.add_argument("--gate-violations", action="append")
    rec_p.add_argument("--constraint-was-wrong", action="append")
    rec_p.add_argument("--constraint-was-useful", action="append")
    rec_p.add_argument("--actual-recovery-class", default=None)
    rec_p.add_argument("--actual-outcome", default=None,
                       help="success | partial | failure")
    rec_p.add_argument("--notes", default="")
    rec_p.set_defaults(func=cmd_record)

    sum_p = sub.add_parser("summary")
    sum_p.set_defaults(func=cmd_summary)

    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
