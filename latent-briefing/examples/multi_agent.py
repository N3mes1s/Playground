"""Multi-agent orchestrator/worker example.

Demonstrates:
  * Building a long shared orchestrator trajectory.
  * Dispatching multiple worker tasks; each gets its own AM-compacted
    briefing of the orchestrator's KV cache.
  * Appending to the orchestrator trajectory between turns (only the
    delta tokens are re-prefilled thanks to prefix reuse).

Usage:
    python examples/multi_agent.py --model distilgpt2 --ratio 0.3
"""
from __future__ import annotations

import argparse
import os
import sys

# Allow running as `python examples/multi_agent.py` from the repo root.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from briefing.model import LatentBriefingModel
from briefing.session import OrchestratorWorkerSession


TRAJECTORY = (
    "SHARED CONTEXT: A small team of engineers is debugging a distributed system. "
    "Service A publishes events to Service B through a Kafka topic. Service B writes "
    "to Postgres with a unique index on event_id. The on-call engineer reports that "
    "Service B is silently dropping events during peak load. The Kafka consumer "
    "group is named 'svc-b-consumer' and has 8 partitions. Service A's retry logic "
    "resends any event that doesn't get an ACK within 2 seconds. Postgres error "
    "logs show duplicate_key_value violations during the incident window."
)

TASKS = [
    "Worker task: What is the most likely root cause of the silent drops?",
    "Worker task: Which specific configuration should we change first?",
    "Worker task: How should we mitigate this in the short term?",
]

TRAJECTORY_EXTRA = (
    " UPDATE: We just confirmed from Grafana that Service A's retry rate spiked "
    "to 30% during the incident, and Postgres CPU was at 95%."
)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", default="distilgpt2")
    ap.add_argument("--ratio", type=float, default=0.3)
    ap.add_argument("--max-new-tokens", type=int, default=32)
    args = ap.parse_args()

    lbm = LatentBriefingModel(args.model)
    sess = OrchestratorWorkerSession(lbm)

    delta, total = sess.set_orchestrator_trajectory(TRAJECTORY)
    print(f"[orchestrator] trajectory: {total} tokens ({delta} freshly prefilled)")

    for task in TASKS:
        turn = sess.dispatch_worker(task, args.ratio,
                                    max_new_tokens=args.max_new_tokens)
        s = turn.briefing_stats
        print(f"\n[task] {task}")
        print(f"[briefing] {s.source_tokens} -> {s.compact_tokens} tokens "
              f"({s.savings*100:.1f}% savings), probe={s.probe_tokens} tok")
        ans = turn.worker_answer[len(task):].strip()
        print(f"[worker]  {ans!r}")

    # Append an update and dispatch again -- should only re-prefill the delta.
    delta, total = sess.append_to_orchestrator(TRAJECTORY_EXTRA)
    print(f"\n[orchestrator] +update: {total} tokens total ({delta} new prefilled)")

    turn = sess.dispatch_worker(
        "Worker task: Given the CPU spike update, what should we do differently?",
        args.ratio, max_new_tokens=args.max_new_tokens,
    )
    s = turn.briefing_stats
    print(f"[briefing] {s.source_tokens} -> {s.compact_tokens} tokens "
          f"({s.savings*100:.1f}% savings)")
    print(f"[worker]  {turn.worker_answer[len(turn.worker_task):].strip()!r}")


if __name__ == "__main__":
    main()
