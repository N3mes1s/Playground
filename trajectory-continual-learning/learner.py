"""The continual-learning loop: ingest -> mine -> govern -> learn -> retrieve.

This ties the pieces together into the engine that mirrors trajectory.ai:

    Instrument (sdk)   ->  trajectories with telemetry
    Understand (miner) ->  lessons + preference pairs
    Steer (governance) ->  approval gate + audit log
    Learn (memory)     ->  approved lessons enter retrievable memory

The policy then reads from that memory at inference time, so the deployed
behavior improves continuously as more usage flows in.
"""

from __future__ import annotations

from typing import Optional

from governance import ApprovalGate, Decision
from memory import Lesson, LessonMemory
from miner import mine_lessons, mine_preference_pairs, PreferencePair
from schema import Message, Trajectory


class ContinualLearner:
    def __init__(self, backend, memory: Optional[LessonMemory] = None,
                 gate: Optional[ApprovalGate] = None, retrieve_k: int = 5):
        self.backend = backend
        self.memory = memory or LessonMemory()
        self.gate = gate or ApprovalGate()
        self.retrieve_k = retrieve_k
        self.preference_pairs: list[PreferencePair] = []
        self.stats = {"ingested": 0, "lessons_proposed": 0, "lessons_approved": 0}
        # per-instance staging area for the approval gate (reinforcement counts)
        self._staged: dict = {}
        self._live_keys: set = set()

    # -- inference: act using what has been learned so far ------------------
    def act(self, context: str, query: str) -> Message:
        lessons = self.memory.retrieve(context, query, k=self.retrieve_k)
        return self.backend.generate(context, query, lessons)

    def policy_context(self, context: str, query: str) -> list[Lesson]:
        return self.memory.retrieve(context, query, k=self.retrieve_k)

    # -- learning: turn one trajectory into durable improvement -------------
    def ingest(self, traj: Trajectory) -> dict:
        self.stats["ingested"] += 1
        approved = 0

        # 1) Understand: mine candidate lessons from the telemetry.
        candidates = mine_lessons(traj)
        self.stats["lessons_proposed"] += len(candidates)

        # 2) Steer: each candidate must clear the approval gate. We pre-stage it
        #    in a scratch store so `support` (reinforcement count) reflects
        #    repeated corrections before it can be approved into production.
        for cand in candidates:
            key = cand.key()
            staged = self._staged.get(key)
            if staged is None:
                self._staged[key] = cand
                staged = cand
            else:
                staged.support += 1
                staged.source_trajectories.extend(cand.source_trajectories)

            decision = self.gate.review(staged)
            if decision == Decision.APPROVED and key not in self._live_keys:
                # 3) Learn: promote into the live, retrievable memory.
                self.memory.upsert(staged)
                self._live_keys.add(key)
                self.stats["lessons_approved"] += 1
                approved += 1

        # also collect preference pairs for the parametric (DPO) export path
        self.preference_pairs.extend(mine_preference_pairs(traj))

        return {"proposed": len(candidates), "approved": approved}
