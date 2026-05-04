"""Adversarial chaos search: an LLM Attacker proposes worst-case failure
combinations; static graph computation scores them; iterative refinement
finds the worst K-step failure set the LLM can construct.

Three-phase loop:

1. **Propose**: Attacker agent reads the plan and proposes T candidate
   K-step failure combinations along with its reasoning for each.
2. **Score**: every proposal is evaluated by `static_cascade` from
   chaos_static. The LLM's reasoning is irrelevant for scoring — only
   the resulting blocked set matters.
3. **Refine** (optional): the top-scoring proposals are fed back to
   the Attacker as "the best you have found so far" and it must
   propose strictly worse (more cascading) combinations.

This complements the random-pair sampling in the original chaos_probe:
- random sampling discovers TYPICAL cascades.
- adversarial search discovers WORST cascades.

Both matter — random sampling answers "what's the average fragility"
and adversarial search answers "what's the floor."

Reference: combines the chaos-engineering robustness angle (arXiv
2505.03096) with a search loop similar to LLM-NSGA-II's adversarial
candidate generation, but specialised to worst-case cascade discovery.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from mirofish_lab.agent import Agent
from mirofish_lab.chaos_static import AchillesEntry, static_cascade
from mirofish_lab.config import Config
from mirofish_lab.personas import Persona
from mirofish_lab.rollout import extract_json


ATTACKER_PERSONA = Persona(
    name="ChaosAttacker",
    role="adversarial chaos search agent",
    system_prompt=(
        "You are an adversarial chaos search agent. You read a rollout "
        "plan and propose K-step failure combinations -- sets of K steps "
        "that, if they all failed simultaneously at their gates, would "
        "block the largest number of remaining steps.\n\n"
        "Output ONLY a JSON object (wrap in ```json fenced block):\n"
        "{\n"
        '  "candidates": [\n'
        "    {\n"
        '      "ids": ["S2", "S5"],\n'
        '      "reasoning": "S2 is mid-chain and S5 is a fan-out hub"\n'
        "    }\n"
        "  ]\n"
        "}\n\n"
        "Rules:\n"
        "- Each candidate must have EXACTLY K step ids that ACTUALLY EXIST "
        "in the plan you were given.\n"
        "- Propose 4-8 candidates per call. Diverse, not repeats.\n"
        "- Prefer steps high in the dependency graph (early roots) and "
        "  steps with many descendants. Avoid leaf steps unless they have "
        "  many siblings that depend on them.\n"
        "- Avoid candidates the human told you have already been tried."
    ),
)


@dataclass
class SearchCandidate:
    ids: tuple[str, ...]
    reasoning: str
    blocked: tuple[str, ...]
    fragility: float


@dataclass
class AdversarialSearchResult:
    plan_id: str
    k: int
    rounds: int
    n_candidates_proposed: int
    n_candidates_scored: int
    best: list[SearchCandidate] = field(default_factory=list)
    history: list[dict] = field(default_factory=list)   # round summaries


def _score_candidate(plan: dict, ids: tuple[str, ...]) -> tuple[tuple[str, ...], float]:
    blocked = static_cascade(plan, ids)
    total = len([s for s in (plan.get("steps") or []) if isinstance(s, dict) and s.get("id")])
    denom_remaining = max(1, total - len(ids))
    return tuple(sorted(blocked)), round(len(blocked) / denom_remaining, 3)


def _parse_candidates(raw: object) -> list[tuple[tuple[str, ...], str]]:
    if not isinstance(raw, dict):
        return []
    out = []
    for c in raw.get("candidates", []) or []:
        if not isinstance(c, dict):
            continue
        ids = tuple(str(x) for x in (c.get("ids") or []) if x)
        reasoning = str(c.get("reasoning", "")).strip()
        if ids:
            out.append((ids, reasoning))
    return out


def adversarial_search(
    plan: dict,
    *,
    cfg: Config,
    plan_id: str,
    k: int,
    rounds: int = 3,
    top_n: int = 5,
) -> AdversarialSearchResult:
    """Run a multi-round attacker loop, scoring candidates with static_cascade.

    Returns the top-N worst K-step combinations the attacker constructed.
    """
    res = AdversarialSearchResult(plan_id=plan_id, k=k, rounds=rounds,
                                  n_candidates_proposed=0, n_candidates_scored=0)
    plan_json = json.dumps(plan, indent=2)
    valid_ids = {
        s.get("id") for s in (plan.get("steps") or [])
        if isinstance(s, dict) and s.get("id")
    }

    attacker = Agent(ATTACKER_PERSONA, cfg)
    seen: set[tuple[str, ...]] = set()
    candidates_pool: list[SearchCandidate] = []

    for r in range(rounds):
        if r == 0:
            prompt = (
                f"# Plan under test (k={k} simultaneous failures)\n\n"
                f"```json\n{plan_json}\n```\n\n"
                f"Propose 4-8 worst-case K={k}-step failure combinations."
            )
        else:
            top_so_far = sorted(candidates_pool, key=lambda c: -c.fragility)[: top_n]
            already = "\n".join(
                f"- {list(c.ids)} -> blocks {list(c.blocked)} (fragility {c.fragility})"
                for c in top_so_far
            )
            prompt = (
                f"# Plan under test (k={k} simultaneous failures)\n\n"
                f"```json\n{plan_json}\n```\n\n"
                f"# Best K-step combinations found so far\n\n{already}\n\n"
                f"Propose 4-8 NEW combinations that you believe will block "
                f"MORE steps than these. Do not repeat any combination "
                f"already in the list above. Diverse picks, not minor "
                f"variations of the best so far."
            )
        resp = attacker.respond(prompt)
        parsed = extract_json(resp.content)
        proposals = _parse_candidates(parsed)
        round_added: list[SearchCandidate] = []
        for ids, reasoning in proposals:
            if len(ids) != k:
                continue
            ids_t = tuple(sorted(ids))
            if ids_t in seen:
                continue
            if not all(i in valid_ids for i in ids_t):
                continue
            seen.add(ids_t)
            blocked, frag = _score_candidate(plan, ids_t)
            cand = SearchCandidate(
                ids=ids_t, reasoning=reasoning, blocked=blocked, fragility=frag
            )
            candidates_pool.append(cand)
            round_added.append(cand)
            res.n_candidates_scored += 1
        res.n_candidates_proposed += len(proposals)
        res.history.append({
            "round": r,
            "proposed": len(proposals),
            "added": len(round_added),
            "best_fragility_round": (
                max((c.fragility for c in round_added), default=0.0)
            ),
            "best_fragility_so_far": (
                max((c.fragility for c in candidates_pool), default=0.0)
            ),
        })

    res.best = sorted(candidates_pool, key=lambda c: -c.fragility)[: top_n]
    return res
