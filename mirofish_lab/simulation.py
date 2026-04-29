"""Multi-agent orchestration primitives.

These are deliberately small. Real MiroFish has a richer simulation engine
(graph + temporal updates); we stick to three useful patterns:

- parallel_run: same prompt to N agents, collect responses.
- debate: A proposes, B rebuts, A defends, ... for K rounds.
- round_table: each agent in turn sees prior contributions and adds its own.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from mirofish_lab.agent import Agent, AgentResponse


@dataclass
class DebateTurn:
    speaker: str
    content: str


def parallel_run(
    agents: list[Agent], prompt: str, *, max_workers: int = 4
) -> list[AgentResponse]:
    """Send the same prompt to every agent concurrently. Order preserved."""
    results: list[AgentResponse | None] = [None] * len(agents)
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(agent.respond, prompt, tags=("parallel",)): i
            for i, agent in enumerate(agents)
        }
        for fut in as_completed(futures):
            i = futures[fut]
            results[i] = fut.result()
    return [r for r in results if r is not None]


def debate(
    a: Agent,
    b: Agent,
    *,
    seed_prompt: str,
    rounds: int = 3,
) -> list[DebateTurn]:
    """A speaks first to seed_prompt, then B responds, A responds, etc.

    Returns the full transcript.
    """
    transcript: list[DebateTurn] = []

    a_resp = a.respond(seed_prompt, tags=("debate", "seed"))
    transcript.append(DebateTurn(a.persona.name, a_resp.content))

    last = a_resp.content
    for r in range(rounds):
        b_resp = b.respond(
            f"{a.persona.name} says:\n\n{last}\n\nRespond.",
            tags=("debate", f"round-{r}"),
        )
        transcript.append(DebateTurn(b.persona.name, b_resp.content))
        last = b_resp.content

        if r == rounds - 1:
            break

        a_resp = a.respond(
            f"{b.persona.name} says:\n\n{last}\n\nRespond.",
            tags=("debate", f"round-{r}"),
        )
        transcript.append(DebateTurn(a.persona.name, a_resp.content))
        last = a_resp.content

    return transcript


def round_table(
    agents: list[Agent],
    *,
    seed_prompt: str,
    rounds: int = 1,
) -> list[DebateTurn]:
    """Each agent sees seed + everything said before, then contributes.

    With rounds>1, the table goes around again, agents seeing the latest state.
    """
    transcript: list[DebateTurn] = []
    for r in range(rounds):
        for agent in agents:
            history = "\n\n".join(
                f"### {t.speaker}\n{t.content}" for t in transcript
            )
            prompt = (
                f"Topic:\n{seed_prompt}\n\n"
                f"Discussion so far:\n{history if history else '(you speak first)'}\n\n"
                f"Add your contribution as {agent.persona.name}."
            )
            resp = agent.respond(prompt, tags=("round_table", f"r{r}"))
            transcript.append(DebateTurn(agent.persona.name, resp.content))
    return transcript
