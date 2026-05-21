"""Experiment 3 -- PEEK end to end with a real RLM agent, measured over N runs.

Experiments 1 and 2 exercise PEEK's machinery on *canned* trajectories. This
one closes the loop: a real RLM agent (``rlm_agent.RLMAgent``) actually explores
a real ~72k-char long context (``corpus.build_corpus``) by running code in a
REPL, and PEEK's ``CachePolicy`` distills each genuine trajectory into the map.

Each run answers the same question stream twice:

  * BASELINE -- every question answered with NO context map.
  * PEEK     -- the map evolves across questions and is prepended to each run.

Because a real model is non-deterministic, a single run is just noise. This
script repeats the whole baseline/PEEK comparison ``--runs`` times and reports
per-question means and a paired (PEEK - baseline) total delta with its spread,
so the comparison is something you can actually read a signal off of (n
permitting).

Needs the `claude` CLI. This makes a LOT of model calls -- roughly 33 per run.

  python experiment_3_rlm.py                    # 3 runs, 4 questions
  python experiment_3_rlm.py --runs 5           # more runs = tighter estimate
  python experiment_3_rlm.py --runs 1 --questions 2   # quick smoke check
"""

from __future__ import annotations

import argparse
import statistics

from peek import CachePolicy

from claude_code_client import ClaudeCodeClient, ClaudeCodeError
from corpus import build_corpus
from rlm_agent import RLMAgent, RLMResult

# Facts use deliberately non-standard values (19 weeks, 23 days, $685, 13) so
# the agent cannot shortcut with a plausible guess -- it must read the corpus.
QUESTIONS = [
    {
        "label": "parental leave (weeks)",
        "q": "How many weeks of paid parental leave does ACME provide?",
        "expect": "19",
    },
    {
        "label": "vacation days at 5 yrs",
        "q": "How many vacation days per year does an employee with 5 years of service receive?",
        "expect": "23",
    },
    {
        "label": "home-office setup stipend",
        "q": "What is the dollar amount of the one-time home-office setup stipend?",
        "expect": "685",
    },
    {
        "label": "paid company holidays",
        "q": "How many paid company holidays does ACME observe each year?",
        "expect": "13",
    },
]

TOKEN_BUDGET = 800


def banner(text: str) -> None:
    print("\n" + "=" * 78)
    print(text)
    print("=" * 78)


def correct(answer: str, expect: str) -> bool:
    return expect.lower() in answer.lower()


def safe_run(agent: RLMAgent, question: str, context: str, context_map: str) -> RLMResult:
    """Run the agent, turning a persistent CLI failure into a sentinel result
    so one flaky call cannot abort the whole multi-run comparison."""
    try:
        return agent.run(question=question, context=context, context_map=context_map)
    except ClaudeCodeError as e:
        print(f"        !! agent run failed after retries: {e}")
        return RLMResult(answer="(failed)", trajectory="", iterations=0,
                         turns=0, stopped="error")


def one_pass(
    agent: RLMAgent,
    questions: list[dict],
    corpus: str,
    policy: CachePolicy | None,
    *,
    tag: str,
) -> list[tuple[RLMResult, bool]]:
    """One sweep over every question. ``policy=None`` is the baseline (no map);
    otherwise the map is prepended and updated from each trajectory."""
    rows: list[tuple[RLMResult, bool]] = []
    for idx, item in enumerate(questions, start=1):
        map_text = policy.current_map_text if policy is not None else ""
        map_note = f" (map: {len(policy.cmap.items())} items)" if policy is not None else ""
        print(f"    {tag} Q{idx}{map_note}")
        res = safe_run(agent, item["q"], corpus, map_text)
        ok = correct(res.answer, item["expect"])
        flag = "FAILED" if res.stopped == "error" else ("ok" if ok else "WRONG")
        print(f"        -> {res.turns} turns [{flag}]  answer={res.answer[:60]!r}")
        if policy is not None and res.stopped != "error" and res.trajectory:
            try:
                policy.update(trajectory=res.trajectory, question=item["q"])
            except ClaudeCodeError as e:
                print(f"        !! distillation failed after retries: {e}")
        rows.append((res, ok))
    return rows


def _fmt(values: list[int]) -> str:
    """mean and range of a list of turn counts, for the aggregate table."""
    if not values:
        return "n/a"
    mean = statistics.mean(values)
    if min(values) == max(values):
        return f"{mean:>4.1f}  ({min(values)})"
    return f"{mean:>4.1f}  ({min(values)}-{max(values)})"


def main(*, n_questions: int, runs: int, model: str | None, max_iters: int) -> None:
    questions = QUESTIONS[:n_questions]
    corpus = build_corpus()

    banner("EXPERIMENT 3 -- PEEK end to end with a real RLM agent")
    print(f"corpus      : {len(corpus):,} chars, 9 chapters")
    print(f"questions   : {len(questions)}   runs: {runs}")
    print(f"agent model : {model or 'claude CLI default'}   max_iterations={max_iters}")

    agent_client = ClaudeCodeClient(model=model)
    peek_client = ClaudeCodeClient(model=model)
    agent = RLMAgent(agent_client, max_iterations=max_iters, verbose=True)

    # all_baseline[run][question] = (RLMResult, ok); same shape for all_peek.
    all_baseline: list[list[tuple[RLMResult, bool]]] = []
    all_peek: list[list[tuple[RLMResult, bool]]] = []
    last_policy: CachePolicy | None = None

    for r in range(1, runs + 1):
        banner(f"RUN {r}/{runs}")
        print("  condition A -- baseline (no context map)")
        all_baseline.append(one_pass(agent, questions, corpus, None, tag="base"))

        print("\n  condition B -- PEEK (map evolves across the question stream)")
        policy = CachePolicy(
            client=peek_client, token_budget=TOKEN_BUDGET, evolve_steps=None
        )
        all_peek.append(one_pass(agent, questions, corpus, policy, tag="peek"))
        last_policy = policy

    # ---- aggregate ---------------------------------------------------------
    banner(f"AGGREGATE -- model turns per question, averaged over {runs} run(s)")
    print(f"{'#':<3}{'question':<28}{'BASELINE':>18}{'PEEK':>18}")
    print(f"{'':<31}{'mean  (range)':>18}{'mean  (range)':>18}")
    print("-" * 67)
    for i, item in enumerate(questions):
        b = [all_baseline[r][i][0].turns for r in range(runs)
             if all_baseline[r][i][0].stopped != "error"]
        p = [all_peek[r][i][0].turns for r in range(runs)
             if all_peek[r][i][0].stopped != "error"]
        print(f"{i + 1:<3}{item['label']:<28}{_fmt(b):>18}{_fmt(p):>18}")
    print("-" * 67)

    # Paired per-run totals -- only runs where every question completed in
    # both conditions are comparable.
    deltas: list[int] = []
    b_totals: list[int] = []
    p_totals: list[int] = []
    for r in range(runs):
        b_ok = all(res.stopped != "error" for res, _ in all_baseline[r])
        p_ok = all(res.stopped != "error" for res, _ in all_peek[r])
        if b_ok and p_ok:
            bt = sum(res.turns for res, _ in all_baseline[r])
            pt = sum(res.turns for res, _ in all_peek[r])
            b_totals.append(bt)
            p_totals.append(pt)
            deltas.append(pt - bt)

    banner("PAIRED COMPARISON -- total turns per run (PEEK vs baseline)")
    if not deltas:
        print("  No run completed every question in both conditions -- cannot compare.")
    else:
        for idx, (bt, pt) in enumerate(zip(b_totals, p_totals), start=1):
            print(f"  run {idx}: baseline {bt:>3}  |  PEEK {pt:>3}  |  delta {pt - bt:+d}")
        mean_d = statistics.mean(deltas)
        print(f"\n  baseline mean total : {statistics.mean(b_totals):.1f} turns")
        print(f"  PEEK     mean total : {statistics.mean(p_totals):.1f} turns")
        if len(deltas) >= 2:
            sd = statistics.stdev(deltas)
            print(f"  paired delta (PEEK - baseline): {mean_d:+.1f} +/- {sd:.1f} turns "
                  f"(n={len(deltas)})")
            verdict = (
                "within run-to-run noise -- no measurable effect at this sample size"
                if abs(mean_d) <= sd
                else ("PEEK faster" if mean_d < 0 else "PEEK slower")
            )
            print(f"  verdict: {verdict}")
        else:
            print(f"  paired delta (PEEK - baseline): {mean_d:+.1f} turns "
                  f"(n=1 -- not enough runs for a spread)")

    total_q = len(questions) * runs
    b_correct = sum(ok for run in all_baseline for _, ok in run)
    p_correct = sum(ok for run in all_peek for _, ok in run)
    print(f"\n  answers correct: baseline {b_correct}/{total_q}, PEEK {p_correct}/{total_q}")
    print(f"  total model calls: agent {agent_client.calls}, "
          f"PEEK Distiller/Cartographer {peek_client.calls}")

    if last_policy is not None:
        banner("FINAL CONTEXT MAP (from the last run's evolved map)")
        print(last_policy.current_map_text.rstrip())
        last_policy.save("output/acme-handbook-rlm.peek.json")
        print("\nsaved last-run map -> output/acme-handbook-rlm.peek.json")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=3,
                        help="how many times to repeat the baseline/PEEK comparison")
    parser.add_argument("--questions", type=int, default=len(QUESTIONS),
                        help="how many questions from the stream to run")
    parser.add_argument("--model", default=None,
                        help="model alias/name for the `claude` CLI (e.g. 'opus')")
    parser.add_argument("--max-iters", type=int, default=8,
                        help="max REPL turns per question before giving up")
    args = parser.parse_args()
    main(
        n_questions=max(1, min(args.questions, len(QUESTIONS))),
        runs=max(1, args.runs),
        model=args.model,
        max_iters=args.max_iters,
    )
