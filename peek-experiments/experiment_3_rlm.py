"""Experiment 3 -- PEEK end to end with a real RLM agent, measured over N runs.

Experiments 1 and 2 exercise PEEK's machinery on *canned* trajectories. This
one closes the loop: a real RLM agent (``rlm_agent.RLMAgent``) actually explores
a real ~115k-char long context (``corpus.build_corpus``) by running code in a
REPL, and PEEK's ``CachePolicy`` distills each genuine trajectory into the map.

Each run answers the same question stream twice:

  * BASELINE -- every question answered with NO context map.
  * PEEK     -- the map evolves across questions and is prepended to each run.

Because a real model is non-deterministic, a single run is just noise. This
script repeats the whole baseline/PEEK comparison ``--runs`` times and reports
per-question means and a paired (PEEK - baseline) total delta with its spread,
so the comparison is something you can actually read a signal off of (n
permitting).

Needs the `claude` CLI. This makes a LOT of model calls -- on the order of
80-100 per run (8 questions x both conditions, plus PEEK's two calls per step).

  python experiment_3_rlm.py                    # 3 runs, 8 questions
  python experiment_3_rlm.py --runs 5           # more runs = tighter estimate
  python experiment_3_rlm.py --runs 1 --questions 3   # quick smoke check
"""

from __future__ import annotations

import argparse
import statistics

from peek import CachePolicy

from claude_code_client import ClaudeCodeClient, ClaudeCodeError
from corpus import build_corpus
from rlm_agent import RLMAgent, RLMResult

# Facts use deliberately non-standard values (13 holidays, 19 weeks, 23 days,
# $685, 75-day probation, $1,650 budget, 12-year sabbatical, 21-day notice) so
# the agent cannot shortcut with a plausible guess -- it must read the corpus.
# The 8 questions span 7 chapters spread across the handbook, so the context
# map has to accumulate orientation knowledge corpus-wide rather than for one
# region.
QUESTIONS = [
    {
        "label": "paid company holidays",
        "q": "How many paid company holidays does ACME observe each year?",
        "expect": "13",
    },
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
        "label": "home-office stipend ($)",
        "q": "What is the dollar amount of the one-time home-office setup stipend?",
        "expect": "685",
    },
    {
        "label": "probation period (days)",
        "q": "How many calendar days is the initial probationary period for a new employee?",
        "expect": "75",
    },
    {
        "label": "prof.-dev. budget ($)",
        "q": "What is the annual professional-development budget per employee, in dollars?",
        "expect": "1650",
    },
    {
        "label": "sabbatical service (yrs)",
        "q": "After how many years of continuous service does an employee become eligible for a sabbatical?",
        "expect": "12",
    },
    {
        "label": "resignation notice (days)",
        "q": "How many calendar days of written notice should a resigning employee provide?",
        "expect": "21",
    },
]

TOKEN_BUDGET = 1200


def banner(text: str) -> None:
    print("\n" + "=" * 78)
    print(text)
    print("=" * 78)


def correct(answer: str, expect: str) -> bool:
    # Comma-insensitive substring match, so an answer of "$1,650" still
    # satisfies an expected token of "1650".
    return expect.replace(",", "").lower() in answer.replace(",", "").lower()


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
    n_chapters = corpus.count("=== CHAPTER ")
    print(f"corpus      : {len(corpus):,} chars, {n_chapters} chapters")
    print(f"questions   : {len(questions)}   runs: {runs}")
    print(f"agent model : {model or 'claude CLI default'}   max_iterations={max_iters}")

    # A longer timeout and an extra retry: the larger corpus makes agent
    # trajectories longer, and an occasional slow/hung `claude` call should not
    # cost a paired data point.
    agent_client = ClaudeCodeClient(model=model, timeout=240.0, retries=3)
    peek_client = ClaudeCodeClient(model=model, timeout=240.0, retries=3)
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

    # Paired comparison at the (run, question) level: a pair counts only when
    # both conditions answered that question without a CLI failure. Pairing per
    # question rather than per run means one timeout drops a single pair, not a
    # whole run -- so the usable sample is up to questions x runs, the n the
    # earlier 4-question version never had enough of.
    pairs: list[tuple[int, int]] = []  # (baseline_turns, peek_turns)
    for r in range(runs):
        for i in range(len(questions)):
            b_res = all_baseline[r][i][0]
            p_res = all_peek[r][i][0]
            if b_res.stopped != "error" and p_res.stopped != "error":
                pairs.append((b_res.turns, p_res.turns))

    banner("PAIRED COMPARISON -- per-question turn delta (PEEK - baseline)")
    attempted = len(questions) * runs
    dropped = attempted - len(pairs)
    if not pairs:
        print("  No question completed in both conditions -- cannot compare.")
    else:
        deltas = [p - b for b, p in pairs]
        mean_d = statistics.mean(deltas)
        print(f"  paired questions    : {len(pairs)} of {attempted}"
              + (f"  ({dropped} dropped to a CLI failure)" if dropped else ""))
        print(f"  baseline mean turns : {statistics.mean(b for b, _ in pairs):.2f} per question")
        print(f"  PEEK     mean turns : {statistics.mean(p for _, p in pairs):.2f} per question")
        if len(deltas) >= 2:
            sd = statistics.stdev(deltas)
            print(f"  paired delta (PEEK - baseline): {mean_d:+.2f} turns per question "
                  f"(SD {sd:.2f}, n={len(deltas)})")
            # Deltas within one run are not fully independent -- the PEEK map
            # evolves across the stream -- so this stays a descriptive
            # mean-vs-spread read, not a significance test.
            verdict = (
                "within question-to-question noise -- no measurable effect"
                if abs(mean_d) <= sd
                else ("PEEK faster" if mean_d < 0 else "PEEK slower")
            )
            print(f"  verdict: {verdict}")
        else:
            print(f"  paired delta (PEEK - baseline): {mean_d:+.2f} turns per question "
                  f"(n=1 -- not enough pairs for a spread)")

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
    parser.add_argument("--max-iters", type=int, default=12,
                        help="max REPL turns per question before giving up")
    args = parser.parse_args()
    main(
        n_questions=max(1, min(args.questions, len(QUESTIONS))),
        runs=max(1, args.runs),
        model=args.model,
        max_iters=args.max_iters,
    )
