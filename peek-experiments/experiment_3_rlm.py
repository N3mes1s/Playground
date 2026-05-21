"""Experiment 3 -- PEEK end to end with a real RLM agent (the missing half).

Experiments 1 and 2 exercise PEEK's machinery but feed it *canned* trajectories.
This one closes the loop. A real RLM agent (``rlm_agent.RLMAgent``) actually
explores a real ~71k-char long context (``corpus.build_corpus``) by running code
in a REPL, and PEEK's ``CachePolicy`` distills each genuine trajectory into the
context map.

It answers the same question stream twice and compares:

  * BASELINE -- every question answered with NO context map.
  * PEEK     -- the map evolves across questions and is prepended to each run.

Headline metric: model turns per question. PEEK should cut the orientation
turns once the chapter index has been distilled into the map. Answers are
checked against known facts so a turn saving is only meaningful if the agent
still gets the answer right.

Needs the `claude` CLI (a real model). This makes dozens of model calls.

  python experiment_3_rlm.py                 # all 4 questions, both conditions
  python experiment_3_rlm.py --questions 2   # shorter / cheaper smoke run
  python experiment_3_rlm.py --model opus
"""

from __future__ import annotations

import argparse

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
    so one flaky call cannot abort the whole comparison."""
    try:
        return agent.run(question=question, context=context, context_map=context_map)
    except ClaudeCodeError as e:
        print(f"      !! agent run failed after retries: {e}")
        return RLMResult(answer="(failed)", trajectory="", iterations=0,
                         turns=0, stopped="error")


def main(*, n_questions: int, model: str | None, max_iters: int) -> None:
    questions = QUESTIONS[:n_questions]
    corpus = build_corpus()

    banner("EXPERIMENT 3 -- PEEK end to end with a real RLM agent")
    print(f"corpus      : {len(corpus):,} chars, 9 chapters")
    print(f"questions   : {len(questions)}")
    print(f"agent model : {model or 'claude CLI default'}   max_iterations={max_iters}")

    agent = RLMAgent(
        ClaudeCodeClient(model=model),
        max_iterations=max_iters,
        verbose=True,
    )

    # ----- BASELINE: no context map, ever -----------------------------------
    banner("CONDITION A -- BASELINE (no context map)")
    baseline = []
    for idx, item in enumerate(questions, start=1):
        print(f"\n  Q{idx}: {item['q']}")
        res = safe_run(agent, item["q"], corpus, context_map="")
        ok = correct(res.answer, item["expect"])
        print(f"      -> {res.turns} turns, answer={res.answer[:80]!r}  [{'OK' if ok else 'WRONG'}]")
        baseline.append((res, ok))

    # ----- PEEK: the map evolves across the question stream -----------------
    banner("CONDITION B -- PEEK (context map evolves across questions)")
    policy = CachePolicy(
        client=ClaudeCodeClient(model=model),
        token_budget=TOKEN_BUDGET,
        evolve_steps=None,  # evolve on every question
    )
    peek = []
    for idx, item in enumerate(questions, start=1):
        items_before = len(policy.cmap.items())
        map_text = policy.current_map_text
        print(f"\n  Q{idx}: {item['q']}")
        print(f"      map in : {items_before} items, "
              f"{policy.token_counter(map_text)} tokens")
        res = safe_run(agent, item["q"], corpus, context_map=map_text)
        ok = correct(res.answer, item["expect"])
        print(f"      -> {res.turns} turns, answer={res.answer[:80]!r}  [{'OK' if ok else 'WRONG'}]")
        if res.stopped != "error" and res.trajectory:
            print("      distilling trajectory into the map (Distiller + Cartographer)...")
            try:
                policy.update(trajectory=res.trajectory, question=item["q"])
            except ClaudeCodeError as e:
                print(f"      !! distillation failed after retries: {e}")
        peek.append((res, ok, items_before, len(policy.cmap.items())))

    # ----- comparison -------------------------------------------------------
    banner("RESULTS -- model turns per question (baseline vs PEEK)")
    print(f"{'#':<3}{'question':<30}{'BASELINE':>18}{'PEEK':>18}{'map':>12}")
    print(f"{'':<3}{'':<30}{'turns  answer':>18}{'turns  answer':>18}{'items':>12}")
    print("-" * 81)
    b_turns = p_turns = comparable = 0
    for idx, item in enumerate(questions):
        (b_res, b_ok) = baseline[idx]
        (p_res, p_ok, m_before, m_after) = peek[idx]
        both_ran = b_res.stopped != "error" and p_res.stopped != "error"
        if both_ran:
            b_turns += b_res.turns
            p_turns += p_res.turns
            comparable += 1
        b_cell = "n/a" if b_res.stopped == "error" else str(b_res.turns)
        p_cell = "n/a" if p_res.stopped == "error" else str(p_res.turns)
        print(
            f"{idx + 1:<3}{item['label']:<30}"
            f"{b_cell:>6}  {'ok' if b_ok else 'WRONG':<9}"
            f"{p_cell:>6}  {'ok' if p_ok else 'WRONG':<9}"
            f"{m_before:>5}->{m_after:<5}"
        )
    print("-" * 81)
    if comparable:
        print(f"{'':<3}{'TOTAL turns (' + str(comparable) + ' comparable Qs)':<30}"
              f"{b_turns:>6}{'':<11}{p_turns:>6}")
        delta = b_turns - p_turns
        pct = 100.0 * delta / b_turns if b_turns else 0.0
        print(f"\n  PEEK used {p_turns} turns vs baseline {b_turns} "
              f"-- {delta:+d} turns ({pct:+.0f}%) over {comparable} question(s) "
              "that completed in both conditions.")
    else:
        print("  No question completed in both conditions -- nothing to compare.")
    b_correct = sum(ok for _, ok in baseline)
    p_correct = sum(ok for _, ok, _, _ in peek)
    print(f"  Answers correct: baseline {b_correct}/{len(questions)}, "
          f"PEEK {p_correct}/{len(questions)}.")

    banner("FINAL CONTEXT MAP (distilled from the real trajectories)")
    print(policy.current_map_text.rstrip())

    policy.save("output/acme-handbook-rlm.peek.json")
    print("\nsaved evolved map -> output/acme-handbook-rlm.peek.json")
    print(
        "\nNote: Q1 sees an empty map (nothing cached yet), so it is the fair "
        "baseline\nfor the PEEK column; the gain, if any, shows up on Q2+ once "
        "the chapter\nindex and section pointers have been distilled in."
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--questions", type=int, default=len(QUESTIONS),
                        help="how many questions from the stream to run")
    parser.add_argument("--model", default=None,
                        help="model alias/name for the `claude` CLI (e.g. 'opus')")
    parser.add_argument("--max-iters", type=int, default=8,
                        help="max REPL turns per question before giving up")
    args = parser.parse_args()
    main(
        n_questions=max(1, min(args.questions, len(QUESTIONS))),
        model=args.model,
        max_iters=args.max_iters,
    )
