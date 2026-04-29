# Add iterative-refinement rounds to `pre-flight-rehearsal`

## What

The four implementer personas (Minimalist, Defensive, TestFirst,
RefactorHappy) currently produce their plans **in parallel and in
isolation**. Add an optional `--rounds N` flag that, after the first
parallel pass, runs additional rounds where each implementer sees
the others' plans and may revise their own (`round_table`-style).

The Judge then ranks the FINAL versions, with explicit visibility of
how each plan evolved between rounds.

## Why

- Real engineering teams don't propose plans in isolation; they look
  at each other's drafts and refine. Parallel-only is a valid first
  pass, but iterative is closer to how plans actually converge.
- We've observed (in the `cost_tracking_issue.md` run) that
  `RefactorHappy` would likely have softened its over-engineered
  plan if it had seen `Minimalist`'s before submitting.
- Single-pass parallel makes the Judge's job harder: it has to
  synthesise across plans that are not aware of each other.

## Scope

- `pre-flight-rehearsal/cli.py`:
  - New `--rounds N` flag (default 1, current behaviour).
  - When `N > 1`, after the parallel pass, run `N - 1` rounds where
    each implementer is shown the merged plan set and can produce a
    revised version.
  - Report includes per-round outputs ("Plan: Minimalist (round 1)",
    "Plan: Minimalist (round 2)") so a human can see the evolution.
- `mirofish_lab/simulation.py`: `round_table` already exists;
  may need a small adapter for "given prior outputs, produce a
  revision" semantics rather than fresh contribution.

## Constraints

- **Default unchanged**: `--rounds 1` produces the existing
  behaviour byte-for-byte (so committed reports remain comparable).
- **Cost transparency**: doubling rounds doubles LLM calls. The CLI
  must print an estimated cost warning when `--rounds > 1`.
- **Convergence detection**: if two consecutive rounds produce
  effectively the same plan from a given persona, stop iterating
  for that persona to save tokens.

## Out of scope

- Cross-PR plan memory.
- Letting implementers vote each other's plans up/down.

## Affected stakeholders

- `pre-flight-rehearsal` (the change)
- `mirofish_lab` (simulation primitives)
