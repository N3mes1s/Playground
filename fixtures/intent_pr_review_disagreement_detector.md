# Add cross-reviewer disagreement detection to `pr-review-rehearsal`

## What

After the four reviewer personas (SecurityHawk, PerfPedant,
GrumpyArchitect, ProductOwner) produce their independent reviews,
introduce a **DisagreementChecker** agent that diffs their outputs
and surfaces explicit conflicts: cases where one reviewer flagged
something another reviewer implicitly endorsed, or where two
reviewers gave opposite recommendations on the same diff hunk.

The current Judge agent ranks concerns and picks a winner, but it
collapses disagreement into a verdict. The new step keeps the
disagreement visible in the report so the human PR author sees
"SecurityHawk wants X removed; GrumpyArchitect wants X kept" before
the judge merges them.

## Why

- Disagreement IS signal. The most useful reviewer feedback is the
  argument the team would have had over the PR; the current report
  hides it.
- Reduces silent-bias: when all four reviewers agree, that's a
  stronger merge signal than when three agree and one objects, but
  the judge currently shows them as the same.
- Cheap: one extra LLM call per PR.

## Scope

- `pr-review-rehearsal/cli.py`:
  - New `DisagreementChecker` persona in
    `mirofish_lab/personas.py`.
  - After `parallel_run(reviewers, ...)`, run the disagreement
    checker over the four review outputs, producing a list of
    `{topic, reviewers_for, reviewers_against, evidence}` entries.
  - New report section "Cross-reviewer conflicts" inserted between
    the per-reviewer comments and the implementer iteration.
  - Judge prompt updated to receive the conflict list as additional
    input.

## Constraints

- **Backwards-compatible report shape**: existing committed reports
  in `pr-review-rehearsal/reports/` must remain readable; the new
  section is additive only.
- **No extra GitHub fetches**: disagreement detection works on the
  in-memory review outputs.
- **Honest empty case**: if there are no real conflicts, the new
  section says so explicitly rather than making things up.

## Out of scope

- A web UI for reviewing the conflicts.
- Mirroring disagreements back to actual GitHub PR comments.
- Persistent cross-PR disagreement memory (separate experiment).

## Affected stakeholders

- `pr-review-rehearsal` (the change)
- `mirofish_lab` (new persona)
- Anyone consuming the existing report format
