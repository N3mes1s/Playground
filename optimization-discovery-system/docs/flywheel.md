# The flywheel: from static corpus to self-growing

> A previous critique: the product felt static — 61 hand-authored
> recipes, no visible mechanism for per-repo adaptation, the
> "self-curating corpus" claim was aspirational. This commit makes
> the flywheel real. Three concrete feedback loops, three
> before/after tables, one honest assessment of what's still
> missing.

## The previous state (honest audit)

What we claimed the product did | What it actually did
--- | ---
Harvests every win into a reusable recipe | Wrote a `candidate` recipe whose `ast_pattern` was the literal changed line — not a tree-sitter trigger. The Generalizer code existed but was never called (orchestrator invoked `harvest::harvest(...)`, which passes `None` for the LLM client, skipping Phase 2).
Surveys each repo for new patterns | `ods explore` was a separate CLI command. `ods run` didn't invoke the Explorer at all. Per-repo Hypothesized recipes only entered the corpus when a human ran `ods explore` manually.
Cross-repo success transfers | Schema had `success_history`. Retrieval ignored it — `retrieval_score` only used `promotion_weight * (1 - negative_penalty)`, so a recipe proven on 5 repos scored identically to one proven nowhere.

Net effect: the corpus only grew when I hand-edited YAML files. The
product was a database of recipes I'd written, with a query engine
over it. Not a flywheel.

## Three closed loops this commit adds

### Loop #1 — Generalizer runs after every win

`orchestrator.rs` now calls `harvest::harvest_full(..., Some(client))`
when a race has a winner. Phase 2 takes the patch + the specialist's
rationale and asks the LLM to describe the REUSABLE pattern (not the
specific change) as a tree-sitter S-expression recipe with pattern-
level transformation steps and no repo-specific identifiers.

Every win now produces **two** recipes:
- a Candidate keyed on the specific target (provenance; one-line `ast_pattern`);
- a Hypothesized "general-*" recipe with a real tree-sitter trigger,
  linked back to the Candidate via `generalized_from` / `generalized_as`.

The Hypothesized generalisation is what the NEXT run on a DIFFERENT
repo will retrieve against. That's the transferable shape.

Prompt change: Generalizer now demands a tree-sitter S-expression
with at least one `@capture` (was "regex/tree-sitter", leaning on
the regex path we deleted in Stage 11).

### Loop #2 — Explorer runs in the main loop

Before `RecipeRetrieve` fires its corpus query, the orchestrator now
runs the Explorer against the current repo in read-only mode. Budget
capped at $0.75 (or 15% of the spend cap, whichever is smaller) so
that a normal $5 race still has >80% of the budget for patches.

Proposed recipes land as `Hypothesized` in the store immediately.
That means:

- The SAME run's Planner query will see them (they're above the
  min_promotion floor).
- Specialists can be seeded by them.
- Wins on Explorer-proposed recipes flow through the harvester,
  including Loop #1, so an Explorer idea can become a validated
  cross-repo pattern within one or two runs.

The Explorer still never applies patches (read-only tool set).

### Loop #3 — Cross-repo successes boost retrieval

`retrieval_score` now multiplies the promotion-weight/negative-penalty
product by a cross-repo-transferability boost:

```
distinct_repos = unique(success_history.repo)
boost = 1 + 0.25 * min(distinct_repos - 1, 4)
       # 1.0 with 0-1 repo, linearly up to 2.0 after 5 distinct repos
```

A recipe that's won on 5 different codebases retrieves at 2× the
weight of an otherwise-identical recipe proven nowhere. DISTINCT is
the word — ten successes on the same repo count as one repo
(measured transferability, not frequency). Two new unit tests lock
both properties in.

## Before / after per-run corpus behaviour

Scenario | Before | After
--- | --- | ---
First run on a new Rust repo, race produces a winning patch | 1 Candidate recipe (specific one-liner) added. | 1 Candidate + 1 Hypothesized general tree-sitter recipe added (`generalized_from` links them). Explorer also proposes up to 5 more Hypothesized recipes before the race runs.
Second run, different repo, same win pattern repeats | Same one-liner already in corpus but can't retrieve on a different function. No transfer. | Hypothesized general recipe matches the new target. Planner retrieves it. Specialist applies it — win faster, cost less. Distinct-repos boost applied to its score for future runs.
A recipe that worked on 3 prior repos vs a brand-new one | Identical retrieval rank. | Boosted recipe retrieves at 1.5× the fresh one's score (and grows to 2× after 5 distinct repos).
Per-repo negative signal | Written to schema but NOT consulted by the Discoverer; only reached the Planner's post-retrieval re-rank. | Same — not changed in this commit. Flagged as the next flywheel fix.

## What this still doesn't do

Being honest about the remaining gap:

- **Explorer proposals are never fact-checked against bench data.**
  A Hypothesized recipe that's LLM-hallucinated but not validated
  still pollutes the retrieval pool until its `negative_history`
  accumulates enough down-weight. Short-term this is OK (negatives
  DO down-weight it); medium-term we'd want the Explorer to run the
  Discoverer's tree-sitter validator on every proposed pattern
  before upserting, rejecting any that don't compile.
- **The `generalized_from` / `generalized_as` links aren't surfaced
  in the PR body.** A reviewer looking at an auto-PR sees the
  specific Candidate id but has to grep the store to find the
  sibling Hypothesized general recipe. Not hard to fix.
- **No corpus GC.** Recipes with many `negative_history` entries and
  zero `success_history` should auto-demote to `AntiPattern` or
  get deleted. `promote.rs` has the rule; it isn't wired to the
  harvest-write path.
- **Cross-repo boost is linear and uncalibrated.** "0.25 per distinct
  repo, capped at 2×" is a guess. Once we have >50 runs we'll have
  data to tune it.

## Numbers we want to see after N runs

Concrete check on whether the flywheel is doing work:

- **Corpus growth rate ≥ 1 per win.** Every winning run should add at
  least one Hypothesized general recipe. Verify in the artifact's
  `generalized_recipe` field post-Loop-#1.
- **Cross-repo recipe retrieval on the 2nd-5th run.** On a 3rd run
  targeting a new repo, the Planner should retrieve at least one
  recipe whose `success_history.repo` != this repo. That proves
  transfer is happening.
- **Explorer proposals that survive.** After 10 runs, count how many
  Hypothesized recipes proposed by the Explorer eventually promoted
  to Candidate or Validated. If the ratio is <5% the Explorer prompt
  needs sharpening. If >30% we're onto something.

We don't have the data yet — the infrastructure shipped this commit
is what MAKES those numbers observable.

## Calibration note (Stage 18)

Three flywheel constants ship with hand-picked defaults and will stay
guesses until we have >50 runs of real data to tune them:

1. **Cross-repo boost** — `0.25 per distinct repo in a recipe's
   success_history, capped at +2.0` (in `ods-recipes::store`). Too
   low and a recipe proven on 5 repos gets ranked below a Seed with
   no history; too high and one lucky cross-repo win drowns out
   better-fitting recipes.
2. **Precision penalty** — `sqrt(rejections / proposals), applied at
   0.5x weight` (in `ods-agents::discover::precision_penalty`).
   Calibrated once against the 12-repo dogfood pass but not
   re-tested since the corpus grew.
3. **Demote threshold** — `5 negatives with 0 successes triggers
   AntiPattern demotion` (in `ods-recipes::promote`). Picked to be
   stricter than the `3-repos-with-0-wins` retire rule for
   Hypothesized but still forgiving enough that one bad run won't
   kill a seeded pattern.

**Unblocking the calibration.** `ods recipes stats` (shipped Stage 17)
now aggregates per-recipe wins, distinct-repos, negatives, and median
speedup. Run it after each batch of runs lands and eyeball the
distribution. Specifically: once any recipe has `distinct_repos >= 3`
with `speedup_median >= 1.5x`, compare its retrieval rank with and
without the cross-repo boost to see whether the boost is earning its
keep or dominating the score. Then tune.

**Gate 2 behaviour confirmed.** Stage 18 added a second Explorer
validation step: proposals that compile against the language grammar
but don't match **any** file in the repo the Explorer just surveyed
are rejected at the write boundary. That closes the last silent
pollution path; the `AgentEvent::RecipeRejected` event is emitted
with a reason string so per-run diagnostics are visible in the
artifact.
