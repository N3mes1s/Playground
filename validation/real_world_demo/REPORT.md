# Real-world demo: Acme Payments API — Pydantic v1 → v2 migration

This is the playground's full pipeline applied to a **real, recent,
well-documented industry migration**: a hypothetical company ("Acme
Corp") moving its production payments API from FastAPI 0.95.2 +
Pydantic 1.10 to FastAPI 0.110 + Pydantic 2.7.

The migration is real (FastAPI 0.100.0 added Pydantic v2 support in
July 2023). The intent fixture is grounded in the actual breaking
changes: ~180 Pydantic models, 40 `@validator` decorators, 6
`@root_validator`, 12 `Config.orm_mode = True`, 3 custom encoders via
`Config.json_encoders`, an OpenAPI-derived TypeScript client consumed
by ~30 internal services, mobile SDKs with app-store submission
cycles. See `intent_acme_pydantic_v2.md` for the full intent.

## TL;DR — what the pipeline produced

| Output | Where | Headline finding |
|---|---|---|
| **Stakeholder constraints** | `cli_pro.json` | 23 structured constraints across all 6 stakeholders. DataPlatform 3, Backend 4, SRE 4, Security 4, ProductPM 4, ConsumerSubsystem 4. |
| **6-plan Pareto frontier** | `cli_pro.md` | Plans range from 10 to 12 steps; recommendation `02-speed-leaning` by user-supplied utility weights. |
| **Z3 SMT verification** | `cli_pro.md` | **All 6 Pareto plans flagged infeasible** with concrete unsat cores. The recommended plan has a 2-edge cycle: `S5 depends_on S4` while DataPlatform's `wait_for:published_openapi_v2` constraint requires S5 *before* S4. |
| **Static cascade analysis** | `cli_chaos.md` | Single-point bottleneck at S1 (root) — its failure cascades to every other step. Fragility curve: k=1→0.49, k=2→0.66, k=3→0.75. |
| **LLM ↔ static cross-validation** | `cli_chaos.md` | **5/5 agreement** on top Achilles steps; no false positives, no missed steps. |
| **Adversarial chaos search** | `cli_chaos.md` | Found fragility 1.0 worst-K=2 pair `(S1, S2)` matching the exhaustive optimum. |
| **Monte Carlo** | `cli_chaos.md` | Probabilistic full-success rate **0.56**, full-failure rate **2.6%**. Per-step failure rate identifies S8 (an approval-gate step) as highest individual risk at 0.11. |
| **Closed-loop hardening** | `cli_harden.md` | Hardener bailed at iteration 1: produced new SMT-infeasible plan; loop stopped safely. **Surfaces a real limit**: SMT-infeasible bases on complex multi-stakeholder migrations are hard to fix in one Hardener pass. |

## What an engineer using this would actually do with the output

### 1. Fix the Z3-flagged ordering bug FIRST

Z3 found a 2-edge unsat core in the recommended plan:

```
- step `S5` depends_on `S4` (so `S4` must be earlier)
- DataPlatform's blocking constraint requires `S5` before `S4`
  (gate `wait_for:published_openapi_v2_and_signed_off_schema_diff`)
```

This is a real contradiction. Either:
- `S5` shouldn't depend on `S4` (the sequencer over-eager-coupled them), or
- DataPlatform's constraint actually means something different and shouldn't require S5-before-S4 ordering.

The fix is a 1-line change to one or the other. Without Z3, the bug
ships unnoticed and shows up as "weird, the rollout got stuck on
step S5" three days into the migration.

### 2. Address the S1 single-point-of-failure

Static analysis: failing S1 cascades to all 10 downstream steps.
S1 in the recommended plan is the bump-pydantic codemod step — the
single biggest blast-radius step. Mitigation options the chaos
analysis suggests:

- Run the codemod on a clean branch, get it merged green, deploy
  with `pydantic.v1.BaseModel` shim still loaded so the migration
  is reversible.
- Split S1 into per-package codemod runs (`app/models/` first,
  `app/schemas/` second) so a failure in one doesn't block the rest.

### 3. Tighten S8 (highest MC failure rate)

S8 is the iOS+Android SDK regeneration + app-store submission step.
MC predicts 11% failure rate driven by its `approval:mobile_release`
gate. Real-world echo: app-store rejections happen, this matches.

The Hardener's logic suggests replacing this with a `monitor:` gate
(post-submission build monitoring) or splitting submission into
TestFlight + production phases.

### 4. Accept the residual risk OR invest

After fixing #1, the residual fragility is dominated by S1 (root,
unavoidable for any sequential plan). The MC's 2.6% catastrophic
failure rate is the real "if everything went wrong simultaneously"
floor; that's a number to discuss with leadership rather than chase
to zero.

## How this run validates the playground's overall design

| Validation axis | Evidence in this run |
|---|---|
| **Multi-stakeholder constraints surface real issues** | DataPlatform's `wait_for:published_openapi_v2` is the kind of constraint a graph-based tool (Greptile, blast-radius.dev) would never see — it's about *what humans agreed on*, not *what files import what*. |
| **Z3 catches real ordering bugs** | The S4/S5 unsat core is a real contradiction the LLM produced, found in seconds. |
| **Cross-validation reduces false positives** | LLM probe and static analysis agreed 5/5 on Achilles. The earlier "LLM hallucinates Achilles" concern is empirically not a problem here. |
| **Adversarial search finds the optimum** | Search found exhaustive-best at k=2 on an 11-step real plan. |
| **MC gives probabilistic risk** | "Your migration has 56% chance of full clean rollout, 2.6% chance of catastrophic failure" is a number the binary chaos probe couldn't give. |
| **Closed-loop hardening surfaces real limits honestly** | The loop bailed safely on SMT-infeasible re-attempts, rather than committing a broken plan. The "Hardener can't always fix infeasibility in one pass" finding is real and documented. |

## What this run does NOT validate

- **No real production data**: this is a hypothetical Acme Corp; no
  actual telemetry from a real Pydantic v2 migration.
- **MC priors are heuristic**: real failure rates per gate type would
  need calibration from actual production data.
- **Single intent**: real validation against this approach should
  run 20+ real industry migrations and compare to actual outcomes.

## Reproduce

```bash
cp .env.example .env
pip install -r requirements.txt

python verified-rollout/cli_pro.py \
    validation/real_world_demo/intent_acme_pydantic_v2.md \
    --n-plans 6 --chaos-pairs 2 \
    --utility "fragility=0.4,coverage=0.3,steps=0.1,severity=0.15,rollback_failure=0.05" \
    --out validation/real_world_demo/cli_pro.md

python verified-rollout/cli_chaos.py \
    validation/real_world_demo/intent_acme_pydantic_v2.md \
    --mc-samples 500 --search-rounds 3 --search-k 2 \
    --out validation/real_world_demo/cli_chaos.md

python verified-rollout/cli_harden.py \
    validation/real_world_demo/intent_acme_pydantic_v2.md \
    --threshold 0.3 --max-iterations 5 \
    --out validation/real_world_demo/cli_harden.md
```

Total LLM cost: ~150 calls (~$0.30 on `gpt-5.4-mini`).
