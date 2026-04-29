# Closed-Loop Hardening — intent_acme_pydantic_v2

> Intent: validation/real_world_demo/intent_acme_pydantic_v2.md · Threshold: 0.3 · Max iterations: 5 · Converged: no · Reason: iteration 1: hardened plan infeasible by Z3 (unsat core size 2) · Initial fragility: 0.5 · Final fragility: 0.5 · Model: gpt-5.4-mini

_Generated 2026-04-29T22:15:27Z_

## Convergence summary

- iterations run: 1 (after base)
- final reason: **iteration 1: hardened plan infeasible by Z3 (unsat core size 2)**
- fragility trajectory: 0.5 → 0.5

## Trajectory

| Iter | Stage | Steps | Fragility | Δ | SMT feasible | Top Achilles |
|---|---|---|---|---|---|---|
| 0 | base | 10 | 0.5 | — | N | [['S1'], ['S2'], ['S3']] |
| 1 | hardened | 10 | 0.5 | 0.0 | N | [['S1'], ['S2'], ['S3']] |

## Iteration 1 — diff

- edits:
-   - S8.rollback: 'flip the rollout flag back to v1 behavio' → 'flip the rollout flag back to v1 behavio'
-   - S5.action: 'Generate the v2 OpenAPI schema, run sche' → 'Generate the v2 OpenAPI schema from the '
-   - S6.rollback: 'withhold client v2 publish and redeploy_' → 'withhold client v2 publish and restore p'

## Final plan

{
  "summary": "Migrate FastAPI/Pydantic with staged compatibility, schema review, dual-support, and gated production cutover.",
  "steps": [
    {
      "id": "S1",
      "action": "Run inventory and codemod dry-run: apply bump-pydantic across the repo, enumerate validator/root_validator, encoders, orm_mode, dict/json, and schema-affecting models.",
      "owner": "BackendOwner",
      "depends_on": [],
      "gate": "none",
      "rollback": "revert codemod working tree changes",
      "observability": "Codemod diff size, list of touched models/routes, count of remaining v1 APIs"
    },
    {
      "id": "S2",
      "action": "Manually rewrite the 6 root validators, 3 json_encoders to field_serializer, orm_mode models to ConfigDict(from_attributes=True), and replace .dict()/.json() call sites that codemod missed.",
      "owner": "BackendOwner",
      "depends_on": [
        "S1"
      ],
      "gate": "wait_for:unit_and_contract_tests_pass",
      "rollback": "revert model and serializer changes to last known good commit",
      "observability": "Unit test failures, serializer output diffs, model validation regressions"
    },
    {
      "id": "S3",
      "action": "Characterize Pydantic v2 coercion changes on charge/payment request models, add explicit strict=False only where approved, and fix validator ordering/async-validator replacements for the 2 tax-service endpoints.",
      "owner": "BackendOwner",
      "depends_on": [
        "S2"
      ],
      "gate": "monitor:validation-rejection-rate increase <=0.1%",
      "rollback": "restore prior validation logic and remove newly relaxed fields",
      "observability": "Validation rejection rate, payload samples that now fail, tax-service call success/error rates"
    },
    {
      "id": "S4",
      "action": "Prepare compatibility shim and regression suite for legacy .dict()/.json() consumers, then verify request/response parsing works for both old and new client expectations.",
      "owner": "ConsumerSubsystem",
      "depends_on": [
        "S2",
        "S3"
      ],
      "gate": "wait_for:shim regression tests passing for legacy .dict()/.json() consumers",
      "rollback": "disable shim path and revert parsing/serialization compatibility changes",
      "observability": "Shim test pass rate, parsed payload equivalence, serialization round-trip diffs"
    },
    {
      "id": "S5",
      "action": "Generate the v2 OpenAPI schema, run schema diff checks, and validate critical endpoints against both v1 and v2 client test suites.",
      "owner": "DataPlatform",
      "depends_on": [
        "S4"
      ],
      "gate": "wait_for:approved_schema_diff_report",
      "rollback": "do not publish the new schema artifacts; revert generated outputs to v1 and keep existing client versions",
      "observability": "Schema diff report, endpoint test matrix, breaking-change candidates"
    },
    {
      "id": "S6",
      "action": "Publish the new major TypeScript client @acme/payments-client@2.x and regenerate the mobile SDK from the approved schema diff.",
      "owner": "ProductPM",
      "depends_on": [
        "S5"
      ],
      "gate": "wait_for:consumer migration notice sent",
      "rollback": "withhold client v2 publish and redeploy_previous",
      "observability": "Package publish success, SDK generation success, consumer notice delivery status"
    },
    {
      "id": "S7",
      "action": "Run partner-integrator and internal consumer comms for the new schema/client, then wait for mobile SDK to be shipped to app stores and in users' hands before any breaking server-side schema change.",
      "owner": "ProductPM",
      "depends_on": [
        "S6"
      ],
      "gate": "window:partner_notice_14d",
      "rollback": "revert to prior public schema/client release and suspend rollout",
      "observability": "Notice date, app store release status, rollout/installation telemetry"
    },
    {
      "id": "S8",
      "action": "Deploy the compatibility server release behind a feature flag with both v1 and v2 serialization paths enabled, keeping response shapes backward compatible during the transition.",
      "owner": "SRE",
      "depends_on": [
        "S3",
        "S4",
        "S5",
        "S7"
      ],
      "gate": "monitor:validation-rejection-rate<0.1%",
      "rollback": "flip the rollout flag back to v1 behavior; redeploy_previous",
      "observability": "Canary error rate, validation rejection rate, response-shape parity, p99 validation latency"
    },
    {
      "id": "S9",
      "action": "Promote canary to wider production only after 24h stable canary, security approval, SRE rollback verification, and support/escalation staffing are in place.",
      "owner": "SRE",
      "depends_on": [
        "S8"
      ],
      "gate": "wait_for:24h stable canary with no error-budget burn",
      "rollback": "reduce traffic to the previous deployment slice and keep the flag on v1",
      "observability": "Error-budget burn, canary stability, SRE approval status, support coverage, p99 latency"
    },
    {
      "id": "S10",
      "action": "Complete SOC2 evidence update and post-cutover monitoring, then keep dual-support active for at least 8 weeks while tracking consumer migration and downstream parse errors.",
      "owner": "Security",
      "depends_on": [
        "S9"
      ],
      "gate": "monitor:downstream_parse_error_rate<=0.1%",
      "rollback": "pause rollout and revert to previous validated release",
      "observability": "SOC2 review completion, downstream parse errors, consumer migration coverage, audit trail coverage"
    }
  ],
  "open_questions": [
    "Which request models need explicit strict=False relaxation versus rejecting new coercions?",
    "What exact compatibility shim behavior is required for legacy .dict()/.json() consumers?",
    "Are any mobile-facing schema changes actually breaking, or can they be kept additive?",
    "What is the approved schema diff threshold for publishing v2 artifacts?",
    "Who provides the named SRE support/escalation approval for the rollout window?"
  ],
  "conflicts": [
    {
      "between": [
        "BackendOwner",
        "ProductPM"
      ],
      "issue": "BackendOwner wants v1/v2 contract compatibility during transition, while ProductPM requires partner notice before externally visible schema/client changes; resolved by sequencing comms before publish and keeping compatibility during rollout."
    },
    {
      "between": [
        "BackendOwner",
        "ConsumerSubsystem"
      ],
      "issue": "BackendOwner wants dual-serialize support until consumers migrate, while ConsumerSubsystem requires a minimum 8-week dual-support window; resolved by maintaining dual support after v2 publish and before any retirement."
    },
    {
      "between": [
        "BackendOwner",
        "SRE"
      ],
      "issue": "BackendOwner wants schema/serializer changes deployed before dependent code, while SRE requires gated canary and rollback-ready rollout; resolved by doing code/schema prep first, then canary under feature flag."
    },
    {
      "between": [
        "DataPlatform",
        "ProductPM"
      ],
      "issue": "DataPlatform requires schema diff approval before publishing v2 JSON/OpenAPI, while ProductPM requires partner notice before schema/client changes; resolved by diff review first, then notice, then publish."
    },
    {
      "between": [
        "DataPlatform",
        "SRE"
      ],
      "issue": "DataPlatform wants off-peak maintenance windows and throttled backfills, while SRE wants Mon-Thu daytime canary/promotion without incidents; resolved by avoiding backfills in cutover and limiting rollout to approved windows."
    },
    {
      "between": [
        "Security",
        "ProductPM"
      ],
      "issue": "Security requires SOC2 evidence completion and approval for validation parity, while ProductPM requires staffing and launch-window avoidance for release timing; resolved by finishing security review before production promotion."
    },
    {
      "between": [
        "Security",
        "ConsumerSubsystem"
      ],
      "issue": "Security requires audit/trust review of relaxed validation paths, while ConsumerSubsystem requires a dual-support window and rollback verification; resolved by keeping dual-support while security validates parity and audit coverage."
    },
    {
      "between": [
        "ProductPM",
        "ConsumerSubsystem"
      ],
      "issue": "ProductPM requires internal consumer notice before client v2 publication, while ConsumerSubsystem requires maintaining old client support for 8 weeks after publish; resolved by notice first, publish second, then long dual-support."
    }
  ]
}
