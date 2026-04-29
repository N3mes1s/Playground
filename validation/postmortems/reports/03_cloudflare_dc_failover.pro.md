# Verified Rollout (PRO) — 03_cloudflare_dc_failover

> Intent: /home/user/Playground/validation/postmortems/intents/03_cloudflare_dc_failover.md · N plans: 4 · Pareto-front size: 3 · Recommendation: 00-cost-leaning · Utility weights: {"fragility": 0.4, "coverage": 0.3, "steps": 0.1, "severity": 0.15, "rollback_failure": 0.05} · Model: gpt-5.4-mini

_Generated 2026-04-29T20:35:35Z_

## Recommendation

**00-cost-leaning** — rank-0 (Pareto-optimal), utility -0.116 under user weights.

## Pareto frontier (NSGA-II)

_4 plans, 3 on the Pareto front._

| Plan | Weights (s/sf/c) | Rank | Crowding | Fragility | Cov | Steps | Severity | RB-fail |
|---|---|---|---|---|---|---|---|---|
| 00-cost-leaning | 0.00/0.00/1.00 | 0 | ∞ | 0.62 | 1.00 | 11 | 2.73 | 0.55 |
| 01-safety-leaning | 0.00/1.00/0.00 | 0 | ∞ | 0.80 | 1.00 | 12 | 3.00 | 0.27 |
| 02-speed-leaning | 1.00/0.00/0.00 | 0 | ∞ | 1.00 | 1.00 | 9 | 3.00 | 0.18 |
| 03-safety-tilted | 0.00/0.50/0.50 | 1 | ∞ | 0.86 | 1.00 | 12 | 3.36 | 0.29 |

## Pareto chart

```
y=steps (lower is better) ↑    Pareto front: '*'   dominated: '.'
                            *       .                       
                                                            
                                                            
                                                            
                                                            
                                                            
*                                                           
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                           *
────────────────────────────────────────────────────────────
        x=fragility (lower is better) →   range [0.62, 1.00]
```

## Plan: 00-cost-leaning (weights (0.0, 0.0, 1.0))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Open incident war room, assign named incident manager, support lead, and comms o | ProductPM | — | `approval:on_call_incident_manager` | Reassign escalations to the primary incident channel and sen |
| S2 | Inventory PDX-01-bound secrets/certs/tokens and approve a rotation plan for any  | Security | S1 | `approval:security_compliance` | Revoke newly issued credentials and restore the prior secret |
| S3 | Verify secondary DC configuration parity, dependencies, and runbook order for th | SRE | S1 | `wait_for:code_and_dependency_parity_verified` | Revert planning changes and restore prior routing assumption |
| S4 | Freeze schema changes for migrated datastores and confirm the cutover occurs wit | DataPlatform | S1 | `window:outside_business_hours` | Reapply the last known stable schema migration or redeploy_p |
| S5 | Bring up secondary control-plane and analytics services in dependency order, inc | BackendOwner | S2, S3, S4 | `wait_for:secondary_stack_healthy` | Redeploy the control-plane services back to PDX-01 and resto |
| S6 | Validate secondary read/write capability for control-plane state and verify fail | ConsumerSubsystem | S5 | `wait_for:secondary_read_write_validation` | Redeploy_previous and revert routing to PDX-01 primary mappi |
| S7 | Fail over replication for analytics and control-plane state to secondary, keepin | DataPlatform | S6 | `monitor:replication_lag<60s` | Stop secondary writes and resume single-writer mode in PDX-0 |
| S8 | Shift writer role and traffic routing for control-plane services to secondary in | SRE | S7 | `wait_for:each_stage_stable` | Fail back the last moved service group to PDX-01 and restore |
| S9 | Complete customer-facing auth, TLS, and endpoint cutover for dashboard, API, ter | Security | S8 | `approval:security_compliance` | redeploy_previous |
| S10 | Confirm customer communications, support briefing, and rollout status updates ar | ProductPM | S1, S8 | `approval:support_lead_briefed` | Send support war room update and resend briefing; retract no |
| S11 | Hold the legacy PDX-01 rollback path and preserve old primary-side tables/volume | DataPlatform | S8 | `wait_for:48h_quiet_period_after_cutover` | Retain old tables/volumes and re-enable access if rollback i |

## SMT verification: 00-cost-leaning

- backend: `z3` (11 steps, 13 dep edges, 6 constraint edges)
- feasible: **False**
Plan **infeasible**. Minimal conflicting set (3 edges):
- step `S5` depends_on `S3` (so `S3` must be earlier)
- step `S6` depends_on `S5` (so `S5` must be earlier)
- ProductPM's blocking constraint requires `S6` before `S3` (gate `wait_for:customer_notification_sent`)

These edges form a cycle in the partial order. To fix: drop or weaken one of them, or insert an intermediate step that lets both orderings be satisfied.

## Chaos probe: 00-cost-leaning

- **fragility (overall)**: 0.618
- **fragility curve**: budget=1 → 0.6, budget=2 → 0.8
- **avg severity**: 2.73 (1=low … 4=critical)
- **rollback-failure rate**: 0.545 (5/11 probes)
- **recovery distribution**: recoverable_in_window=4, manual_ops=7
- **Achilles heel** (top 5 by per-step fragility):
  - `S1` → 1.0
  - `S2` → 1.0
  - `S3` → 1.0
  - `S4` → 1.0
  - `S6` → 0.4

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | high | yes | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
| S2 | gate_violation | medium | yes | S5, S6, S7, S8, S9, S10 | recoverable_in_window |
| S3 | gate_violation | high | yes | S5, S6, S7, S8, S9, S10 | recoverable_in_window |
| S4 | gate_violation | medium | yes | S5, S6, S7, S8, S9, S10 | recoverable_in_window |
| S5 | gate_violation | medium | NO | — | manual_ops |
| S6 | gate_violation | medium | NO | — | manual_ops |
| S7 | gate_violation | medium | NO | — | manual_ops |
| S8 | gate_violation | medium | NO | — | manual_ops |
| S1 | rollback_failure | critical | NO | S2, S3, S4, S5, S6, S7 | manual_ops |
| S2 | rollback_failure | critical | NO | S5, S6, S7, S8, S9, S10 | manual_ops |
| S6, S7 | gate_violation | critical | yes | S8, S9, S10, S11 | manual_ops |

## Plan: 01-safety-leaning (weights (0.0, 1.0, 0.0))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Declare incident, name the incident manager, brief support, send customer notice | ProductPM | — | `approval:on_call_incident_manager` | Reassign escalations to the primary incident channel and sen |
| S2 | Approve the failover plan, freeze schema changes, and inventory any PDX-01-bound | Security | S1 | `approval:security_compliance` | Reapply the last known stable schema migration or redeploy_p |
| S3 | Bring up and validate the secondary-datacenter control-plane and analytics stack | SRE | S2 | `wait_for:secondary_stack_healthy` | Redeploy the moved control-plane services back to PDX-01 and |
| S4 | Validate code, config, storage consumers, and read/write behavior in secondary D | ConsumerSubsystem | S3 | `wait_for:secondary_read_write_validation` | Revert routing to PDX-01 and redeploy previous binaries in t |
| S5 | Fail over replication for analytics and configuration state, then confirm second | DataPlatform | S3 | `wait_for:secondary_dc_replication_caught_up` | Repoint analytics services back to PDX-01 primary and resume |
| S6 | Rotate or reissue any PDX-01-bound credentials and validate audit-log delivery t | Security | S2, S3 | `monitor:audit_log_delivery_loss<0.1%` | Pause migration, restore log forwarding to both DCs, and rep |
| S7 | Cut over the compatibility shim and service-discovery mappings in secondary DC,  | ConsumerSubsystem | S4, S6 | `wait_for:shim-validated-in-secondary-DC` | Disable the shim and route traffic back to primary mappings. |
| S8 | Shift a small, dependency-ordered slice of control-plane traffic to secondary DC | SRE | S4, S5, S6, S7 | `monitor:error_rate<0.1% and p95_latency<baseline+20% for 60m` | Restore previous routing weights or DNS targets to PDX-01 fo |
| S9 | Enable dual-write for configuration and analytics state during the overlap windo | BackendOwner | S8 | `monitor:replication_lag<60s` | Stop secondary writes and resume single-writer mode in PDX-0 |
| S10 | Flip writer authority to secondary only after secondary read/write validation an | BackendOwner | S9 | `wait_for:secondary_read_write_validation` | Fail back writer role to PDX-01 and disable secondary write  |
| S11 | Continue staged service-group cutovers with pauses between each stage until each | SRE | S10 | `wait_for:each_stage_stable` | Fail back the last moved service group to PDX-01 if dependen |
| S12 | Hold PDX-01-specific storage objects and decommissioning actions in place; do no | DataPlatform | S11 | `wait_for:48h_quiet_period_after_cutover` | Retain old tables/volumes and re-enable access if rollback i |

## SMT verification: 01-safety-leaning

- backend: `z3` (12 steps, 16 dep edges, 3 constraint edges)
- feasible: **False**
Plan **infeasible**. Minimal conflicting set (2 edges):
- step `S8` depends_on `S4` (so `S4` must be earlier)
- BackendOwner's blocking constraint requires `S8` before `S4` (gate `wait_for:secondary_read_write_validation`)

These edges form a cycle in the partial order. To fix: drop or weaken one of them, or insert an intermediate step that lets both orderings be satisfied.

## Chaos probe: 01-safety-leaning

- **fragility (overall)**: 0.8
- **fragility curve**: budget=1 → 0.857, budget=2 → 0.0
- **avg severity**: 3.0 (1=low … 4=critical)
- **rollback-failure rate**: 0.267 (4/15 probes)
- **recovery distribution**: recoverable_in_window=11, manual_ops=3, unrecoverable=1
- **Achilles heel** (top 5 by per-step fragility):
  - `S3` → 1.0
  - `S4` → 1.0
  - `S5` → 1.0
  - `S6` → 1.0
  - `S7` → 1.0

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | critical | yes | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
| S2 | gate_violation | high | yes | S3, S4, S5, S6, S7, S8 | recoverable_in_window |
| S3 | gate_violation | critical | yes | S4, S5, S6, S7, S8, S9 | recoverable_in_window |
| S4 | gate_violation | critical | yes | S7, S8, S9, S10, S11, S12 | recoverable_in_window |
| S5 | gate_violation | high | yes | S8, S9, S10, S11, S12 | recoverable_in_window |
| S6 | gate_violation | high | yes | S7, S8, S9, S10, S11, S12 | recoverable_in_window |
| S7 | gate_violation | high | yes | S8, S9, S10, S11, S12 | recoverable_in_window |
| S8 | gate_violation | high | yes | S9, S10, S11, S12 | recoverable_in_window |
| S9 | gate_violation | high | yes | S10, S11, S12 | recoverable_in_window |
| S10 | gate_violation | high | yes | S11, S12 | recoverable_in_window |
| S11 | gate_violation | medium | yes | S12 | recoverable_in_window |
| S1 | rollback_failure | medium | NO | — | manual_ops |
| S2 | rollback_failure | medium | NO | — | manual_ops |
| S3 | rollback_failure | critical | NO | S4, S5, S6, S7, S8, S9 | unrecoverable |
| S2, S8 | gate_violation | medium | NO | — | manual_ops |

## Plan: 02-speed-leaning (weights (1.0, 0.0, 0.0))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Inventory current PDX-01-dependent services, dependencies, secrets, and customer | SRE | — | `none` | Revert to the pre-migration service and dependency inventory |
| S2 | Prepare secondary DC by deploying/patching code, config, schemas, replication, l | BackendOwner | S1 | `wait_for:secondary_stack_healthy` | Redeploy previous binaries/config in the secondary DC and re |
| S3 | Validate secondary read/write capability for control-plane state and analytics d | DataPlatform | S2 | `wait_for:secondary_read_write_validation` | Fail writer role back to PDX-01 and stop secondary write tra |
| S4 | Install compatibility shim and keep API contracts backward-compatible while seco | ConsumerSubsystem | S2 | `wait_for:shim-validated-in-secondary-DC` | Disable shim and restore primary mappings |
| S5 | Complete security prerequisites: approve secret rotation plan, rotate PDX-01-bou | Security | S1, S2 | `approval:security_compliance` | Revoke newly issued credentials and restore prior secret set |
| S6 | Notify support and customers, assign incident owner, and publish the rollout sta | ProductPM | S1 | `wait_for:customer_notification_sent` | Retract notice and send follow-up restoration notice |
| S7 | Move analytics replication/ingestion primary handling to secondary and confirm n | DataPlatform | S3, S5 | `wait_for:secondary_dc_replication_caught_up` | Repoint analytics services back to PDX-01 primary and resume |
| S8 | Fail over control-plane service groups in dependency order, starting with lowest | SRE | S3, S4, S5, S6, S7 | `wait_for:each_stage_stable` | Fail back the last moved service group to PDX-01 and restore |
| S9 | Run post-cutover stabilization checks and keep PDX-01 as fallback until secondar | SRE | S8 | `monitor:error_rate<0.1% and p95_latency<baseline+20% for 60m` | Route traffic back to the previous DC for the impacted servi |

## SMT verification: 02-speed-leaning

- backend: `z3` (9 steps, 14 dep edges, 3 constraint edges)
- feasible: **False**
Plan **infeasible**. Minimal conflicting set (5 edges):
- BackendOwner's blocking constraint requires `S9` before `S2` (gate `wait_for:secondary_stack_healthy`)
- step `S8` depends_on `S4` (so `S4` must be earlier)
- step `S3` depends_on `S2` (so `S2` must be earlier)
- step `S9` depends_on `S8` (so `S8` must be earlier)
- ConsumerSubsystem's blocking constraint requires `S3` before `S4` (gate `wait_for:shim-validated-in-secondary-DC`)

These edges form a cycle in the partial order. To fix: drop or weaken one of them, or insert an intermediate step that lets both orderings be satisfied.

## Chaos probe: 02-speed-leaning

- **fragility (overall)**: 1.0
- **fragility curve**: budget=1 → 1.0, budget=2 → 1.0
- **avg severity**: 3.0 (1=low … 4=critical)
- **rollback-failure rate**: 0.182 (2/11 probes)
- **recovery distribution**: recoverable_in_window=9, manual_ops=2
- **Achilles heel** (top 5 by per-step fragility):
  - `S1` → 1.0
  - `S2` → 1.0
  - `S3` → 1.0
  - `S4` → 1.0
  - `S5` → 1.0

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | medium | yes | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
| S2 | gate_violation | high | yes | S3, S4, S5, S6, S7, S8 | recoverable_in_window |
| S3 | gate_violation | high | yes | S7, S8, S9 | recoverable_in_window |
| S4 | gate_violation | high | yes | S8, S9 | recoverable_in_window |
| S5 | gate_violation | high | yes | S7, S8, S9 | recoverable_in_window |
| S6 | gate_violation | medium | yes | S8, S9 | recoverable_in_window |
| S7 | gate_violation | high | yes | S8, S9 | recoverable_in_window |
| S8 | gate_violation | critical | yes | S9 | recoverable_in_window |
| S1 | rollback_failure | medium | NO | S2, S3, S4, S5, S6, S7 | manual_ops |
| S2 | rollback_failure | critical | NO | S3, S4, S5, S6, S7, S8 | manual_ops |
| S6, S7 | gate_violation | critical | yes | S8, S9 | recoverable_in_window |

## Plan: 03-safety-tilted (weights (0.0, 0.5, 0.5))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Convene the incident command path: assign named incident manager, brief support, | ProductPM | — | `approval:on_call_incident_manager` | reassign_escalations_to_primary_incident_channel |
| S2 | Freeze schema changes on migrated control-plane and analytics datastores, and ob | DataPlatform | S1 | `approval:security_compliance` | Reapply the last known stable schema migration or redeploy_p |
| S3 | Inventory and prepare rotation for all PDX-01-bound credentials, and preserve au | Security | S1, S2 | `wait_for:secret_inventory_and_rotation_plan_approved` | revoke newly issued credentials and restore prior secret set |
| S4 | Bring up the secondary-datacenter control-plane and analytics stack from runbook | BackendOwner | S2, S3 | `wait_for:secondary_stack_healthy` | Redeploy the control-plane services back to PDX-01 and resto |
| S5 | Validate code/config/storage parity and read-write behavior in secondary, includ | ConsumerSubsystem | S4 | `wait_for:code_and_dependency_parity_verified` | Revert routing to PDX-01 and redeploy previous binaries in t |
| S6 | Catch up analytics replication to secondary and enable controlled dual-write for | DataPlatform | S5 | `monitor:replication_lag<60s` | Stop secondary writes and resume single-writer mode in PDX-0 |
| S7 | Confirm secondary can serve reads and writes for control-plane state, then keep  | BackendOwner | S6 | `wait_for:secondary_read_write_validation` | Fail back writer role to PDX-01 and disable secondary write  |
| S8 | Cut over service groups in dependency order from PDX-01 to secondary using traff | SRE | S7 | `wait_for:each_stage_stable` | fail back the last moved service group to PDX-01 if dependen |
| S9 | After each staged cutover, hold for soak monitoring before proceeding to the nex | SRE | S8 | `monitor:error_rate<0.1% and p95_latency<baseline+20% for 60m` | route traffic back to the previous DC for the impacted servi |
| S10 | Flip customer-facing routing and DNS/LB targets to secondary for the control pla | ConsumerSubsystem | S9 | `approval:release-oncall` | restore previous routing weights or DNS targets to PDX-01 |
| S11 | Keep old API endpoint compatibility live during the post-cutover period and main | BackendOwner | S10 | `window:dual-support for 14 days after cutover` | redeploy_previous |
| S12 | Retain old primary-side tables and volumes during the quiet period, then decommi | DataPlatform | S10 | `wait_for:48h_quiet_period_after_cutover` | Retain old tables/volumes and re-enable access if rollback i |

## SMT verification: 03-safety-tilted

- backend: `z3` (12 steps, 13 dep edges, 2 constraint edges)
- feasible: **False**
Plan **infeasible**. Minimal conflicting set (3 edges):
- step `S4` depends_on `S3` (so `S3` must be earlier)
- ProductPM's blocking constraint requires `S5` before `S3` (gate `wait_for:customer_notification_sent`)
- step `S5` depends_on `S4` (so `S4` must be earlier)

These edges form a cycle in the partial order. To fix: drop or weaken one of them, or insert an intermediate step that lets both orderings be satisfied.

## Chaos probe: 03-safety-tilted

- **fragility (overall)**: 0.857
- **fragility curve**: budget=1 → 0.923, budget=2 → 0.0
- **avg severity**: 3.36 (1=low … 4=critical)
- **rollback-failure rate**: 0.286 (4/14 probes)
- **recovery distribution**: recoverable_in_window=10, manual_ops=4
- **Achilles heel** (top 5 by per-step fragility):
  - `S2` → 1.0
  - `S3` → 1.0
  - `S4` → 1.0
  - `S5` → 1.0
  - `S7` → 1.0

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | high | yes | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
| S2 | gate_violation | high | yes | S3, S4, S5, S6, S7, S8 | recoverable_in_window |
| S3 | gate_violation | high | yes | S4, S5, S6, S7, S8, S9 | recoverable_in_window |
| S4 | gate_violation | critical | yes | S5, S6, S7, S8, S9, S10 | recoverable_in_window |
| S5 | gate_violation | critical | yes | S6, S7, S8, S9, S10, S11 | recoverable_in_window |
| S6 | gate_violation | critical | yes | S7, S8, S9, S10, S11, S12 | recoverable_in_window |
| S7 | gate_violation | critical | yes | S8, S9, S10, S11, S12 | recoverable_in_window |
| S8 | gate_violation | critical | yes | S9, S10, S11, S12 | recoverable_in_window |
| S9 | gate_violation | critical | yes | S10, S11, S12 | recoverable_in_window |
| S10 | gate_violation | medium | yes | S11, S12 | recoverable_in_window |
| S1 | rollback_failure | medium | NO | — | manual_ops |
| S2 | rollback_failure | critical | NO | S3, S4, S5, S6, S7, S8 | manual_ops |
| S3 | rollback_failure | critical | NO | S4, S5, S6, S7, S8, S9 | manual_ops |
| S6, S8 | gate_violation | medium | NO | — | manual_ops |
