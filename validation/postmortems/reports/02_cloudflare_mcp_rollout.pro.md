# Verified Rollout (PRO) — 02_cloudflare_mcp_rollout

> Intent: /home/user/Playground/validation/postmortems/intents/02_cloudflare_mcp_rollout.md · N plans: 4 · Pareto-front size: 4 · Recommendation: 02-speed-leaning · Utility weights: {"fragility": 0.4, "coverage": 0.3, "steps": 0.1, "severity": 0.15, "rollback_failure": 0.05} · Model: gpt-5.4-mini

_Generated 2026-04-29T20:30:37Z_

## Recommendation

**02-speed-leaning** — rank-0 (Pareto-optimal), utility 0.123 under user weights.

## Pareto frontier (NSGA-II)

_4 plans, 4 on the Pareto front._

| Plan | Weights (s/sf/c) | Rank | Crowding | Fragility | Cov | Steps | Severity | RB-fail |
|---|---|---|---|---|---|---|---|---|
| 00-cost-leaning | 0.00/0.00/1.00 | 0 | ∞ | 0.85 | 1.00 | 12 | 2.87 | 0.40 |
| 01-safety-leaning | 0.00/1.00/0.00 | 0 | ∞ | 0.88 | 1.00 | 13 | 2.71 | 0.29 |
| 02-speed-leaning | 1.00/0.00/0.00 | 0 | ∞ | 0.09 | 1.00 | 9 | 2.00 | 0.91 |
| 03-safety-tilted | 0.00/0.50/0.50 | 0 | ∞ | 0.93 | 1.00 | 11 | 2.71 | 0.29 |

## Pareto chart

```
y=steps (lower is better) ↑    Pareto front: '*'   dominated: '.'
                                                       *    
                                                            
                                                            
                                                            
                                                            
                                                     *      
                                                            
                                                            
                                                            
                                                           *
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
*                                                           
────────────────────────────────────────────────────────────
        x=fragility (lower is better) →   range [0.09, 0.93]
```

## Plan: 00-cost-leaning (weights (0.0, 0.0, 1.0))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Confirm approved change window and outside launch/major-event timing; if not tru | SRE | — | `window:approved change window, excluding incident windows and Friday afternoon` | stop deployment and restore the last known-good routing stat |
| S2 | Send customer/partner notice, support rollout brief, and assign incident command | ProductPM | S1 | `window:advance_notice_before_customer_visible_change` | Send immediate incident update and hold further batches unti |
| S3 | Obtain network-ops approval for a very small initial batch and batch sizing plan | BackendOwner | S1 | `approval:network-ops` | redeploy_previous |
| S4 | Obtain network engineer, compliance, and network-ops-on-call approvals for stage | BackendOwner | S1, S2, S3 | `approval:network_engineer` | halt rollout and redeploy_previous |
| S5 | Deploy the updated routing config to a minimal canary batch of spine locations u | SRE | S2, S3, S4 | `monitor:customer-visible packet loss<0.1%` | revert the initial batch to the previous routing config befo |
| S6 | Hold the canary steady and watch for propagation lag, prefix leakage, traffic as | SRE | S5 | `wait_for:canary_72h_no_prefix_leakage` | pause rollout and redeploy_previous on the affected batch |
| S7 | Verify canary stability window and present results for promotion decision. | BackendOwner | S6 | `wait_for:canary_stability_window` | pause rollout and redeploy_previous on the affected batch |
| S8 | Check that customer/partner notice remains valid before any customer-visible exp | ProductPM | S7 | `wait_for:customer notice sent` | redeploy_previous |
| S9 | Expand to the next small batch only if canary is healthy and route behavior rema | SRE | S7, S8 | `monitor:batch_health=healthy` | roll back the most recent batch and keep remaining spines un |
| S10 | Pause expansion for a stabilization window after each batch before any further p | SRE | S9 | `wait_for:batch_stability_window` | pause rollout and redeploy_previous on the affected batch |
| S11 | Repeat monitored small-batch expansion until all 19 spine locations are on the n | SRE | S10 | `monitor:traffic_asymmetry=normalized` | pause rollout and revert any newly changed spine locations t |
| S12 | After all 19 locations are healthy, preserve audit trail and retain legacy confi | Security | S11 | `window:until_all_19_locations_confirmed_healthy` | restore_last_known_good_config_with_full_audit_log |

## SMT verification: 00-cost-leaning

- backend: `z3` (12 steps, 16 dep edges, 3 constraint edges)
- feasible: **False**
Plan **infeasible**. Minimal conflicting set (2 edges):
- step `S9` depends_on `S7` (so `S7` must be earlier)
- DataPlatform's blocking constraint requires `S9` before `S7` (gate `wait_for:canary_stability_window`)

These edges form a cycle in the partial order. To fix: drop or weaken one of them, or insert an intermediate step that lets both orderings be satisfied.

## Chaos probe: 00-cost-leaning

- **fragility (overall)**: 0.852
- **fragility curve**: budget=1 → 0.841, budget=2 → 1.0
- **avg severity**: 2.87 (1=low … 4=critical)
- **rollback-failure rate**: 0.4 (6/15 probes)
- **recovery distribution**: recoverable_in_window=9, manual_ops=5, unrecoverable=1
- **Achilles heel** (top 5 by per-step fragility):
  - `S1` → 1.0
  - `S4` → 1.0
  - `S5` → 1.0
  - `S6` → 1.0
  - `S7` → 1.0

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | medium | yes | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
| S2 | gate_violation | high | yes | S4, S5, S8, S9, S10, S11 | recoverable_in_window |
| S3 | gate_violation | high | yes | S4, S5, S6, S7, S8, S9 | recoverable_in_window |
| S4 | gate_violation | high | yes | S5, S6, S7, S8, S9, S10 | recoverable_in_window |
| S5 | gate_violation | critical | NO | S6, S7, S8, S9, S10, S11 | manual_ops |
| S6 | gate_violation | critical | NO | S7, S8, S9, S10, S11, S12 | manual_ops |
| S7 | gate_violation | medium | yes | S8, S9, S10, S11, S12 | recoverable_in_window |
| S8 | gate_violation | medium | yes | S9, S10, S11, S12 | recoverable_in_window |
| S9 | gate_violation | high | yes | S10, S11, S12 | recoverable_in_window |
| S10 | gate_violation | medium | yes | S11, S12 | recoverable_in_window |
| S11 | gate_violation | critical | NO | S12 | manual_ops |
| S1 | rollback_failure | critical | NO | S2, S3, S4, S5, S6, S7 | unrecoverable |
| S2 | rollback_failure | medium | NO | — | manual_ops |
| S3 | rollback_failure | medium | NO | — | manual_ops |
| S7, S9 | gate_violation | high | yes | S8, S9, S10, S11, S12 | recoverable_in_window |

## Plan: 01-safety-leaning (weights (0.0, 1.0, 0.0))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Confirm an approved maintenance window that is not Friday afternoon, not during  | SRE | — | `window:approved change window, excluding incident windows and Friday afternoon` | stop deployment and restore the last known-good routing stat |
| S2 | Send customer and partner advance notice, and brief support with the rollout pla | ProductPM | S1 | `window:advance_notice_before_customer_visible_change` | Send immediate incident update and hold further batches unti |
| S3 | Obtain required approvals for staged rollout beyond the first batch: network eng | BackendOwner | S1, S2 | `approval:network_engineer` | halt rollout and redeploy_previous |
| S4 | Reconfirm dry-run output and audit logging are attached to the change ticket, an | Security | S3 | `none` | restore_last_known_good_config_with_full_audit_log |
| S5 | Deploy the new routing config to a very small initial canary batch of 1 spine lo | SRE | S4 | `monitor:customer-visible packet loss<0.1%` | revert the initial batch to the previous routing config befo |
| S6 | Hold the canary on the new config for the full soak period and only continue if  | DataPlatform | S5 | `wait_for:24h of stable routing with no blackhole or reachability alerts` | pause rollout and revert any newly changed spine locations t |
| S7 | Review canary behavior against baseline and secure explicit promotion approvals  | BackendOwner | S6 | `approval:network_engineer` | halt rollout and redeploy_previous |
| S8 | Expand to the next small batch only if canary metrics remain healthy and propaga | SRE | S7 | `monitor:propagation lag<2m` | roll back the most recent batch and keep remaining spines un |
| S9 | After each batch, wait for stabilization before the next expansion and halt imme | BackendOwner | S8 | `wait_for:batch_stability_window` | pause rollout and redeploy_previous on the affected batch |
| S10 | Continue stepped rollout through the remaining spines in small batches, rechecki | ConsumerSubsystem | S9 | `monitor:prefix_reachability_errors0` | halt rollout and redeploy_previous |
| S11 | Before each further promotion, confirm canary/batch behavior matches baseline, c | Security | S10 | `approval:compliance` | halt_rollout_and_revert_to_previous_config |
| S12 | Complete rollout to all 19 spine locations only after the final batch remains he | BackendOwner | S11 | `monitor:traffic_asymmetry=normalized` | redeploy_previous |
| S13 | After all 19 locations are confirmed healthy, wait through the quiet period befo | DataPlatform | S12 | `wait_for:quiet_period_complete` | restore_old_routing_entries |

## SMT verification: 01-safety-leaning

- backend: `z3` (13 steps, 13 dep edges, 3 constraint edges)
- feasible: **False**
Plan **infeasible**. Minimal conflicting set (2 edges):
- step `S10` depends_on `S9` (so `S9` must be earlier)
- Security's blocking constraint requires `S10` before `S9` (gate `wait_for:canary_72h_no_prefix_leakage`)

These edges form a cycle in the partial order. To fix: drop or weaken one of them, or insert an intermediate step that lets both orderings be satisfied.

## Chaos probe: 01-safety-leaning

- **fragility (overall)**: 0.882
- **fragility curve**: budget=1 → 0.938, budget=2 → 0.0
- **avg severity**: 2.71 (1=low … 4=critical)
- **rollback-failure rate**: 0.294 (4/17 probes)
- **recovery distribution**: recoverable_in_window=12, manual_ops=5
- **Achilles heel** (top 5 by per-step fragility):
  - `S1` → 1.0
  - `S2` → 1.0
  - `S3` → 1.0
  - `S5` → 1.0
  - `S8` → 1.0

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | high | yes | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
| S2 | gate_violation | medium | yes | S3, S4, S5, S6, S7, S8 | recoverable_in_window |
| S3 | gate_violation | medium | yes | S4, S5, S6, S7, S8, S9 | recoverable_in_window |
| S4 | gate_violation | medium | yes | S5, S6, S7, S8, S9, S10 | recoverable_in_window |
| S5 | gate_violation | critical | yes | S6, S7, S8, S9, S10, S11 | recoverable_in_window |
| S6 | gate_violation | high | yes | S7, S8, S9, S10, S11, S12 | recoverable_in_window |
| S7 | gate_violation | medium | yes | S8, S9, S10, S11, S12, S13 | recoverable_in_window |
| S8 | gate_violation | high | yes | S9, S10, S11, S12, S13 | recoverable_in_window |
| S9 | gate_violation | high | yes | S10, S11, S12, S13 | recoverable_in_window |
| S10 | gate_violation | critical | yes | S11, S12, S13 | recoverable_in_window |
| S11 | gate_violation | medium | yes | S12, S13 | recoverable_in_window |
| S12 | gate_violation | critical | yes | S13 | recoverable_in_window |
| S1 | rollback_failure | critical | NO | S2, S3, S4, S5, S6, S7 | manual_ops |
| S2 | rollback_failure | medium | NO | S3, S4, S5, S6, S7, S8 | manual_ops |
| S3 | rollback_failure | medium | NO | S4, S5, S6, S7, S8, S9 | manual_ops |
| S4 | rollback_failure | medium | NO | — | manual_ops |
| S6, S7 | gate_violation | medium | NO | — | manual_ops |

## Plan: 02-speed-leaning (weights (1.0, 0.0, 0.0))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Confirm approved change window is open, notify customers/partners, and brief sup | ReleaseManager | — | `window:approved change window, excluding incident windows and Friday afternoon` | stop rollout and send immediate status update; resume only i |
| S2 | Run the routing-deploy tool for a single-spine canary batch with the smallest fe | NetworkOps | S1 | `none` | redeploy_previous for the initial batch and halt expansion |
| S3 | Monitor the canary for customer-visible packet loss, upstream flap rate, propaga | SRE | S2 | `monitor:batch_health=healthy` | revert the initial batch to the previous routing config befo |
| S4 | Obtain required expansion approvals for broader rollout after canary health is c | ReleaseManager | S3 | `approval:network_engineer` | halt rollout and redeploy_previous |
| S5 | Expand to the next small batch of spines, keeping the batch size well below a re | NetworkOps | S4 | `none` | pause rollout and redeploy_previous on the affected batch |
| S6 | Wait for the batch stability window and verify traffic asymmetry is normalizing  | SRE | S5 | `wait_for:batch_stability_window` | roll back the most recent batch and keep remaining spines un |
| S7 | Continue stepped rollout in additional small batches, repeating deploy then stab | NetworkOps | S6 | `monitor:traffic_asymmetry=normalized` | stop deployment and restore the last known-good routing stat |
| S8 | Perform the final validation pass that all 19 locations are on the new config an | SRE | S7 | `monitor:customer-visible packet loss<0.1%` | restore last known-good routing state with full audit log an |
| S9 | Complete cleanup of prior routing entries after the network has remained quiet. | NetworkOps | S8 | `wait_for:quiet_period_complete` | restore_old_routing_entries |

## SMT verification: 02-speed-leaning

- backend: `z3` (9 steps, 8 dep edges, 2 constraint edges)
- feasible: **False**
Plan **infeasible**. Minimal conflicting set (2 edges):
- Security's blocking constraint requires `S7` before `S6` (gate `wait_for:canary_72h_no_prefix_leakage`)
- step `S7` depends_on `S6` (so `S6` must be earlier)

These edges form a cycle in the partial order. To fix: drop or weaken one of them, or insert an intermediate step that lets both orderings be satisfied.

## Chaos probe: 02-speed-leaning

- **fragility (overall)**: 0.091
- **fragility curve**: budget=1 → 0.1, budget=2 → 0.0
- **avg severity**: 2.0 (1=low … 4=critical)
- **rollback-failure rate**: 0.909 (9/11 probes)
- **recovery distribution**: recoverable_in_window=1, manual_ops=10
- **Achilles heel** (top 5 by per-step fragility):
  - `S1` → 0.5
  - `S2` → 0.0
  - `S3` → 0.0
  - `S4` → 0.0
  - `S5` → 0.0

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | medium | yes | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
| S2 | gate_violation | medium | NO | — | manual_ops |
| S3 | gate_violation | medium | NO | — | manual_ops |
| S4 | gate_violation | medium | NO | — | manual_ops |
| S5 | gate_violation | medium | NO | — | manual_ops |
| S6 | gate_violation | medium | NO | — | manual_ops |
| S7 | gate_violation | medium | NO | — | manual_ops |
| S8 | gate_violation | medium | NO | — | manual_ops |
| S1 | rollback_failure | medium | NO | — | manual_ops |
| S2 | rollback_failure | medium | NO | — | manual_ops |
| S4, S7 | gate_violation | medium | NO | — | manual_ops |

## Plan: 03-safety-tilted (weights (0.0, 0.5, 0.5))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Send customer, partner, and support rollout notices; assign named incident escal | ProductPM | — | `approval:support lead` | Pause rollout and re-brief support on known symptoms, custom |
| S2 | Obtain required approvals to begin staged routing rollout, including network-ops | BackendOwner | S1 | `approval:network_engineer` | halt rollout and redeploy_previous |
| S3 | Start approved maintenance window and deploy the new MCP/BGP config to a very sm | SRE | S2 | `window:approved change window, excluding incident windows and Friday afternoon` | revert the initial batch to the previous routing config befo |
| S4 | Hold the canary batch and verify it remains stable with no prefix leakage, no pr | DataPlatform | S3 | `wait_for:canary_72h_no_prefix_leakage` | redeploy_previous |
| S5 | If canary remains healthy, expand to the next smallest batch, keeping the rollou | SRE | S4 | `monitor:batch_health=healthy` | roll back the most recent batch and keep remaining spines un |
| S6 | Soak the newly expanded batch until routing behavior is stable and traffic asymm | BackendOwner | S5 | `wait_for:24h of stable routing with no blackhole or reachability alerts` | pause rollout and redeploy_previous on the affected batch |
| S7 | Obtain explicit operator and compliance approval to proceed beyond the staged ba | BackendOwner | S6 | `approval:compliance` | halt rollout and revert to previous config |
| S8 | Expand rollout to the next small batch of remaining spine locations using the st | SRE | S7 | `monitor:upstream route flap rate<0.01%` | stop deployment and restore the last known-good routing stat |
| S9 | After each batch, wait for stabilization before any further expansion. | DataPlatform | S8 | `wait_for:batch_stability_window` | pause rollout and redeploy_previous on the affected batch |
| S10 | Repeat the small-batch rollout/soak cycle until all 19 spine locations are on th | SRE | S9 | `monitor:batch_health=healthy` | redeploy_previous |
| S11 | Confirm all 19 spine locations are healthy on the new config, with support and c | ProductPM | S10 | `window:until_all_19_locations_confirmed_healthy` | restore_last_known_good_config_with_full_audit_log |

## SMT verification: 03-safety-tilted

- backend: `z3` (11 steps, 10 dep edges, 3 constraint edges)
- feasible: **True**
- witness ordering: `S1` → `S2` → `S3` → `S4` → `S5` → `S6` → `S7` → `S8` → `S9` → `S10` → `S11`

## Chaos probe: 03-safety-tilted

- **fragility (overall)**: 0.929
- **fragility curve**: budget=1 → 1.0, budget=2 → 0.0
- **avg severity**: 2.71 (1=low … 4=critical)
- **rollback-failure rate**: 0.286 (4/14 probes)
- **recovery distribution**: recoverable_in_window=4, manual_ops=10
- **Achilles heel** (top 5 by per-step fragility):
  - `S1` → 1.0
  - `S2` → 1.0
  - `S4` → 1.0
  - `S5` → 1.0
  - `S6` → 1.0

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | medium | yes | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
| S2 | gate_violation | medium | yes | S3, S4, S5, S6, S7, S8 | recoverable_in_window |
| S3 | gate_violation | medium | yes | S4, S5, S6, S7, S8, S9 | recoverable_in_window |
| S4 | gate_violation | high | yes | S5, S6, S7, S8, S9, S10 | manual_ops |
| S5 | gate_violation | high | yes | S6, S7, S8, S9, S10, S11 | manual_ops |
| S6 | gate_violation | high | yes | S7, S8, S9, S10, S11 | manual_ops |
| S7 | gate_violation | medium | yes | S8, S9, S10, S11 | recoverable_in_window |
| S8 | gate_violation | critical | yes | S9, S10, S11 | manual_ops |
| S9 | gate_violation | high | yes | S10, S11 | manual_ops |
| S10 | gate_violation | critical | yes | S11 | manual_ops |
| S1 | rollback_failure | medium | NO | S2, S3, S4, S5, S6, S7 | manual_ops |
| S2 | rollback_failure | medium | NO | S3, S4, S5, S6, S7, S8 | manual_ops |
| S3 | rollback_failure | critical | NO | S4, S5, S6, S7, S8, S9 | manual_ops |
| S3, S7 | gate_violation | medium | NO | — | manual_ops |
