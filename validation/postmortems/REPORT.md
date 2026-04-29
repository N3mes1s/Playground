# Retrospective validation: verified-rollout vs 5 real public post-mortems

Each case was a real public migration / rollout incident. We crafted an intent capturing the **pre-incident** state and ran `verified-rollout/cli_pro.py` against it, then scored whether the pipeline surfaced the constraint that was actually violated.

## Verdicts

| Case | Real-world incident | Verdict | KW hits | Pair hits | SMT infeasible | Winner fragility |
|---|---|---|---|---|---|---|
| `01_atlassian_app_deletion` | Atlassian April 2022: ~800 customer sites entirely deleted because Team A handed... | **caught** | 8/13 | 2/2 | 4 | 0.53 |
| `02_cloudflare_mcp_rollout` | Cloudflare June 21, 2022: stepped rollout reached 19 spine locations; 'steps wer... | **caught** | 8/12 | 1/2 | 3 | 0.09 |
| `03_cloudflare_dc_failover` | Cloudflare Nov 2-4, 2023: 41-hour control-plane outage because many services bel... | **partial** | 3/10 | 0/2 | 4 | 0.62 |
| `04_gitlab_db_replica` | GitLab Jan 31, 2017: engineer ran rm -rf on db1 (primary) instead of db2 (replic... | **caught** | 6/11 | 2/2 | 0 | 0.50 |
| `05_linear_cascade_migration` | Linear Jan 24, 2024: generated migration with ON DELETE CASCADE deleted producti... | **caught** | 9/11 | 0/2 | 4 | 0.55 |

**Aggregate**: caught=4, partial=1, missed=0 (out of 5)

## 01_atlassian_app_deletion — verdict: **caught**

**Real-world incident**: Atlassian April 2022: ~800 customer sites entirely deleted because Team A handed Team B site-level IDs instead of app-level IDs.

- constraint keywords surfaced: 8/13: `verification`, `handoff`, `sample`, `dry-run`, `verify`, `schema`, `csv`, `approval`
- keywords MISSED: `id`, `dry_run`, `spot-check`, `cross-team`, `format`
- expected stakeholder-conflict pairs: 2/2 hit
  - HIT: BackendOwner ↔ DataPlatform
  - HIT: Security ↔ ProductPM

- plan steps that referenced the root cause:
  - 00-cost-leaning:S1 -> Team A exports a versioned CSV of Insight app-install IDs only, with schema documentation and an immutable handoff artifact. approval:securi
  - 00-cost-leaning:S2 -> Security and Storage validate the CSV against app-install records, confirm target granularity, and freeze the handoff for execution. approva
  - 00-cost-leaning:S3 -> ProductPM sends customer notifications, assigns a named escalation owner, and briefs support on the rollout and playbook. approval:support_m
  - 00-cost-leaning:S5 -> Deploy the validated cleanup.py parser and CSV schema checks before any destructive action. wait_for:validation_build_deployed redeploy_prev
  - 00-cost-leaning:S6 -> Run a non-destructive preflight dry-run on the frozen CSV to prove every ID maps to an Insight app record only. wait_for:preflight_audit_pas

- open questions that referenced the root cause:
  - 00-cost-leaning: What is the exact CSV schema version string Team A should publish?
  - 00-cost-leaning: What constitutes the official compliance approval artifact?
  - 01-safety-leaning: What exact CSV schema version should Team A emit for the versioned handoff?
  - 01-safety-leaning: Which approval order is preferred for security, storage, compliance, and support if they cannot all be obtained concurrently?
  - 02-speed-leaning: Who from storage owns the app-install validation approval?

- pipeline output: 25 constraints, 48 plan steps across all frontier plans, 4 plans proven infeasible by Z3, winner fragility 0.53

## 02_cloudflare_mcp_rollout — verdict: **caught**

**Real-world incident**: Cloudflare June 21, 2022: stepped rollout reached 19 spine locations; 'steps weren't small enough' so all 19 went down together.

- constraint keywords surfaced: 8/12: `canary`, `stepped`, `batch`, `monitor`, `rollback`, `wait`, `traffic`, `smaller`
- keywords MISSED: `single`, `one location`, `per-location`, `smoke`
- expected stakeholder-conflict pairs: 1/2 hit
  - HIT: SRE ↔ ProductPM
  - miss: BackendOwner ↔ SRE

- plan steps that referenced the root cause:
  - 00-cost-leaning:S3 -> Obtain network-ops approval for a very small initial batch and batch sizing plan. approval:network-ops redeploy_previous Approval record, pl
  - 00-cost-leaning:S5 -> Deploy the updated routing config to a minimal canary batch of spine locations using the smallest practical batch size. monitor:customer-vis
  - 00-cost-leaning:S6 -> Hold the canary steady and watch for propagation lag, prefix leakage, traffic asymmetry normalization, and no blackhole/reachability alerts.
  - 00-cost-leaning:S7 -> Verify canary stability window and present results for promotion decision. wait_for:canary_stability_window pause rollout and redeploy_previ
  - 00-cost-leaning:S9 -> Expand to the next small batch only if canary is healthy and route behavior remains stable. monitor:batch_health=healthy roll back the most 

- open questions that referenced the root cause:
  - 00-cost-leaning: What exact batch size is approved for the initial canary?
  - 01-safety-leaning: What exact batch size should be used for the initial canary and subsequent batches?
  - 02-speed-leaning: What exact batch size should be used for the canary and subsequent expansions?
  - 03-safety-tilted: Which exact initial canary size is approved as 'very small' for the first batch?

- pipeline output: 24 constraints, 45 plan steps across all frontier plans, 3 plans proven infeasible by Z3, winner fragility 0.09

## 03_cloudflare_dc_failover — verdict: **partial**

**Real-world incident**: Cloudflare Nov 2-4, 2023: 41-hour control-plane outage because many services believed to be HA were single-region in PDX-01; no recent failover drill.

- constraint keywords surfaced: 3/10: `verify`, `dependency`, `audit`
- keywords MISSED: `ha`, `drill`, `single-region`, `catalog`, `single-point`, `pdx`, `failover order`
- expected stakeholder-conflict pairs: 0/2 hit
  - miss: SRE ↔ BackendOwner
  - miss: DataPlatform ↔ Security

- plan steps that referenced the root cause:
  - 00-cost-leaning:S3 -> Verify secondary DC configuration parity, dependencies, and runbook order for the control plane and analytics services; identify any PDX-01-
  - 00-cost-leaning:S5 -> Bring up secondary control-plane and analytics services in dependency order, including compatibility shim and API backward-compatibility che
  - 00-cost-leaning:S6 -> Validate secondary read/write capability for control-plane state and verify failover smoke tests for dashboard, API, terraform-provider, and
  - 00-cost-leaning:S9 -> Complete customer-facing auth, TLS, and endpoint cutover for dashboard, API, terraform-provider, and analytics query endpoints after seconda
  - 01-safety-leaning:S3 -> Bring up and validate the secondary-datacenter control-plane and analytics stack in dependency order without shifting customer traffic. wait

- pipeline output: 26 constraints, 44 plan steps across all frontier plans, 4 plans proven infeasible by Z3, winner fragility 0.62

## 04_gitlab_db_replica — verdict: **caught**

**Real-world incident**: GitLab Jan 31, 2017: engineer ran rm -rf on db1 (primary) instead of db2 (replica); 5 of 6 backup procedures had silently failed.

- constraint keywords surfaced: 6/11: `host`, `verify`, `backup`, `two-person`, `buddy`, `confirm`
- keywords MISSED: `destination`, `verify backup`, `wrong host`, `rm -rf`, `dry-run`
- expected stakeholder-conflict pairs: 2/2 hit
  - HIT: DataPlatform ↔ SRE
  - HIT: BackendOwner ↔ Security

- plan steps that referenced the root cause:
  - 00-cost-leaning:S1 -> Confirm an escalation owner is assigned and notify on-call, DB owners, and support that a db2 rebuild is about to start. approval:on-call in
  - 00-cost-leaning:S2 -> Verify the rebuild is occurring in an approved low-risk window and not during incident/launch/overnight fatigue risk. window:outside_inciden
  - 00-cost-leaning:S3 -> SSH into the replica host and confirm the hostname is exactly db2.cluster.gitlab.com before any destructive command. wait_for:hostname_confi
  - 00-cost-leaning:S4 -> Have the second engineer and observing engineer explicitly approve that the connected host is db2 and that the session is safe to proceed. a
  - 00-cost-leaning:S5 -> Stop PostgreSQL on db2 and confirm it is fully stopped before any cleanup. wait_for:postgresql stopped on db2 Start PostgreSQL on db2 if sto

- open questions that referenced the root cause:
  - 00-cost-leaning: Which exact backup/snapshot mechanism exists for pre-wipe recovery if the wipe is started on the wrong host?

- pipeline output: 26 constraints, 45 plan steps across all frontier plans, 0 plans proven infeasible by Z3, winner fragility 0.50

## 05_linear_cascade_migration — verdict: **caught**

**Real-world incident**: Linear Jan 24, 2024: generated migration with ON DELETE CASCADE deleted production data; PR reviewed by multiple engineers, local test ran against smaller snapshot that did not reproduce.

- constraint keywords surfaced: 9/11: `cascade`, `generated`, `ddl`, `production`, `snapshot`, `schema`, `audit`, `review`, `destructive`
- keywords MISSED: `explain`, `dry-run`
- expected stakeholder-conflict pairs: 0/2 hit
  - miss: DataPlatform ↔ BackendOwner
  - miss: DataPlatform ↔ ProductPM

- plan steps that referenced the root cause:
  - 00-cost-leaning:S1 -> Merge and apply schema migration to create IssueAssignee with required indexes/constraints; do not change app reads yet. wait_for:IssueAssig
  - 00-cost-leaning:S6 -> Prepare and review Prisma-generated drop migration SQL, explicitly inspecting the ON DELETE CASCADE path and helper DDL before merge. approv
  - 00-cost-leaning:S7 -> Obtain security review and explicit cascade-path confirmation for the destructive drop migration. wait_for:explicit_cascade_review redeploy_
  - 00-cost-leaning:S8 -> Confirm customer notice was sent at least 14 days before the destructive step and that support is briefed/staffed with a named escalation ow
  - 00-cost-leaning:S10 -> Run the final Prisma-generated migration to drop Issue.assignee_id after cutover, keeping the destructive DDL reviewed and approved. approva

- open questions that referenced the root cause:
  - 01-safety-leaning: What constitutes a production-shape snapshot for parity verification?
  - 02-speed-leaning: Exact maintenance window start time for the destructive drop
  - 02-speed-leaning: Whether the generated Prisma drop SQL passes explicit cascade review and non-destructive prod-shape testing
  - 03-safety-tilted: Who will act as the support lead for the destructive cutover?

- pipeline output: 26 constraints, 40 plan steps across all frontier plans, 4 plans proven infeasible by Z3, winner fragility 0.55
