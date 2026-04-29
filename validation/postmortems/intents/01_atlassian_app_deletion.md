# Bulk-deprecate and delete the legacy `Insight` standalone app from customer sites

## What

We are deprecating the legacy `Insight` standalone app and need to remove
it from approximately **800 customer sites** that still have it installed.
This is a cross-team workflow:

- **Team A** owns the customer-site catalogue. They will produce the list
  of identifiers to act on.
- **Team B** owns the deletion tooling. They will run the bulk-delete
  script against whatever identifiers Team A provides.

## Why

`Insight` has been replaced by the in-platform Jira Service Management
asset module. Continuing to support both is operational dead weight, and
some customers have begun reporting confusion about which to use.

## Scope

- Inventory: Team A queries the customer catalogue and emits a CSV of
  identifiers for sites that have `Insight` installed.
- Execution: Team B runs `cleanup.py --ids <csv>` to remove the app.
- The CSV format is `id\n`, one per row.

## Constraints

- Customer-visible: many customers haven't decommissioned their `Insight`
  data. Total data loss for end users if anything in this pipeline goes
  wrong.
- Bulk: ~800 targets is too many to manually verify each.
- Cross-team: Team A and Team B do not share a tracker; the only handoff
  artifact is the CSV.
- Reversibility: `Insight` is a separate database; once deleted, only
  customer-side backups (if they took any) can recover state.
- Time pressure: leadership wants this done in the current quarter.

## What success looks like

All 800 sites no longer have `Insight` installed. Customer-visible state
on those sites is otherwise unchanged. No customer-initiated escalation.

---

_Real-world echo: this is the pre-incident framing of the
**Atlassian April 2022 13-day outage**, during which approximately 800
customer sites were entirely deleted because Team A handed Team B the
**site IDs** rather than the **app IDs**, and the bulk-delete script
operated at site granularity._
