# Migrate `Issue.assignee` schema from single-FK to many-to-many via `IssueAssignee` join table

## What

Today `Issue.assignee_id` is a nullable FK to `User`. We need many users
to be assignable to one issue. The migration:

1. Create new `IssueAssignee(issue_id, user_id, ...)` join table.
2. Backfill: for every issue with non-null `assignee_id`, insert one row
   into `IssueAssignee`.
3. Deploy code that reads from `IssueAssignee` and writes to both old
   and new during a transition window.
4. After a quiet period, deploy code that reads/writes only from
   `IssueAssignee`.
5. Drop the old `Issue.assignee_id` column.

Each step is its own PR, peer-reviewed, tested locally against a
production-shape database snapshot.

## Why

Multi-assign is one of our most-requested features and is blocked on
this schema change.

## Scope

- One Postgres database, ~50M issues.
- Step 5 (the column drop) is the destructive one.
- We use Prisma for schema migration; it generates `ALTER TABLE` DDL
  and helper functions automatically.
- The Prisma-generated DDL for this drop includes an `ON DELETE CASCADE`
  relationship that was added in a separate, unrelated migration four
  weeks ago.

## Constraints

- ~50M issues is too many to manually inspect.
- We have full backups but recovery is hours of customer-visible
  downtime.
- The codegen tool (Prisma) generates DDL automatically; reviewers
  read the migration SQL it produces.
- All migrations go through PR review with at least two approvers.
- Tests are run locally against a copy of production data, not against
  production itself.

## What success looks like

`IssueAssignee` is the source of truth, the legacy column is gone, no
data is lost, no customer-visible downtime.

---

_Real-world echo: pre-incident framing of the **Linear January 24, 2024
incident**, in which a generated migration's `ON DELETE CASCADE`
behaviour (added in an earlier unrelated migration) caused the
column-drop step to delete user data from production. The PR was
reviewed by multiple engineers but the cascade behaviour was missed by
all of them, and the local test environment did not reproduce the
cascade because it ran against a smaller snapshot._
