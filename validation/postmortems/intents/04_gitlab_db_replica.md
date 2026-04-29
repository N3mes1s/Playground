# Rebuild the lagging `db2.cluster.gitlab.com` PostgreSQL replica from `db1`

## What

`db2.cluster.gitlab.com` is the streaming replica of our primary
production PostgreSQL database `db1.cluster.gitlab.com`. Its WAL replay
fell behind during a recent traffic spike and replication has now
stopped advancing.

We need to bring `db2` back into sync. The standard procedure:

1. Stop PostgreSQL on `db2`.
2. Wipe the data directory on `db2`.
3. Re-run `pg_basebackup` against `db1` to refill `db2`.
4. Start PostgreSQL on `db2` and confirm replication is caught up.

Engineers will SSH into `db2` to perform the rebuild. This is a
two-engineer task: one driving, one observing.

## Why

`db2` serves as the failover target for `db1` and as a source for
backups. While it's lagging it provides neither function correctly.

## Scope

- Single host: `db2.cluster.gitlab.com`.
- Standard procedure documented in the runbook.
- Estimated wall-clock: 2–4 hours.

## Constraints

- `db1` is THE production primary. Any operation on the wrong host
  could destroy production data.
- The two hosts have very similar names (`db1` vs `db2`) and similar
  shell prompts.
- The rebuild involves `rm -rf` on the data directory (destructive).
- We have backups of `db1`, but recovery time would be many hours.
- It's currently 23:00 local time; the on-call engineer is tired.

## What success looks like

`db2` is fully caught up with `db1` and replication is healthy. `db1`
production state is unaffected. No customer-visible impact.

---

_Real-world echo: pre-incident framing of the **GitLab January 31, 2017
database outage**, during which the engineer SSH'd into `db1.cluster`
(production) instead of `db2.cluster` (the lagging replica) and ran
`rm -rf` on the production data directory. Recovery from backups
revealed five of the six backup procedures had been silently failing,
extending the outage._
