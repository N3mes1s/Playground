# rollout-rehearsal

Take a proposed code change and produce a **multi-stakeholder, temporally-
constrained rollout plan** by simulating six stakeholder personas
(BackendOwner, DataPlatform, SRE, Security, ProductPM, ConsumerSubsystem)
contributing structured constraints, then a Sequencer agent synthesising
them into a partial-order plan with explicit gate / rollback / observability
per step.

This is the gap left open by:

- **Greptile, CodeRabbit, blast-radius.dev** — produce *what changes / what
  breaks* from a diff, but not *in what order to roll it out*.
- **Cursor 2.2 multi-agent judging** — judges *implementations*, not rollouts.
- **Bytebase, Liquibase, Flyway** — execute schema rollouts, but you have to
  give them the order.
- **SagaLLM (VLDB 2025)** — academic; rule-based dependency graph, not
  stakeholder-debate driven.

## What's different

- **Constraints, not free-text discussion.** Each persona contributes 2-5
  structured constraints with axis / summary / scope / gate / rollback /
  blocking / owner — JSON, mechanically merge-able. Without this, persona
  debates degenerate to consensus ("do it carefully") because the agents
  share a model and reasoning style.
- **Persona-specific axes.** Each persona is locked to its axis(es)
  (schema/api/deploy/data/comms/security/ops/business) and is told
  explicitly to defer to others outside it. Conflict is then mechanically
  detectable.
- **Sequencer as conflict resolver, not just summariser.** Output includes
  an explicit `conflicts` list where the sequencer flags blocking
  stakeholder constraints that pulled against each other and how it
  resolved them.

## Run

```bash
cp .env.example .env  # OPENAI_API_KEY=... ; MODEL=gpt-5.4-mini
pip install -r requirements.txt
python rollout-rehearsal/cli.py fixtures/intent_sqlite_memory_migration.md
```

Output:

- `rollout-rehearsal/reports/<intent_stem>.md` — markdown rollout doc
  (summary, constraint table, plan table, Mermaid flowchart, conflicts,
  open questions).
- `rollout-rehearsal/reports/<intent_stem>.json` — sidecar JSON with the
  raw merged constraints and the sequencer's plan object.

## Limits

- Personas have no real grounding in deployment-frequency or on-call data
  (they don't know your release cadence). Constraints they emit will be
  generic about timing windows unless the intent doc supplies that
  context.
- The sequencer outputs a partial-order plan, not a calendar schedule —
  no dates, only logical dependencies + gates.
- 6 personas is enough for a typical change; larger orgs (separate data
  privacy team, separate compliance, separate marketing) would benefit
  from extra personas — easy to add in `mirofish_lab/rollout.py`.
