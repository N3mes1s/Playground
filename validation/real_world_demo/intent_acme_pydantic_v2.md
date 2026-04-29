# Migrate Acme Payments API from FastAPI 0.95.2 + Pydantic v1.10 to FastAPI 0.110 + Pydantic v2.7

## What

Acme Corp runs a production payments API on **FastAPI 0.95.2** with
**Pydantic 1.10**. We are migrating to **FastAPI 0.110.x** with
**Pydantic 2.7+**. This is the well-documented industry migration that
followed [FastAPI 0.100.0 (Jul 2023)](https://fastapi.tiangolo.com/release-notes/)
adding Pydantic v2 support.

The codebase contains:

- ~180 Pydantic models across `app/models/`, `app/schemas/`, and
  inline request/response models in routes.
- ~40 `@validator` decorators and 6 `@root_validator` decorators.
- 3 custom encoders registered via `Config.json_encoders` (Decimal,
  datetime with TZ, internal `MoneyAmount`).
- 12 `Config.orm_mode = True` models bridging to SQLAlchemy ORM.
- `.dict()` and `.json()` calls in 200+ places (computed by ripgrep
  before we started).
- An OpenAPI-generated TypeScript client published as
  `@acme/payments-client@1.x` that ~30 internal services consume.
- An OpenAPI-generated mobile SDK consumed by 4 iOS/Android apps.
- Auto-generated documentation served at `docs.acme.internal/payments`
  used by partner integrators.

## Why

- **Performance**: Pydantic v2 is 5–50× faster on validation and
  serialization. Our p99 request validation latency on the
  `/v1/payments/charge` endpoint is currently 35 ms; we expect it to
  drop to ~5 ms.
- **Maintenance**: Pydantic v1 is in security-fix-only mode. Continuing
  to ship v1 is a known security debt that auditors flagged in the
  last SOC2 review.
- **Ecosystem**: most new FastAPI features (e.g. proper streaming
  responses, async dependency injection improvements) are v2-only.

## Scope

- Bump `pydantic` from `^1.10` to `^2.7`.
- Bump `fastapi` from `^0.95.2` to `^0.110`.
- Run the official `bump-pydantic` codemod across the codebase.
- Manually rewrite the 6 `@root_validator` decorators (codemod
  doesn't handle them well).
- Manually rewrite the 3 custom encoders (`Config.json_encoders` was
  removed; replace with `@field_serializer`).
- Rewrite `Config.orm_mode = True` to
  `model_config = ConfigDict(from_attributes=True)` on 12 models.
- Replace 200+ `.dict()` / `.json()` calls with `.model_dump()` /
  `.model_dump_json()` (codemod handles most).
- Regenerate OpenAPI schema and **publish a new major version** of
  the TypeScript client (`@acme/payments-client@2.x`).
- Coordinate the mobile SDK regeneration and store-submission
  timeline.
- Update API documentation site.

## Constraints

- **Customer-visible**: this API processes real-money payments. Any
  validation regression that lets bad data through, or any schema
  change that breaks consumers, costs money and SLA breach.
- **Mixed-fleet transition**: ~30 internal services consuming
  `@acme/payments-client@1.x` will not all be able to upgrade
  simultaneously. We must support both client versions during the
  transition.
- **Mobile**: app store submission cycles are 1–3 weeks; mobile cannot
  hot-fix. The new mobile SDK must ship and be in user hands before
  any breaking server-side schema change.
- **Pydantic v2's stricter coercion**: Pydantic v1 coerced strings to
  ints, ints to bools, etc., much more aggressively. v2 is stricter.
  Some legitimate currently-working request bodies may start to fail
  validation. We need to characterize and either accept or
  explicitly relax via `strict=False`.
- **OpenAPI drift**: Pydantic v2 generates slightly different schemas
  (e.g. `nullable` handling, examples, discriminated unions). The
  TypeScript client regenerated from the new schema may differ from
  the v1 client even on endpoints we did not intend to change.
- **Validator ordering**: `@validator` and `@field_validator` have
  different always/each_item semantics. Subtle behaviour changes if
  not migrated carefully.
- **Async validators**: Pydantic v1 supported async validators via a
  hack; v2's are sync. We have 2 endpoints that hit a remote tax
  service from inside a validator (an antipattern, but real).

## Out of scope

- Switching from SQLAlchemy ORM 1.4 → 2.x (separate project).
- Switching from FastAPI to anything else.
- Replacing the payment processor.

## Affected stakeholders

- **Backend** (the `payments-api` team): owns the actual code change.
- **Mobile** (iOS + Android): consume the SDK; need timed releases.
- **SDK consumers** (~30 internal services): consume
  `@acme/payments-client`.
- **SRE**: runs payments-api in production; needs feature flags,
  staged rollout, error-budget gates.
- **Security**: must validate that v2's stricter validation does not
  introduce a new bypass surface; must verify SOC2 compliance is
  improved as expected.
- **Product / PM**: customer-facing partner integrators; comms cycle.
- **Data platform**: events stream into Snowflake; v2's slightly
  different JSON output may break downstream parsers.

## What success looks like

- payments-api runs on Pydantic v2 in production with **<= 0.1%
  validation-rejection-rate increase** vs the v1 baseline.
- `@acme/payments-client@2.x` is published and at least 80% of
  internal consumers are migrated.
- Mobile apps shipped with the new SDK are in user hands before any
  breaking server-side schema change.
- p99 validation latency on `/v1/payments/charge` drops by at least
  3×.
- No customer-reported payments incident attributable to the
  migration in the 30 days following completion.
