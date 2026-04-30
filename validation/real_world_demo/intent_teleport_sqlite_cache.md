# Add local SQLite cache layer with TTL invalidation to `n3mes1s/claude-teleport-analyzer`

## What

`claude-teleport-analyzer` is a Rust CLI that reads Claude Code
remote-session data from the Anthropic API. Today every invocation
hits the API live: `list_sessions()`, `get_session(id)`,
`get_events(id, max)` (which can paginate 10k+ events at 1000/page),
and `get_loglines(id)`. Repeated invocations against the same
session re-fetch the same data, bouncing off the same OAuth flow.

We are adding a **local SQLite cache** under
`~/.claude-teleport-analyzer/cache.db` (or
`$CLAUDE_TELEPORT_ANALYZER_CACHE` if set) with TTL-based
invalidation:

- `sessions` table: cache `list_sessions()` responses, default TTL
  60 seconds.
- `session_events` table: cache `get_events(id)` paginated results,
  TTL 5 minutes by default but **infinite** for sessions whose
  `status != "running"` (terminated sessions don't change).
- `loglines` table: cache `get_loglines(id)` responses, TTL same as
  events.
- `oauth_profile` table: cache the org-UUID lookup
  (`/api/oauth/profile`), TTL 1 hour.
- A new top-level CLI flag `--no-cache` to bypass it for one
  invocation, and `--clear-cache` subcommand to drop the DB.

## Why

- A user inspecting a single session typically runs `show`, `read`,
  `summary`, and `loglines` in quick succession. Today each one
  re-paginates events from scratch.
- Sessions with 10k+ events take ~30–60 seconds to fully fetch;
  with cache, every subsequent command on the same session is
  millisecond-scale.
- The Anthropic OAuth API has rate limits; reducing duplicate calls
  is responsible-citizen behaviour for a tool that's run frequently
  against the same sessions during debugging.
- The events of a terminated session are immutable; caching them
  forever (until manual clear) is correct.

## Scope

- `src/cache.rs` — new module wrapping `rusqlite` with the cache
  schema, TTL logic, and a typed `CacheEntry<T: Serialize +
  DeserializeOwned>` interface.
- `src/client.rs` — wrap each existing API method
  (`list_sessions`, `get_session`, `get_events`, `get_loglines`,
  `fetch_org_uuid`) to consult the cache first, fall through to the
  HTTP call, and write back. Cache lookup happens BEFORE the OAuth
  flow so an offline / re-uses-token-cached path is possible.
- `src/main.rs` — CLI flag wiring (`--no-cache`, `--clear-cache`).
- `src/types.rs` — derive `Serialize + Deserialize + Clone` on the
  types that go through the cache (most already have it; a few
  stragglers need `Clone`).
- `Cargo.toml` — add `rusqlite = { version = "0.32", features = ["bundled"] }`.
- `ARCHITECTURE.md` — update the "Command Data Flow" diagram and
  add a "Caching" section.

## Constraints

- **No behavioural change without `--no-cache`**: a fresh user with
  no cache file behaves identically to today. Cache is created on
  first hit.
- **Token freshness**: OAuth access tokens may rotate; the cache
  MUST NOT serve stale data based on a stale token assumption.
  Cache hit decisions are by `(method, params)`, not `(token, ...)`.
- **Schema migrations**: cache.db version must be tracked; if a
  future version of the tool changes the schema, it must
  drop-and-recreate rather than corrupt. SQLite `user_version` is
  the standard.
- **Cross-platform**: cache path resolution must work on macOS,
  Linux, Windows. Use the `dirs` crate (already a dep).
- **No silent OAuth bypass**: if the cache is hit and we never load
  credentials, that's a feature; but `list-sessions --org-uuid` and
  related auth-required CLI surfaces must still validate auth even
  when serving from cache. Surface a clear "served from cache, age
  Xs" footer when relevant.
- **Concurrent access**: two `claude-teleport-analyzer` processes
  may run simultaneously against the same cache.db. SQLite WAL
  mode handles this; document it.
- **Privacy**: cache.db contains transcript content (potentially
  sensitive). Permissions must be `0600`. README must document
  this and add `--clear-cache` instruction in security guidance.

## Out of scope

- Migrating from `reqwest` to a different HTTP client.
- Server-side cache (this is local-only).
- Cache compression.
- Cross-machine cache sharing.

## Affected stakeholders

- **Backend (Rust core team / project maintainer)**: owns `client.rs`
  and `cache.rs`.
- **DataPlatform**: cache schema design, TTL policy per endpoint,
  user_version migration policy.
- **Security**: file permissions on `cache.db`, transcript-content
  privacy implications, `--clear-cache` documentation.
- **SRE / observability**: log cache hit/miss to stderr at
  `RUST_LOG=debug`; consider an env-var-controlled
  `--cache-stats` flag.
- **ProductPM**: CLI UX, especially the "served from cache, age
  Xs" footer; release-note framing.
- **ConsumerSubsystem**: any external scripts wrapping
  `claude-teleport-analyzer` need to know cache exists; document
  `--no-cache` for cron-driven monitoring.

## What success looks like

- Running `claude-teleport-analyzer read <session-id>` twice in
  succession: first call ~30s on a 10k-event session; second call
  <100ms.
- Running with `--no-cache` matches today's behaviour byte-for-byte
  in stdout.
- `--clear-cache` removes the DB file and exits 0.
- A `RUST_LOG=debug` run shows cache hit/miss for every API method.
- No cross-platform regressions; the existing tests still pass plus
  new cache-specific tests covering: TTL expiry, terminated-session
  infinite cache, schema-migration drop-and-recreate, concurrent
  process access via WAL.
