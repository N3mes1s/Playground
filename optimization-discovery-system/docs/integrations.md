# Integrations

`ods` talks to two external services: **Anthropic** (for LLM-driven
specialists and the Explorer) and **GitHub** (for PR delivery and the
webhook-driven App mode). Every integration is written with the same
constraints:

- **musl single-binary**. `rustls` + `webpki-roots` for TLS. No OpenSSL,
  no `native-tls`, no `ring`. The binary you `curl` into a CI runner has
  zero dynamic dependencies.
- **No wrapper crates**. `reqwest` direct — not `octocrab`, not the
  official Anthropic SDK. Smaller deps, tighter control, auditable
  request shapes.
- **Constant-time crypto where it matters**. HMAC verification uses the
  `hmac` crate's `verify_slice`, which is constant-time by construction.

---

## Anthropic

All LLM traffic goes through `ods-agents/src/anthropic.rs`. The client is
deliberately small — transport only. Orchestration (multi-turn, tool-use
fan-out, caching) lives in `ToolUseLoop`, which builds on top.

### Wire shape

```rust
POST https://api.anthropic.com/v1/messages
Headers:
  x-api-key:         $ANTHROPIC_API_KEY
  anthropic-version: 2023-06-01
  content-type:      application/json

{
  "model": "claude-opus-4-7",
  "max_tokens": N,
  "system": "<prompt>",
  "messages": [ ... ],
  "tools":    [ ... ],                 // optional
  "output_config": {                   // optional — structured outputs
    "format": {
      "type": "json_schema",
      "schema": { /* JSON Schema, additionalProperties:false */ }
    }
  }
}
```

Default model is `claude-opus-4-7` (constant `DEFAULT_MODEL` in
`anthropic.rs`). Specialists can override per-role via
`ToolUseLoop::with_model`.

### Structured outputs

This is the key to the Explorer working reliably. We learned the hard way
that prompt-engineering "output JSON" gives you model output like:

```text
Sure! Here are the recipes I found:
{"recipes": [{...}, /* no trailing comma needed */,]}
```

Anthropic's **structured outputs** (GA across Opus 4.7, Sonnet 4.6/4.5,
Haiku 4.5) flip the switch from *hope* to *guarantee*: the final text
block is constrained at decode time to match the supplied JSON Schema.
You get valid JSON, always, or a refusal with reason.

`send_messages_with_schema` adds `output_config.format.json_schema.schema`
to the request body when a schema is provided. Intermediate `tool_use`
turns are *free* — the schema only applies to the final assistant text
block after the tool-use loop converges. This is why the Explorer can:

1. Call `list_dir`, `read_file`, `ast_query`, `recipe_search` as many
   times as it needs.
2. Produce a normal text transcript of its reasoning in those turns.
3. End with a JSON text block that we can `serde_json::from_str` without
   ever running a regex or handling fenced blocks.

The schema we send for the Explorer is in `explorer.rs::explorer_output_schema`
and includes `additionalProperties: false` on every object (required by
the API — any missing `additionalProperties` returns a 400 at request
time, before tokens are generated).

### Cost and token accounting

`ResponseEnvelope.usage` is parsed out of every response and accumulated
into `LoopStats`:

```rust
pub struct LoopStats {
    pub tokens_in: u32,
    pub tokens_out: u32,
    pub tool_calls: u32,
}

impl LoopStats {
    pub fn estimated_cost_usd(&self, model: &str) -> f64 { ... }
}
```

Prices are hard-coded per model based on Anthropic's published rates; a
miss on the model name defaults to the Opus tier (conservative). Each
specialist's `LoopStats.estimated_cost_usd()` is added to `Run.spent_usd`
after the race completes; in CI mode, exceeding `spend_cap` aborts
remaining stages and writes a partial-result artefact.

### Prompt caching

Set `--header "anthropic-beta: prompt-caching-2024-07-31"` style is **not**
used — stable prompt caching is GA so we rely on the normal
`cache_control: {"type": "ephemeral"}` marker on the system prompt +
retrieved recipe snippets. This cuts the per-turn cost of the Explorer
(which is all tool-use-loop turns sharing the same hefty preamble)
significantly in practice.

### TLS

`reqwest` with `default-features = false, features = ["rustls-tls",
"gzip", "json"]`. Root certificates come from `webpki-roots` so we don't
depend on the OS's cert store. That lets the static musl binary be
published to any CI runner without surprises.

---

## GitHub

Three pieces: REST client (`api.rs`), App-mode auth (`app_auth.rs`), and
webhook server (`webhook.rs` + `signature.rs`). All of them compose —
the Action mode uses just the REST client, the App mode stacks the
webhook server on top of App-scoped tokens.

### REST client

Source: `crates/ods-ci/src/api.rs`.

We only implemented the endpoints the "open a PR from a patch" flow
needs:

| Method                       | Purpose                                      |
|------------------------------|----------------------------------------------|
| `default_branch(owner,repo)` | `GET /repos/:owner/:repo` → `default_branch` |
| `branch_sha(…)`              | `GET /repos/.../git/ref/heads/:branch`       |
| `create_branch(…)`           | `POST /repos/.../git/refs` with `from_sha`   |
| `put_file(…)`                | `PUT /repos/.../contents/:path` — creates on first call, fetches existing `sha` for updates |
| `open_pr(…)`                 | `POST /repos/.../pulls`                      |

Base64 encoding of file contents for the Contents API is done inline
(`b64_encode` at the bottom of `api.rs`) rather than pulling the `base64`
crate — the encode path is bounded by patch size and the implementation is
40 lines.

Auth is a single `Authorization: Bearer <token>` header on every call.
The token is either:

- `GITHUB_TOKEN` — ambient token, common in Action mode.
- The output of `GitHubAppAuth::installation_token` — scoped App token.

The client is otherwise stateless; callers build one per Action run or
per webhook dispatch.

### GitHub App authentication

Source: `crates/ods-ci/src/app_auth.rs`.

Flow:

1. Sign a short RS256 JWT claiming `iss = <app_id>`, `iat = now - 60`,
   `exp = now + 600`. The 60-second backdate tolerates clock skew —
   GitHub rejects "future" iats.
2. `POST /app/installations/{installation_id}/access_tokens` with
   `Authorization: Bearer <jwt>`.
3. Use the returned installation token against the REST endpoints above.

**Why pure-Rust RSA.** `ring` and `openssl` both break the musl story.
We use `rsa` + `sha2` for signing and accept either PKCS#1 or PKCS#8 PEM
via `DecodeRsaPrivateKey` / `DecodePrivateKey`. The `DeterministicRng`
you'll see is a required-by-trait satisfier — PKCS#1 v1.5 signatures
don't actually consume randomness, but the `RandomizedSigner` trait
signature insists on a `CryptoRng`.

Env vars:

- `ODS_APP_ID`
- `ODS_APP_PRIVATE_KEY_PEM` — the full PEM text, not a path
- `ODS_APP_INSTALLATION_ID`

When all three are present, `ods ci action` prefers App auth over
`GITHUB_TOKEN`.

### Webhook server

Source: `crates/ods-ci/src/webhook.rs`.

`ods ci serve --port 8787` starts an axum server with two routes:

- `GET /health` → `200 ok` (for the App platform's webhook health check)
- `POST /webhook` — handles `issue_comment.created` events

The handler does two things, in order:

1. **Signature gate**. `X-Hub-Signature-256` is verified against
   `ODS_WEBHOOK_SECRET` using HMAC-SHA256 **before** we call
   `serde_json::from_slice`. Missing header → 401; bad HMAC → 401;
   malformed header → 400. This prevents an attacker from forcing JSON
   parsing or triggering runs without knowing the secret.
2. **Intent parse**. Only `action == "created"` comments whose body
   starts with `/ods optimize` are forwarded. Everything else → 200
   ignored (so GitHub marks the webhook delivery OK and stops
   retrying).

Accepted events are forwarded on a `tokio::mpsc::UnboundedSender<WebhookEvent>`.
The HTTP handler returns `200 queued` immediately — GitHub's webhook
timeout is 10 seconds, and an actual `ods run` will often take minutes,
so dispatch is always async.

### Signature verification

Source: `crates/ods-ci/src/signature.rs`.

```rust
pub enum SignatureVerdict { Ok, Missing, Mismatch, Malformed }

pub fn verify(secret: &[u8], body: &[u8], header: Option<&str>) -> SignatureVerdict;
pub fn sign(secret: &[u8], body: &[u8]) -> String;
```

- `verify` uses `hmac::Mac::verify_slice`, which is constant-time.
- `decode_hex` + `nibble` are hand-rolled to avoid pulling the `hex` crate.
- `sign` exists mainly so the integration tests can round-trip
  (generate-then-verify) without spinning up a real webhook.

### PR body rendering

Source: `crates/ods-report/src/markdown.rs` (referenced from the Loop's
`Explain` stage).

The PR body is the product's *visible output* — it's where the
"data-backed" promise pays off. The renderer takes a `ReportInputs`
struct and produces a markdown body that includes:

- Headline speedup with CI lower bound, e.g. `2.3× faster (lower bound
  1.8× at 99% CI)`.
- Before/after bench table.
- Syscall delta table (`read: 142 → 18`, etc.).
- Alloc delta (`41 KiB → 2 KiB`, allocation count).
- Collapsed flame-graph `<details>` block; the SVG is uploaded as an
  extra file in the PR branch via a second `put_file` call.
- Applied recipe IDs, each linked back to the corpus YAML file.
- Compat evidence: test-suite counts, fuzz minutes, property-test seed,
  `cargo-semver-checks` verdict, downstream-test results when the change
  was a dependency bump.
- The exact `ods run ...` command needed to reproduce.

The same body is re-used in the "partial result" path, except the
headline reads "speedup withheld" and the compat evidence is replaced
with the reason (`CI overlap`, `fingerprint mismatch`, `fuzz found a
crash`, etc.).

---

## How the pieces compose

### One-shot Action

```
ods ci action
│
├─ Orchestrator::run on the checked-out repo
├─ produces artifact { patch_diff, report }
└─ if artifact.gate_passed:
     ├─ GitHubClient::new(GITHUB_TOKEN)            ── or App auth if env present
     ├─ default_branch + branch_sha
     ├─ create_branch("ods/auto-<timestamp>")
     ├─ for each file in patch:  put_file(...)
     ├─ put_file("ods/flame.svg", ...)             ── when available
     └─ open_pr(title, render_pr_body(inputs))
```

### App mode

```
ods ci serve --port 8787
│
├─ axum listener
├─ /webhook → signature-verify → mpsc channel
└─ worker task:
     ├─ pull WebhookEvent off channel
     ├─ clone target repo at comment's ref
     ├─ GitHubAppAuth::installation_token(...)
     └─ same Orchestrator → PR pipeline as Action
```

---

## Status

| Integration                | Status |
|----------------------------|--------|
| Anthropic transport client | Real, typed, `rustls`-only. |
| ToolUseLoop (multi-turn)   | Real; LoopStats + cost accounting wired. |
| Structured outputs         | Real; used by Explorer and harvest generalizer. |
| Prompt caching             | Wired via `cache_control: ephemeral`. |
| GitHub REST (PR flow)      | Real — the endpoints the Action mode needs. |
| GitHub App JWT auth        | Real — pure-Rust RSA, no `ring`. |
| Webhook server (axum)      | Real; signature-gated; queues to mpsc channel. |
| Webhook signature verify   | Real; HMAC-SHA256, constant-time. |
| Installation token cache   | **Not yet** — we re-mint per dispatch. Cheap enough in practice. |
| PR review-thread replies   | **Not yet** — one-shot PRs only. |
| Check runs / status API    | **Not yet** — relies on target repo's own CI passing. |
