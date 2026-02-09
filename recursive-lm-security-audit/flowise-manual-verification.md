# Flowise Security Audit — Manual Verification Report

## Context

The RLM security scanner produced 19 findings on Flowise (`/tmp/Flowise/packages/server/src`).
Adversarial validation reduced these to 5 "confirmed" findings. This report manually verifies
each confirmed finding by reading actual source code and tracing execution paths.

**Target**: FlowiseAI/Flowise (LLM orchestration platform)
**Stack**: Node.js, Express, TypeORM, Passport.js JWT, crypto-js AES, multer
**Scope**: `packages/server/src` (~505 TypeScript files, ~46K LOC)

---

## Verified Findings

### Finding 1: Path Traversal in File Upload/Download

| Field | Value |
|-------|-------|
| Scanner Severity | CRITICAL |
| Validator Verdict | CONFIRMED |
| **Manual Verdict** | **FALSE POSITIVE** |

**Scanner/Validator claim**: Unsanitized `fileName` from `req.query` enables directory traversal
in the `streamUploadedFile` endpoint.

**Evidence FOR the claim** (controller layer):
- `get-upload-file/index.ts:18`: `const fileName = req.query.fileName as string` — no sanitization
- Passed directly to `streamStorageFile(chatflowId, chatId, fileName, orgId)` at line 45

**Evidence AGAINST the claim** (storage layer):
- `storageUtils.ts:761`: `const sanitizedFilename = sanitize(fileName)` — uses `sanitize-filename` npm package which strips `../`, `..\\`, null bytes, path separators, and reserved names
- `storageUtils.ts:751`: `chatflowId` validated as UUID v4 via `isValidUUID()`
- `storageUtils.ts:756`: `chatId` checked via `isPathTraversal()` — blocks `..`, `/`, `\`, `%2e`, `%2f`, `%5c`
- `storageUtils.ts:872-874` (local storage): Additional checks for `path.isAbsolute()` and `filePath.includes('..')`
- `_sanitizeFilename()` at line 1101 also strips leading dots

**Why scanner/validator got it wrong**: They analyzed only the controller layer and did not trace
into `streamStorageFile()` in the `flowise-components` package. The cross-package boundary
caused both the scanner and the adversarial validator to miss the defense-in-depth sanitization.

---

### Finding 2: Plaintext API Secrets in Database

| Field | Value |
|-------|-------|
| Scanner Severity | HIGH |
| Validator Verdict | CONFIRMED |
| **Manual Verdict** | **TRUE POSITIVE (HIGH)** |

**Scanner/Validator claim**: API secrets stored in plaintext in the database.

**Evidence — two columns in `database/entities/ApiKey.ts`**:
- `apiKey: string` — `text` column, stores **plaintext** API key (e.g., `fl-<64 hex chars>`)
- `apiSecret: string` — `text` column, stores **scrypt hash** of the API key

**Creation flow** (`services/apikey/index.ts:178-184`):
```typescript
const apiKey = generateAPIKey()              // "fl-" + 32 random bytes as hex
const apiSecret = generateSecretHash(apiKey) // scrypt(apiKey, randomSalt)
newKey.apiKey = apiKey       // PLAINTEXT stored in DB
newKey.apiSecret = apiSecret // scrypt hash stored in DB
```

**Validation flow** (`utils/validateKey.ts:53,59-60`):
```typescript
const apiKey = await apikeyService.getApiKey(suppliedKey) // lookup by PLAINTEXT apiKey column
const apiSecret = apiKey.apiSecret
if (!compareKeys(apiSecret, suppliedKey)) return false    // verify via scrypt + timingSafeEqual
```

**Analysis**: The `apiKey` column stores the full secret in plaintext. The `apiSecret` scrypt hash
is completely redundant — an attacker with database read access (SQL injection, backup leak,
exposed DB) gets all API keys directly from the `apiKey` column. The scrypt verification
adds no value since the plaintext is stored alongside it.

**Note**: While `generateSecretHash()` and `compareKeys()` are well-implemented (scrypt + salt +
timingSafeEqual), they protect against nothing when the plaintext sits in an adjacent column.

---

### Finding 3: Missing Authentication on File Access Endpoint

| Field | Value |
|-------|-------|
| Scanner Severity | HIGH |
| Validator Verdict | CONFIRMED |
| **Manual Verdict** | **TRUE POSITIVE (downgrade to MEDIUM)** |

**Scanner/Validator claim**: File access endpoint is unauthenticated, allowing anyone to access
uploaded files.

**Evidence**:
- `/api/v1/get-upload-file` is in `WHITELIST_URLS` (`constants.ts:20`) — bypasses all auth
- Controller comment (line 23): `"This can be public API"` — intentional design
- Used to serve files in embedded chat widget for public chatflows
- The endpoint requires `chatflowId` (UUID), `chatId`, and `fileName` — all must match real data

**The actual vulnerability**:
- No check whether the chatflow has `isPublic = true`
- Files from **private** chatflows are accessible to anyone who knows the IDs
- Security relies entirely on ID secrecy (UUIDs), not access control

**Why downgraded to MEDIUM**: The unauthenticated access is by design for public chatflows.
UUIDs (128-bit random) are effectively unguessable. The real risk is if IDs leak via logs,
referrer headers, or URL sharing — then private chatflow files become exposed.

---

### Finding 4: Weak Session / JWT Configuration Defaults

| Field | Value |
|-------|-------|
| Scanner Severity | MEDIUM |
| Validator Verdict | CONFIRMED |
| **Manual Verdict** | **TRUE POSITIVE (UPGRADE to HIGH/CRITICAL)** |

**Scanner/Validator claim**: Weak default session configuration.

**Evidence** (`enterprise/middleware/passport/index.ts`):
```typescript
const jwtAuthTokenSecret = process.env.JWT_AUTH_TOKEN_SECRET || 'auth_token'
const jwtRefreshSecret = process.env.JWT_REFRESH_TOKEN_SECRET || process.env.JWT_AUTH_TOKEN_SECRET || 'refresh_token'
// Express session:
secret: process.env.EXPRESS_SESSION_SECRET || 'flowise'
```

**Analysis**: If environment variables aren't set (the default), JWT signing secrets are publicly
known strings: `'auth_token'`, `'refresh_token'`, `'flowise'`. Any attacker can:

1. Craft a JWT payload with arbitrary user claims
2. Sign it with the known secret `'auth_token'`
3. Present it as a valid Bearer token
4. Impersonate any user, including admins

**Why upgraded**: The scanner called this MEDIUM but hardcoded default JWT secrets in
production-deployable software enable **complete authentication bypass**. Many users deploy
with defaults, especially in Docker quick-start scenarios. This is a well-known vulnerability
class (CWE-798: Use of Hard-coded Credentials).

---

### Finding 5: Missing Rate Limiting on Authentication Endpoints

| Field | Value |
|-------|-------|
| Scanner Severity | MEDIUM |
| Validator Verdict | CONFIRMED |
| **Manual Verdict** | **TRUE POSITIVE (MEDIUM)** |

**Scanner/Validator claim**: No rate limiting on authentication endpoints.

**Evidence**:
- `utils/rateLimit.ts` implements `RateLimiterManager` — rate limiting exists in the codebase
- But it's **per-chatflow** rate limiting for `/prediction/:id` endpoints only (opt-in via `apiConfig`)
- Auth endpoints (`/auth/login`, `/auth/refreshToken`) are in `WHITELIST_URLS`
- **No rate limiting is applied to any auth endpoint**
- The `RateLimiterManager.getRateLimiter()` only applies to routes with `:id` params

**Analysis**: An attacker can make unlimited login attempts. Combined with Finding 4 (if env
vars ARE set properly and the JWT issue is mitigated), brute-force attacks against credentials
are unrestricted.

**Severity stays MEDIUM**: Production deployments often use reverse proxies (nginx, Cloudflare)
that add rate limiting. The impact requires valid usernames and no external rate limiting.

---

## Scorecard

| # | Finding | Scanner | Validator | Manual Verdict | Correct? |
|---|---------|---------|-----------|----------------|----------|
| 1 | Path Traversal (CRITICAL) | CRITICAL | CONFIRMED | **FALSE POSITIVE** | Scanner WRONG, Validator WRONG |
| 2 | Plaintext API Keys (HIGH) | HIGH | CONFIRMED | **TRUE (HIGH)** | Both correct |
| 3 | Missing Auth on Files (HIGH) | HIGH | CONFIRMED | **TRUE (MEDIUM)** | Real but severity wrong |
| 4 | Weak Session Config (MEDIUM) | MEDIUM | CONFIRMED | **TRUE (HIGH/CRITICAL)** | Real but severity too low |
| 5 | No Auth Rate Limiting (MEDIUM) | MEDIUM | CONFIRMED | **TRUE (MEDIUM)** | Both correct |

**Validator accuracy**: 4/5 real (80% precision on "confirmed" findings)
**Severity accuracy**: 2/5 correct severity (40%)

---

## Scanner Blind Spots: What Was Missed Entirely

### MISSED 1: Unauthenticated OAuth2 Token Refresh (CRITICAL)

**Endpoint**: `POST /api/v1/oauth2-credential/refresh/:credentialId`
**File**: `routes/oauth2/index.ts:307-420`

This endpoint is in `WHITELIST_URLS` (`constants.ts:40`) — **no authentication required**.

The flow:
1. Takes `credentialId` from URL parameter (no auth check)
2. Looks up credential in database
3. Decrypts stored OAuth2 config (client_id, client_secret, refresh_token)
4. Calls the OAuth provider to refresh the token
5. **Returns the fresh access_token in the HTTP response** (line 393-401)

```typescript
res.json({
    success: true,
    tokenInfo: {
        ...tokenData,  // includes access_token!
        has_new_refresh_token: !!tokenData.refresh_token,
        expires_at: updatedCredentialData.expires_at
    }
})
```

**Impact**: An attacker who knows (or enumerates) a credential UUID can obtain fresh OAuth2
access tokens for any connected service — Microsoft Graph, Google Workspace, GitHub, etc.
This grants the attacker full access to whatever the OAuth2 scopes allow.

**Why the scanner missed it**: The OAuth2 route file is relatively straightforward Express code.
The vulnerability requires understanding the WHITELIST_URLS architecture and recognizing that
"whitelisted = unauthenticated" combined with "returns decrypted secrets" is a critical pairing.

### MISSED 2: OAuth2 State Parameter is Credential ID (HIGH)

**File**: `routes/oauth2/index.ts:125`

```typescript
state: credentialId  // Uses credential ID as state parameter
```

The OAuth2 `state` parameter should be a **random, unguessable CSRF nonce** tied to the user's
session. Using the credential ID instead means:

1. **No CSRF protection**: An attacker can craft a callback URL with their own authorization
   code and the victim's credential ID, writing attacker-controlled tokens to the victim's credential
2. **Credential ID leakage**: The state parameter appears in the callback URL, which may be
   logged by the OAuth provider, browser history, or referrer headers — enabling MISSED 1

---

## Overall Assessment

The RLM scanner + adversarial validator pipeline caught real issues but had significant
gaps:

- **False positive that survived validation**: Path traversal (the #1 CRITICAL finding) was
  false — both the scanner and validator failed to trace cross-package sanitization
- **Severity miscalibration**: Hardcoded JWT secrets rated as MEDIUM when it's HIGH/CRITICAL
- **Major blind spots**: The most dangerous real vulnerability (unauthenticated OAuth2 token
  endpoint) was never flagged — it requires architectural understanding of the auth whitelist
  system, which the scanner's file-by-file approach couldn't capture

### Real Vulnerabilities (ranked by actual severity)

1. **CRITICAL**: Unauthenticated OAuth2 token refresh (MISSED by scanner)
2. **HIGH/CRITICAL**: Hardcoded default JWT secrets (found but under-rated)
3. **HIGH**: Plaintext API keys in database (correctly identified)
4. **HIGH**: OAuth2 CSRF via credential ID as state (MISSED by scanner)
5. **MEDIUM**: Missing auth check for private chatflow files (found but over-rated)
6. **MEDIUM**: No rate limiting on auth endpoints (correctly identified)
