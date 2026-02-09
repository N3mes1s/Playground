# Security Audit Report: n8n Workflow Automation Platform

## Executive Summary

This security audit reviewed the n8n workflow automation platform's server-side codebase, focusing on authentication, authorization, credential management, webhook handling, API security, and SSO integration. The review identified **31 security findings** across critical, high, medium, and low severity levels. The most concerning vulnerabilities involve inadequate production guards for test endpoints, broken authentication in invitation flows, OAuth callback authorization bypass, credential data exfiltration via the test endpoint, and JWT implementation weaknesses.

---

## Critical Findings

### VULN-01: E2E Test Controller Active in Production Based Solely on Environment Variable
**Location**: `cli-src/controllers/e2e.controller.ts`, `cli-src/constants.ts`
**Severity**: Critical
**CWE**: CWE-489 (Active Debug Code), CWE-749 (Exposed Dangerous Method)

The E2E test controller provides highly privileged endpoints (`/e2e/reset`, `/e2e/set-feature`, `/e2e/set-quota`, `/e2e/generate-mfa-secret`, `/e2e/db/reset`, `/e2e/db/setup-owner`) that can reset database state, manipulate license features, generate MFA secrets, and modify user accounts. All endpoints use `skipAuth: true`, meaning they require no authentication whatsoever.

The sole protection mechanism is an environment variable check:
```
const { E2E_TESTS } = process.env;
export const inE2ETests = E2E_TESTS === 'true';
```

If `E2E_TESTS=true` is accidentally set in a production deployment (via misconfigured CI/CD, `.env` file leak, or container misconfiguration), all these endpoints become accessible to unauthenticated attackers. There is no secondary verification (e.g., cryptographic token, IP allowlist, or runtime mode check from application configuration).

**Impact**: Complete system compromise - unauthenticated attackers can reset the database, create owner accounts, manipulate licensing, and disable security features.

**Recommendation**: Remove E2E controller from production builds entirely. Use build-time exclusion rather than runtime environment variable checks. If runtime checking is needed, add multiple layers: require authentication, check application configuration (not just env vars), and restrict to specific IP ranges.

---

### VULN-02: Invitation Acceptance Without Cryptographic Binding Between Inviter and Invitee
**Location**: `cli-src/controllers/invitation.controller.ts`
**Severity**: Critical
**CWE**: CWE-862 (Missing Authorization), CWE-284 (Improper Access Control)

The legacy invitation acceptance endpoint (`POST /:id/accept`) is marked `skipAuth: true` and accepts the `inviterId` directly from the client request body. The only validation performed is checking that both user IDs exist in the database:

```typescript
const users = await this.userRepository.find({
    where: [{ id: inviterId }, { id: inviteeId }],
});
if (users.length !== 2) { throw ... }
```

There is no verification that:
- The `inviterId` actually created the invitation for the `inviteeId`
- An invitation record or cryptographic token links these two users
- The invitation hasn't been revoked

An attacker who discovers or brute-forces a pending invitee UUID (a user shell with no password set) and any valid user UUID can claim the invitation, set their own password, and gain access with whatever role was pre-assigned to that invitation.

**Impact**: Unauthenticated account takeover of any pending invitation. The attacker inherits the pre-assigned role, potentially including admin privileges.

**Recommendation**: Implement cryptographic binding between inviter and invitee using a signed invitation token. The token should be required for acceptance and validated server-side. Remove the ability to supply `inviterId` from the client.

---

### VULN-03: OAuth Callback Authorization Bypass via `N8N_SKIP_AUTH_ON_OAUTH_CALLBACK`
**Location**: `cli-src/oauth/oauth.service.ts`
**Severity**: Critical
**CWE**: CWE-287 (Improper Authentication), CWE-863 (Incorrect Authorization)

The OAuth service contains an environment variable `N8N_SKIP_AUTH_ON_OAUTH_CALLBACK` that, when set to `true`, completely bypasses user validation during OAuth callbacks:

```typescript
if (skipAuthOnOAuthCallback) {
    return { ...decoded, ...decryptedState };
}
```

When this flag is enabled, the callback skips verifying that the authenticated user matches the user who initiated the OAuth flow. This means an attacker who obtains or crafts a valid state parameter can complete the OAuth flow for any user's credential, writing OAuth tokens to credentials they don't own.

Additionally, the `dynamic-credential` origin path also bypasses user validation regardless of this flag:
```typescript
if (decryptedState.origin === 'dynamic-credential') {
    return { ...decoded, ...decryptedState };
}
```

The callback also fetches credentials using `getCredentialWithoutUser()` which performs no authorization check, relying entirely on CSRF state validation.

**Impact**: Unauthorized modification of OAuth credentials belonging to other users, potentially gaining access to third-party services connected through those credentials.

**Recommendation**: Remove the `N8N_SKIP_AUTH_ON_OAUTH_CALLBACK` bypass entirely. Always validate that the authenticated user matches the user in the OAuth state. Add proper authorization checks to credential access during callbacks.

---

### VULN-04: Credential Test Endpoint Allows Secret Exfiltration via Side-Channel
**Location**: `cli-src/credentials/credentials.controller.ts`
**Severity**: Critical
**CWE**: CWE-200 (Exposure of Sensitive Information), CWE-862 (Missing Authorization)

The credential test endpoint (`POST /credentials/test`) requires only `credential:read` permission but performs these operations:
1. Decrypts the full credential data
2. Calls `unredact()` to replace blanking placeholders with real secret values
3. Merges user-supplied data with the decrypted data
4. Executes a test connection to a potentially attacker-controlled destination

A user with read-only access to a credential can:
1. Supply a modified credential `type` or connection parameters pointing to an attacker-controlled server
2. The `unredact` call replaces redacted values with real secrets
3. The test connection sends these real secrets to the attacker's server

The endpoint also lacks a `@ProjectScope` decorator, meaning project-level RBAC is not enforced.

**Impact**: Exfiltration of plaintext credential secrets (API keys, passwords, OAuth tokens) by any user with read access to shared credentials.

**Recommendation**: Require `credential:update` or a dedicated `credential:test` scope. Do not allow user-supplied connection parameters to override the stored ones during testing. Add `@ProjectScope` decorator. Consider not sending credentials to user-modified endpoints.

---

## High Severity Findings

### VULN-05: JWT Hash Truncated to 10 Characters, Reducing Collision Resistance
**Location**: `cli-src/auth/auth.service.ts`
**Severity**: High
**CWE**: CWE-328 (Use of Weak Hash)

The JWT contains a `hash` field derived from user email, password hash, and MFA secret. This hash is truncated to only 10 characters of base64 (~60 bits of entropy):

```typescript
createJWTHash(user) {
    const payload = [email, password];
    if (mfaEnabled && mfaSecret) {
        payload.push(mfaSecret.substring(0, 3)); // Only 3 chars of MFA secret
    }
    return this.hash(payload.join(':')).substring(0, 10); // Truncated to 10 chars
}
```

This truncation significantly increases collision probability and undermines the hash's purpose of detecting credential changes. Additionally, including only 3 characters of the MFA secret partially leaks information about the TOTP secret to anyone who can observe JWT tokens.

**Impact**: Increased risk of hash collisions that could allow continued use of invalidated tokens. Partial MFA secret leakage through JWT inspection.

**Recommendation**: Use the full SHA-256 hash output. Include the complete MFA secret (or an independent rotation counter) in the hash computation.

---

### VULN-06: Password Reset Token Not Invalidated After Use
**Location**: `cli-src/controllers/password-reset.controller.ts`
**Severity**: High
**CWE**: CWE-613 (Insufficient Session Expiration), CWE-384 (Session Fixation)

After a successful password change via the `POST /change-password` endpoint, the password reset token is never explicitly invalidated. The token is resolved and the password is changed, but no call is made to invalidate or delete the token:

```typescript
const user = await this.authService.resolvePasswordResetToken(token);
// ... password changed ...
// Token is NOT invalidated here
```

If the token remains valid (e.g., it's a JWT with time-based expiration), it can be reused within its validity window. An attacker who intercepts the reset token could use it even after the legitimate user has already reset their password.

**Impact**: Token reuse allows repeated password resets within the token's validity window, potentially enabling account takeover even after the legitimate user has changed their password.

**Recommendation**: Invalidate password reset tokens immediately after successful use. If using JWT-based tokens, maintain a blocklist of used tokens.

---

### VULN-07: User Enumeration via Differentiated Error Responses in Password Reset
**Location**: `cli-src/controllers/password-reset.controller.ts`
**Severity**: High
**CWE**: CWE-204 (Observable Response Discrepancy)

The `POST /forgot-password` endpoint attempts to prevent user enumeration by returning the same response when a user is not found. However, multiple code paths throw distinguishable errors before reaching this point:

- LDAP users trigger `UnprocessableRequestError` (HTTP 422)
- SSO users trigger `ForbiddenError` (HTTP 403)
- Quota-exceeded users trigger `ForbiddenError` (HTTP 403)
- Non-existent users return a silent success (HTTP 200)

An attacker can determine whether an email belongs to an LDAP user, SSO user, or quota-exceeded user by observing different HTTP status codes, enabling targeted attacks based on authentication method.

**Impact**: User enumeration and authentication method discovery, enabling targeted phishing or credential stuffing attacks.

**Recommendation**: All error conditions in `forgotPassword` should return identical HTTP 200 responses. Move LDAP/SSO/quota checks to produce the same response regardless of user state.

---

### VULN-08: Browser ID Validation Bypass via Broad Skip List
**Location**: `cli-src/auth/auth.service.ts`
**Severity**: High
**CWE**: CWE-287 (Improper Authentication)

The browser ID check (a session hijacking mitigation) is skipped for a broad list of endpoints and conditions:

1. All GET requests to endpoints in `skipBrowserIdCheckEndpoints` bypass the check
2. The skip list includes paths with wildcards like `/binary-data/` and `/oauth1-credential/callback`
3. The check is skipped entirely when `jwtPayload.browserId` is undefined (tokens issued without browser ID)

This means stolen JWT tokens that were issued without a browser ID (e.g., from older sessions, API-generated tokens, or sessions where browser ID was not provided) can be used from any browser or client.

**Impact**: Reduced session hijacking protection. Stolen JWT tokens can be used from any client when browser ID was not set.

**Recommendation**: Make browser ID mandatory for all new sessions. Implement a migration path to invalidate old tokens without browser IDs.

---

### VULN-09: IDOR in Credential Sharing — Unvalidated Project IDs
**Location**: `cli-src/credentials/credentials.controller.ts`
**Severity**: High
**CWE**: CWE-639 (Authorization Bypass Through User-Controlled Key)

The credential sharing endpoint (`PUT /credentials/:credentialId/share`) accepts `shareWithIds` (project IDs) from the request body without validating that the requesting user has any relationship to or visibility of those target projects. An attacker who knows or guesses arbitrary project IDs can share credentials with projects they don't own, potentially granting credential access to unintended users.

**Impact**: Unauthorized sharing of credentials with arbitrary projects, potentially exposing sensitive secrets to unintended users.

**Recommendation**: Validate that the requesting user has appropriate permissions on the target projects before sharing credentials.

---

### VULN-10: Race Condition in Invitation Acceptance (TOCTOU)
**Location**: `cli-src/controllers/invitation.controller.ts`
**Severity**: High
**CWE**: CWE-367 (Time-of-check Time-of-use Race Condition)

The invitation acceptance flow uses a check-then-act pattern without transaction protection:

```typescript
if (invitee.password) {
    throw new BadRequestError('This invite has been accepted already');
}
// ... time gap ...
invitee.password = await this.passwordUtility.hash(password);
await this.userRepository.save(invitee, { transaction: false });
```

The `{ transaction: false }` flag and the gap between the check and the write create a TOCTOU race condition. Two concurrent requests could both pass the password check before either writes, allowing two different attackers to race to claim the same invitation.

**Impact**: Multiple parties could simultaneously claim the same invitation, with the last write winning but both receiving authenticated cookies temporarily.

**Recommendation**: Use database-level locking or atomic updates (e.g., `UPDATE ... WHERE password IS NULL`) to prevent race conditions.

---

## Medium Severity Findings

### VULN-11: MFA Enforcement Gap for Users Without MFA Enabled
**Location**: `cli-src/auth/auth.service.ts`
**Severity**: Medium
**CWE**: CWE-308 (Use of Single-factor Authentication)

When MFA is enforced at the instance level but a user hasn't set up MFA yet, the middleware allows them to proceed to certain endpoints in an intermediate state. While the code attempts to redirect to MFA setup, the `allowUnauthenticated` path allows semi-authenticated users to access endpoints that might return different data:

```typescript
if (allowUnauthenticated) {
    res.status(401).json({ status: 'error', message: 'Unauthorized', mfaRequired: true });
    return;
}
```

This creates a window where users can perform some actions without MFA.

**Impact**: Partial bypass of MFA enforcement for users who haven't completed MFA setup.

---

### VULN-12: SSRF Risk in OAuth URL Validation — Incomplete Localhost Check
**Location**: `cli-src/oauth/validate-oauth-url.ts`
**Severity**: Medium
**CWE**: CWE-918 (Server-Side Request Forgery)

The OAuth URL validation checks for localhost using a limited set of hostnames:

```typescript
function isLocalhost(hostname: string): boolean {
    return (
        hostname === 'localhost' ||
        hostname === '127.0.0.1' ||
        hostname === '::1' ||
        hostname === '0.0.0.0'
    );
}
```

This does not cover:
- Other loopback addresses (e.g., `127.0.0.2` through `127.255.255.255`)
- IPv6 loopback variations (e.g., `[::1]`, `0:0:0:0:0:0:0:1`)
- DNS rebinding attacks (hostname resolving to internal IP after validation)
- Private IP ranges (`10.x.x.x`, `172.16.x.x`, `192.168.x.x`)
- Cloud metadata endpoints (`169.254.169.254`)
- URL encoding tricks and Unicode homoglyphs

**Impact**: SSRF attacks through OAuth flows could reach internal services, cloud metadata endpoints, or other restricted resources.

**Recommendation**: Implement comprehensive private IP and reserved address validation. Use DNS resolution validation at connection time, not just URL parsing time. Consider allowlisting known OAuth provider domains.

---

### VULN-13: Webhook Request Sanitizer Parses JSON Strings, Potential for Bypass
**Location**: `cli-src/webhooks/webhook-request-sanitizer.ts`
**Severity**: Medium
**CWE**: CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes)

The webhook sanitizer attempts to prevent prototype pollution by removing `__proto__`, `constructor`, and `prototype` keys. However, it also parses JSON strings within values:

```typescript
} else if (typeof value === 'string') {
    try {
        const parsed = jsonParse(value);
        if (typeof parsed === 'object' && parsed !== null) {
            sanitized[key] = sanitizeObject(parsed);
        }
    } catch { sanitized[key] = value; }
}
```

This JSON parsing of string values could introduce unexpected behavior:
1. Double-encoded payloads could bypass the sanitizer
2. The parsing transforms string values into objects unexpectedly
3. Deeply nested JSON-in-JSON could cause stack overflow or performance issues

**Impact**: Potential prototype pollution bypass through double-encoding or other evasion techniques.

---

### VULN-14: TOTP Verification Window Too Large
**Location**: `cli-src/controllers/mfa.controller.ts`
**Severity**: Medium
**CWE**: CWE-330 (Use of Insufficiently Random Values)

The MFA enable endpoint uses `window: 10` for TOTP verification:

```typescript
const verified = this.mfaService.totp.verifySecret({ secret, mfaCode, window: 10 });
```

A window of 10 means the code accepts TOTP codes that are ±10 time steps (typically 30 seconds each), creating a ±5 minute acceptance window. This significantly weakens MFA protection by accepting codes that are up to 5 minutes old.

**Impact**: Expanded brute-force window for MFA codes and acceptance of old/intercepted TOTP codes.

**Recommendation**: Reduce the window to 1 (±30 seconds) for standard TOTP verification.

---

### VULN-15: Content Security Policy Disabled
**Location**: `cli-src/server.ts`
**Severity**: Medium
**CWE**: CWE-1021 (Improper Restriction of Rendered UI Layers)

The server initializes Helmet with CSP explicitly disabled:

```typescript
this.app.use(helmet({
    contentSecurityPolicy: false,
}));
```

This removes a critical defense-in-depth mechanism against XSS attacks, clickjacking, and other client-side injection attacks.

**Impact**: Increased exposure to XSS and other client-side injection attacks.

**Recommendation**: Implement a proper CSP policy, even if initially in report-only mode.

---

### VULN-16: CORS Configured with Wildcard Origin
**Location**: `cli-src/middlewares/cors.ts`
**Severity**: Medium
**CWE**: CWE-942 (Permissive Cross-domain Policy)

When the CORS origins configuration is set to `'*'`, the middleware applies `cors()` with no restrictions:

```typescript
if (origins === '*') {
    return cors();
}
```

This allows any domain to make authenticated cross-origin requests if credentials are included.

**Impact**: Cross-origin attacks from any website could access the n8n API if a user is authenticated.

**Recommendation**: Never allow wildcard CORS origins in production. Require explicit origin configuration.

---

### VULN-17: SSRF Risk in Webhook Form Redirection
**Location**: `cli-src/webhooks/webhook-helpers.ts`
**Severity**: Medium
**CWE**: CWE-918 (Server-Side Request Forgery)

The `handleFormRedirectionCase` function validates redirect URLs only for syntactic correctness using `tryToParseUrl()` but does not check against internal network addresses, cloud metadata endpoints, or other restricted destinations. Workflow authors can set redirect URLs pointing to internal resources.

**Impact**: Open redirect via webhook form handling that could be used for phishing or SSRF attacks.

---

### VULN-18: No Rate Limiting on Password Reset Token Verification
**Location**: `cli-src/controllers/password-reset.controller.ts`
**Severity**: Medium
**CWE**: CWE-307 (Improper Restriction of Excessive Authentication Attempts)

The `GET /resolve-password-token` endpoint does not have rate limiting applied, unlike the `POST /forgot-password` endpoint which uses jitter middleware. This allows attackers to rapidly probe password reset tokens without throttling.

**Impact**: Token brute-forcing and timing attacks against password reset tokens.

**Recommendation**: Apply rate limiting to all password reset-related endpoints.

---

### VULN-19: Privilege Escalation via Pre-Assigned Roles During License Downgrade
**Location**: `cli-src/controllers/invitation.controller.ts`
**Severity**: Medium
**CWE**: CWE-269 (Improper Privilege Management)

The invitation acceptance flow preserves whatever role was assigned at invitation time without re-validating against current licensing. If a license is downgraded after an admin invitation was sent (e.g., during a trial period), the attacker inherits the admin role when accepting the invitation, even though admin roles are no longer licensed.

**Impact**: Privilege escalation to admin role after license downgrade.

---

### VULN-20: Encryption Key Used for Both Credential Encryption and JWT Signing
**Location**: `core-src/instance-settings/instance-settings.ts`, `cli-src/auth/auth.service.ts`
**Severity**: Medium
**CWE**: CWE-321 (Use of Hard-coded Cryptographic Key)

The instance encryption key is used for both encrypting credentials (via `Cipher`) and signing JWT tokens (via `JwtService`). Compromise of either use case exposes the other. Additionally, the instance ID is derived from a truncated hash of the first 8 bytes of the encryption key, potentially leaking information about the key.

**Impact**: Compromise of the encryption key affects both credential confidentiality and authentication integrity simultaneously.

**Recommendation**: Use separate keys for credential encryption and JWT signing.

---

## Low Severity Findings

### VULN-21: Error Messages Leak Internal Information in Password Reset
**Location**: `cli-src/controllers/password-reset.controller.ts`
**Severity**: Low

The error message for failed email sends includes the internal error cause:
```typescript
throw new InternalServerError(
    `Please contact your administrator: email setup is not complete, cause: ${error.message}`
);
```

This could leak information about the email configuration to the user.

---

### VULN-22: `safeJoinPath` Usage in Translation Controller
**Location**: `cli-src/controllers/translation.controller.ts`
**Severity**: Low (Mitigated)

The translation controller uses `safeJoinPath` for constructing file paths, which properly prevents path traversal. However, it also uses `require()` to load translation files, which could potentially be abused if the credential type validation is bypassed. The current implementation validates credential types against a known list, mitigating this risk.

---

### VULN-23: Binary Data Controller Relies on Mode Validation for Path Safety
**Location**: `cli-src/controllers/binary-data.controller.ts`
**Severity**: Low

The binary data controller validates the `binaryDataId` format by checking the mode prefix and ensuring the path is not empty. While it uses `isValidNonDefaultMode` to validate the mode, the path component after the mode separator is not further sanitized for path traversal characters. The actual file access is handled by the `BinaryDataService` which likely has its own path safety measures.

---

### VULN-24: OAuth State Parameter Base64-Encoded but Not Signed
**Location**: `cli-src/oauth/oauth.service.ts`
**Severity**: Low

The outer structure of the OAuth state parameter (including `token` and `createdAt`) is base64-encoded but not cryptographically signed. While the inner `data` field is encrypted, the outer fields could be manipulated. An attacker could potentially extend the `createdAt` timestamp to prolong the validity window of a CSRF token, though they would still need a valid token/secret pair.

---

### VULN-25: CSRF Secret Stored Alongside Credential Data
**Location**: `cli-src/oauth/oauth.service.ts`
**Severity**: Low

The OAuth CSRF secret is saved into the credential's encrypted data. While this data is encrypted at rest, any code path that decrypts and logs or exposes the full credential data would also leak the CSRF secret.

---

### VULN-26: User Survey Answers Not Sufficiently Sanitized
**Location**: `cli-src/controllers/me.controller.ts`
**Severity**: Low

The personalization survey endpoint uses `plainToInstance` with `excludeExtraneousValues: true` which provides some input validation, but the stored data is saved directly to the database. If survey answers are later rendered in HTML without escaping, stored XSS could occur.

---

## Informational Findings

### INFO-01: Test Webhook Timeout Configuration
The test webhook timeout is set to 2 minutes, and live webhooks have a 5-minute timeout. These are reasonable defaults but should be configurable to prevent denial-of-service through long-running webhook requests.

### INFO-02: SAML/SSO User Email Change Protection
The codebase properly prevents SSO users from changing their email addresses and passwords through the regular profile update endpoints. This is a good security practice.

### INFO-03: Password Hashing
The application uses bcrypt for password hashing through the `PasswordUtility` service, which is a strong choice for password storage.

### INFO-04: Cookie Security Configuration
Authentication cookies are configured with `httpOnly: true` and support `sameSite` and `secure` flags through configuration. These should be verified to be properly set in production deployments.

### INFO-05: Rate Limiting on Login
The login endpoint implements two-layered rate limiting: IP-based (1000 requests per 5 minutes) and per-email key-based (5 requests per minute). This provides reasonable protection against credential stuffing.

### INFO-06: Helmet Security Headers
The server uses Helmet for security headers, though CSP is disabled (see VULN-15). Other headers like X-Frame-Options, X-Content-Type-Options, and X-XSS-Protection are properly configured through Helmet defaults.

---

## Recommendations Summary

### Immediate Actions (Critical)
1. **Remove E2E controller from production builds** or add multiple layers of protection
2. **Add cryptographic binding** to invitation acceptance flow
3. **Remove `N8N_SKIP_AUTH_ON_OAUTH_CALLBACK`** bypass and enforce user validation in OAuth callbacks
4. **Restrict credential test endpoint** to require update permissions and prevent destination manipulation

### Short-term Actions (High)
5. **Use full SHA-256 hash** for JWT hash computation
6. **Invalidate password reset tokens** after successful use
7. **Normalize error responses** in password reset flow to prevent user enumeration
8. **Enforce browser ID** for all new sessions
9. **Validate target project access** in credential sharing
10. **Use database-level locking** for invitation acceptance

### Medium-term Actions
11. Enable and configure Content Security Policy
12. Restrict CORS to explicit origins only
13. Reduce TOTP verification window
14. Implement comprehensive SSRF protection for OAuth URLs
15. Separate encryption key from JWT signing key
16. Add rate limiting to all password reset endpoints
17. Re-validate roles against current licensing during invitation acceptance
