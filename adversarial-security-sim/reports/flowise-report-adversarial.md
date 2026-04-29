# Adversarial Security Sim — flowise-report.md

> Source: recursive-lm-security-audit/flowise-report.md · Findings analysed: 2 · Rounds: 1 · Model: gpt-5.4-mini

_Generated 2026-04-29T16:11:38Z_

## Finding 1: REMOTE CODE EXECUTION VIA CUSTOM FUNCTION EXECUTION (CRITICAL)

### RedTeamTriager

## Triage verdict: **Plausible, but the scanner overstates what is proven from the cited snippets**

Based on the cited code references, there is a credible risk of **server-side arbitrary code execution** *if* `javascriptFunction` is actually interpreted or invoked by downstream custom-node logic. However, the report as written does **not yet prove** that arbitrary user-supplied JavaScript is directly executed from these two files alone.

### What the snippets do show
From `utils/executeCustomNodeFunction.ts`:

- It reads `data.javascriptFunction` into `jsFunction`.
- It dynamically imports a module from `componentNodes['customFunction'].filePath`.
- It instantiates `new nodeModule.nodeClass()`.
- It calls `newNodeInstance.init(nodeData, '', options)` and passes:
  - `appDataSource`
  - `databaseEntities`
  - `workspaceId`
  - `orgId`

From `controllers/nodes/index.ts`:

- `executeCustomFunction(req.body, workspaceId, orgId)` is called on request body input.
- The controller snippet itself shows no obvious validation.

### What is **not** proven by the snippet
The report claims:
- arbitrary JavaScript execution,
- OS command execution,
- database exfiltration,
- backdoor installation.

Those are **possible blast-radius outcomes** if the custom function is truly executed with Node.js privileges, but the provided code does **not** itself show:
- `jsFunction` being evaluated,
- `eval`, `new Function`, `vm`, `Function(...)`, or similar,
- any direct call that executes the user-provided string.

So the scanner appears to be inferring execution from the presence of a “custom function” feature plus a raw request field, but the actual sink is not visible in the cited code.

---

## Preconditions a real attacker would need

At minimum, the attacker likely needs:

1. **Network access to the exposed controller route**
   - The trigger surface is the API endpoint that reaches `controllers/nodes/index.ts -> executeCustomFunction()`.

2. **Whatever authentication/authorization the route requires**
   - The snippet does not show auth checks.
   - If this endpoint is protected, the attacker would need valid credentials, a session, or a token.
   - If it is not protected elsewhere, this could be remotely reachable by any client.

3. **A custom node implementation that actually executes the supplied `javascriptFunction`**
   - The decisive question is whether `customFunction`’s `nodeClass.init(...)` consumes `nodeData.inputs.javascriptFunction` as executable code.
   - If `init()` merely stores or validates the string, the finding is not an RCE.

4. **A valid `componentNodes['customFunction']` mapping**
   - The code dynamically imports `componentNodes['customFunction'].filePath`.
   - If that mapping is attacker-influenced, there may be a separate path traversal / module-loading issue.
   - If it is hardcoded server configuration, then it is not itself an attack primitive.

---

## Trigger surface

The likely trigger is:

- An API call into the nodes controller path that invokes:
  - `executeCustomFunction(req.body, workspaceId, orgId)`
- A request body containing:
  - `javascriptFunction`
  - potentially other inputs in `body`

The surface is therefore **HTTP request body handling** in `controllers/nodes/index.ts`, with execution delegated to `utils/executeCustomNodeFunction.ts`.

---

## Data reachable if the claim is valid

If the custom function code truly runs as server-side JavaScript in the application process, then the reachable data could include:

- `appDataSource` database access
- `databaseEntities`
- `workspaceId`, `orgId`-scoped data
- Any secrets available in the process environment
- Local filesystem data accessible to the process user
- Outbound network access from the server, if not restricted

The report’s examples suggest access to:
- user tables,
- credentials,
- API keys,
- local system files.

That would be consistent with **full application-level compromise**, but only if execution is real.

---

## Blast radius IF the finding is valid

If the code path genuinely executes attacker-controlled JavaScript inside the server process, the impact can be severe:

- **Confidentiality**
  - Full read access to application data exposed through `appDataSource`
  - Potential access to configuration, secrets, and environment variables
  - Possible filesystem disclosure

- **Integrity**
  - Database modification or deletion
  - Configuration tampering
  - Potential persistence if the process can write files or alter app state

- **Availability**
  - Process crash, resource exhaustion, infinite loops, or expensive DB queries
  - Potential service disruption or full takeover

- **Lateral movement**
  - Only if the server has network reach and credentials that allow it
  - The report’s “lateral movement” claim is plausible only as a secondary consequence, not guaranteed by the snippet

---

## Why the finding is under-specified / what must be inspected next

To settle whether this is a real RCE, the following code paths need review:

1. **`customFunction` node implementation**
   - Specifically the class loaded from `componentNodes['customFunction'].filePath`
   - Inspect `nodeClass.init(...)` and any helper methods it calls
   - Look for:
     - `eval`
     - `new Function`
     - `vm`, `vm2`
     - `child_process`
     - template-based code generation
     - dynamic import or command execution

2. **Definition of `componentNodes['customFunction']`**
   - Is `filePath` static and trusted, or user-controlled?
   - If user-controlled, the import itself may be a separate high-risk issue.

3. **Route authentication and authorization**
   - The controller snippet does not show whether only privileged users can call it.
   - Determine whether this endpoint is admin-only, workspace-scoped, or public.

4. **Input validation in `nodesService.executeCustomFunction(...)`**
   - The controller passes raw `req.body`
   - Need to inspect whether the service enforces a schema or sanitizes function-related fields

5. **Any server-side sandboxing or restricted execution model**
   - If “custom functions” are actually declarative workflow nodes rather than raw JS execution, then the scanner’s RCE claim is likely false positive or overstated.

---

## Assessment summary

### Likelihood of a real issue
- **Moderate** that there is a dangerous custom-code execution feature.
- **Not proven** from the cited snippets that arbitrary attacker-controlled JavaScript is directly executed.
- The severity could be **critical** if `javascriptFunction` is later evaluated in `customFunction.init(...)`.

### Most accurate current characterization
- **Potential server-side code execution in a custom function feature**
- Or **unsafe dynamic execution path requiring confirmation in the custom node implementation**

### What would make the report clearly valid
- Evidence that `jsFunction` is passed into an interpreter, evaluator, or code-generation sink in the `customFunction` node class.

### What would make it clearly false/benign
- If `javascriptFunction` is only metadata, validated, or transformed into a safe declarative structure without execution.
- If the custom node code does not use the field as executable code at all.

If you want, I can help you draft a follow-up review checklist for the `customFunction` node implementation and the route authorization chain.

### Maintainer

We agree with the triager’s narrower assessment: **the two cited snippets alone do not prove direct arbitrary JS execution**, but they do show a potentially dangerous **user-controlled custom-function execution path** that needs the downstream node implementation inspected.

Code-levelly:

- In `utils/executeCustomNodeFunction.ts`, `data.javascriptFunction` is copied into `jsFunction`, but in the cited snippet **it is not executed here**.
- The function then loads `componentNodes['customFunction'].filePath` and calls `newNodeInstance.init(nodeData, '', options)`.
- In `controllers/nodes/index.ts`, `executeCustomFunction(req.body, workspaceId, orgId)` is invoked with raw request body input, but the controller snippet **does not show any authorization or schema validation**.

So, from these files:

- **Confirmed:** attacker-controlled request data reaches the custom-node pipeline.
- **Not yet proven:** that `javascriptFunction` is evaluated via `eval`/`Function`/`vm` or any other JS sink.
- **Not yet proven:** OS command execution, exfiltration, or persistence.

What would make this a real vuln is if the `customFunction` node class consumes `nodeData.inputs.javascriptFunction` as executable code inside `init()` or a helper it calls. If that happens, then the blast radius could indeed include full application compromise through the `appDataSource`/`databaseEntities` objects passed in `options`.

### Current conclusion
- **Plausible dangerous feature**
- **Insufficient evidence for confirmed RCE from the cited snippets alone**

### Next step
Please inspect the implementation loaded from `componentNodes['customFunction'].filePath`, especially `nodeClass.init(...)`, for any use of:
- `eval`
- `new Function`
- `vm` / `vm2`
- `child_process`
- dynamic code generation/execution

If you want a triage outcome for the report as written: **keep it open, but downgrade the certainty to “potential RCE pending downstream sink confirmation.”**

---

**Verdict**

1. **NEEDS_VALIDATION**  
   - RedTeamTriager: “**the report as written does not yet prove that arbitrary user-supplied JavaScript is directly executed from these two files alone**.”  
   - Maintainer: “**the cited snippet does not show [data.javascriptFunction] is executed here**.”  
   - But both agree the request body reaches a “**potentially dangerous custom-function execution path**” via `executeCustomFunction(req.body, workspaceId, orgId)`.

2. **Winner: Maintainer**  
   - Stronger because it cleanly separates confirmed facts from speculation and avoids claiming RCE without the downstream sink.

3. **Brief rationale**
   - The strongest evidence for danger is that raw input flows into the custom-node pipeline, and `javascriptFunction` is captured as `jsFunction`.  
   - The strongest evidence against a confirmed RCE is that neither snippet shows `eval`, `Function`, `vm`, or any other execution sink.

4. **Exact checks a human should run**
   - Inspect `componentNodes['customFunction'].filePath` and `nodeClass.init(...)` for `eval` / `new Function` / `vm` / `child_process`.  
   - Verify whether `javascriptFunction` is actually executed or only stored/validated.

## Finding 2: INSECURE DIRECT OBJECT REFERENCE (IDOR) IN API KEY OPERATIONS (CRITICAL)

### RedTeamTriager

## Triage verdict: **Plausible, but not yet proven from the snippets alone**

The scanner’s claim is **credible in principle**: the cited controller code shows sensitive API-key operations being delegated to service methods without any visible ownership or membership checks in the controller itself. If `services/apikey/index.ts` also lacks tenant/ownership enforcement, this could indeed be a real IDOR / cross-tenant authorization flaw.

That said, the finding is **under-specified** because the snippets do not show the actual service-layer authorization logic, route guards, or persistence model. In particular, the absence of checks in `controllers/apikey/index.ts` is not enough by itself to prove vulnerability if the service layer or middleware already enforces access control.

---

## What the finding cites

### Controller references
- `controllers/apikey/index.ts`
  - `updateApiKey()`
  - `verifyApiKey()`
  - `getAllApiKeys()`

### Service reference
- `services/apikey/index.ts`

The report explicitly alleges missing ownership checks before:
- updating an API key by `req.params.id`
- listing organization API keys
- potentially deleting/validating keys as well, though the snippet only shows `updateApiKey` and `getAllApiKeys`

---

## Why this is plausibly an IDOR

The suspicious pattern is:

```typescript
await apikeyService.updateApiKey(
    user, req.params.id, req.body.keyName, req.body.permissions
)
```

and:

```typescript
await apikeyService.getAllApiKeysByOrganization(user.activeOrganizationId)
```

The controller passes an object identifier (`req.params.id`) and a tenant-scoped selector (`user.activeOrganizationId`) to the service, but the report claims no ownership verification occurs first.

### If no service-layer checks exist
A real attacker could potentially:
- guess or enumerate an API key ID
- call the update endpoint for a key belonging to another workspace/org
- retrieve API keys for an organization they should not see
- alter permissions on a key to escalate access or disrupt access control

That is classic IDOR / broken object-level authorization.

---

## Preconditions a real attacker would need

If the flaw is real, an attacker would typically need:

1. **An authenticated session**
   - The controller references `req.user as LoggedInUser`, so the endpoints likely require authentication.
   - This is not an unauthenticated bug; it is an authorization bypass.

2. **Access to the relevant API routes**
   - The attacker must be able to reach the API key endpoints in `controllers/apikey/index.ts`.

3. **A way to learn or guess object identifiers**
   - For `updateApiKey(req.params.id)`, the attacker needs a valid API key identifier.
   - Whether this is practical depends on ID format:
     - sequential integer IDs: easier to enumerate
     - UUIDs / random IDs: harder but still possible if leaked elsewhere

4. **Potentially some role or tenant membership**
   - The `getAllApiKeys()` snippet suggests the organization path is gated by `user.isOrganizationAdmin`, but the report alleges the membership check is missing.
   - If the application relies only on `isOrganizationAdmin` without verifying organization membership/active-org consistency, an attacker with stale or mismatched tenant context may exploit it.
   - For update operations, the attacker may only need to be a normal authenticated user if the service does not validate ownership.

---

## Trigger surface

Based on the report, the likely trigger surface is:

### 1) API key update endpoint
- `controllers/apikey/index.ts -> updateApiKey()`
- Uses `req.params.id`, `req.body.keyName`, `req.body.permissions`
- The actionable risk is object-level update authorization failure.

### 2) API key listing endpoint
- `controllers/apikey/index.ts -> getAllApiKeys()`
- The reported issue is around organization-scoped listing and missing org membership verification.
- The branch shown in the report checks `req.query?.type === 'organization' && user.isOrganizationAdmin`
- If that is the only gate, the question is whether `activeOrganizationId` is always trustworthy and bound to the current user’s actual org membership.

### 3) Potentially verify/delete endpoints
- The title mentions “operations,” but the snippets only explicitly show `updateApiKey`, `verifyApiKey`, and `getAllApiKeys`.
- If `verifyApiKey()` or delete endpoints exist in the same file/service and follow the same pattern, they may share the same authorization weakness.

---

## Data reachable if the finding is valid

If the bug is real, the attacker could reach:

1. **API key metadata**
   - key names
   - permissions
   - workspace/org association
   - possibly status, creation info, last-used info

2. **Secret-bearing material, depending on implementation**
   - If the service returns full API key values on create/list/update, the blast radius includes secret disclosure.
   - If only metadata is exposed, the impact is still severe because permissions can be altered.

3. **Authorization state**
   - Changing permissions could grant broader access or disable protections.
   - A malicious update could also cause denial of service by invalidating or renaming keys.

4. **Tenant boundaries**
   - Cross-workspace and cross-organization visibility into keys is a serious multi-tenant isolation failure.

---

## Blast radius if valid

### Confidentiality
- Exposure of API key metadata and potentially secrets
- Cross-tenant enumeration of access patterns
- Possible indirect access to downstream systems protected by those keys

### Integrity
- Unauthorized modification of key names and permissions
- Potential privilege escalation if permissions drive access control
- Tampering with tenant-scoped credentials

### Availability
- API key disablement or corruption could break integrations
- Malicious permission changes could lock out users or services

### Organizational impact
- If API keys are used to authenticate automation or privileged workflows, the impact can extend beyond the application itself into:
  - internal tools
  - data pipelines
  - billing/integration services
  - third-party integrations

---

## Why the finding is not fully proven yet

The report is missing the most important part: **the actual authorization logic in `services/apikey/index.ts`**.

The controller code alone does not prove a vulnerability because:

- authorization may be enforced inside `apikeyService.updateApiKey(...)`
- the route may be protected by middleware that restricts access by workspace/org
- `req.user.activeOrganizationId` may be server-assigned and trustworthy
- the service might query by `(id, workspaceId)` even if the controller doesn’t show it
- `verifyApiKey()` may be a misleading name and not a state-changing/security-sensitive operation at all

---

## Additional code paths to inspect to settle this

To confirm or refute the finding, inspect:

### In `services/apikey/index.ts`
- `updateApiKey(...)`
  - Does it fetch the key by ID only, or by `(id, workspaceId / orgId)`?
  - Does it verify the key belongs to the caller’s workspace/org before update?
- `getAllApiKeysByOrganization(...)`
  - Does it validate the caller is a member of the org, or only that `activeOrganizationId` is set?
- Any `deleteApiKey(...)`, `verifyApiKey(...)`, `getApiKeyById(...)`
  - Look for similar object lookup patterns without tenant filters

### In routing/middleware
- Route guards for the API-key endpoints
- Authentication middleware that populates `req.user`
- Workspace/organization scoping middleware
- Any centralized authorization helper used elsewhere for tenant checks

### In the data model / query layer
- How API keys are stored:
  - is there a `workspaceId` or `organizationId` column?
  - are queries filtered on it?
- Whether IDs are global or tenant-local
- Whether updates are performed directly by ID without ownership conditions

### In `controllers/apikey/index.ts`
- The full implementations of:
  - `verifyApiKey()`
  - any delete/list/get-by-id handlers
- Whether there are missing `try/catch` blocks or silent fallthroughs that might mask auth failures

---

## Practical assessment

### Likely real if:
- `updateApiKey()` and organization listing operate on raw IDs or tenant selectors without verifying ownership in the service layer
- no middleware enforces workspace/org binding
- API key IDs are guessable or discoverable

### Less likely if:
- service-layer queries are tenant-scoped
- middleware enforces org/workspace membership
- `activeOrganizationId` is validated on every request
- the controller snippet is merely missing context and the scanner inferred too much

---

## Bottom line

**Plausibility: medium-high.**  
The finding is **credible** because the controller snippets show potentially sensitive API-key operations being invoked without visible ownership checks. However, **it is not proven** from the report alone. The key deciding evidence will be in `services/apikey/index.ts` and any auth middleware or route guards.

If you want, I can help you build a short verification checklist for the service layer to confirm whether this is a true IDOR or a false positive.

### Maintainer

I agree with the triager’s bottom line: **this is plausible, but the snippets alone do not prove an IDOR**.

What matters here is that the controller is **not where the authorization is expected to live** in this codebase. The controller in `controllers/apikey/index.ts` is just delegating to `apikeyService`:

- `updateApiKey(user, req.params.id, req.body.keyName, req.body.permissions)`
- `getAllApiKeysByOrganization(user.activeOrganizationId)`

So the absence of explicit ownership checks in the controller is **not itself a bug** if the service layer enforces tenant scoping correctly.

## Why I can’t confirm the vuln from the provided snippets

The triager is right that the pattern is suspicious, but there are several common reasons it may still be safe:

1. **Service-layer authorization may exist**
   - If `services/apikey/index.ts` loads the target key with a predicate like:
     - `WHERE id = ? AND organizationId = ?`
     - or `WHERE id = ? AND workspaceId = ?`
   - then cross-tenant updates are blocked even though the controller passes only `req.params.id`.

2. **Middleware may already enforce tenant membership**
   - If requests reach these handlers only after auth middleware populates `req.user` and validates org/workspace access, then the controller not repeating those checks is normal.

3. **`activeOrganizationId` may be server-trusted**
   - The listing call using `user.activeOrganizationId` is only dangerous if that field is user-controlled or can drift out of sync with membership.
   - If it is derived from authenticated session state and enforced centrally, the listing route is not an IDOR by itself.

## What would make this a real bug

This becomes a confirmed authorization flaw if `services/apikey/index.ts` does any of the following:

- updates keys by raw `id` alone
- lists keys for an org without verifying the caller belongs to that org
- trusts `activeOrganizationId` without checking membership
- allows `verifyApiKey()` or similar endpoints to reveal or mutate data without scoping to the caller’s tenant

That would be a true BOLA/IDOR.

## My current assessment

- **Controller evidence:** suspicious, but not sufficient
- **Vulnerability confirmation:** not possible without the service/middleware code
- **Most likely outcome:** either
  - a real IDOR in the service layer, or
  - a false positive because authorization is centralized below the controller

## What I would check next

Specifically in `services/apikey/index.ts`:

- does `updateApiKey()` query by `(id, organizationId)` or just `id`?
- does `getAllApiKeysByOrganization()` verify the caller’s org membership?
- do delete/verify/get-by-id paths follow the same tenant-scoped lookup pattern?

If you can provide that service code, I can confirm whether this is a real cross-tenant auth issue or a false positive.

---

**Verdict**

1. **NEEDS_VALIDATION**  
   - RedTeamTriager: the controller shows “**sensitive API-key operations being delegated to service methods without any visible ownership or membership checks in the controller itself**.”  
   - Maintainer: “**the absence of explicit ownership checks in the controller is not itself a bug if the service layer enforces tenant scoping correctly**.”  
   - So the snippets show a suspicious pattern, but not a proven IDOR.

2. **Winner: Maintainer**  
   - Stronger because it correctly notes that authorization may be centralized in the service layer, which the cited snippets do not expose.

3. **Brief rationale**
   - The strongest pro-vuln point is `updateApiKey(user, req.params.id, req.body.keyName, req.body.permissions)` using a raw object ID.  
   - The strongest counterpoint is that the controller is only delegating; the real check may be in `services/apikey/index.ts`.

4. **Exact checks a human should run**
   - Inspect `services/apikey/index.ts` to see whether `updateApiKey()` and `getAllApiKeysByOrganization()` query by `(id, organizationId/workspaceId)` and verify membership.  
   - Check route middleware/auth guards to confirm whether org/workspace access is enforced before these handlers run.
