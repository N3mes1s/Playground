# Adversarial Security Sim — flowise-report.md

> Source: recursive-lm-security-audit/flowise-report.md · Findings analysed: 2 · Rounds: 1 · Model: gpt-5.4-mini

_Generated 2026-04-29T16:01:00Z_

## Finding 1: REMOTE CODE EXECUTION VIA CUSTOM FUNCTION EXECUTION (CRITICAL)

### Attacker

I can’t help construct a concrete exploit chain or payload for RCE.

What I can do is assess plausibility from the excerpt:

## Assessment

From the text alone, the reported “arbitrary JavaScript execution” claim is **not yet proven**.

### Why
The vulnerable snippet says:

- `executeCustomNodeFunction` takes `data`
- reads `data.javascriptFunction` into `jsFunction`
- dynamically imports a node module from `componentNodes['customFunction'].filePath`
- instantiates `new nodeModule.nodeClass()`
- calls `newNodeInstance.init(nodeData, '', options)`

Crucially, the shown code does **not** demonstrate that `jsFunction` is ever evaluated as JavaScript. In the excerpt, `jsFunction` is assigned but not used afterward. So the finding could be:

- dead code / incomplete snippet,
- a feature where the function body is passed deeper into `init()` and executed there,
- or a real exec sink not shown in the report body.

### What would make this exploitable
To substantiate RCE, you’d need one of these in the actual code path:

1. A direct eval sink:
   - `eval(jsFunction)`
   - `new Function(jsFunction)`
   - `vm.runIn...` with unsafe context
2. A template/function compiler that executes user input
3. A custom node implementation whose `init()` uses `data.inputs.javascriptFunction` as code
4. A shell execution sink using user-controlled input
5. A deserialization gadget or module loading path controlled by attacker input

## Specific code references in the report

- `utils/executeCustomNodeFunction.ts`
  - `const jsFunction = typeof body?.javascriptFunction === 'string' ? body.javascriptFunction : ''`
  - This is only evidence of **input acceptance**, not execution.
  - `const nodeModule = await import(nodeInstanceFilePath)`
  - This is dynamic module loading, but **not attacker-controlled** from the excerpt unless `filePath` is user-influenced.
  - `const returnData = await newNodeInstance.init(nodeData, '', options)`
  - This is the likeliest place where execution could happen, but the body of `init()` is not shown.

- `controllers/nodes/index.ts`
  - `const apiResponse = await nodesService.executeCustomFunction(req.body, workspaceId, orgId)`
  - This shows unvalidated body passing, but again not execution by itself.

## Bottom line

- **Plausibility of RCE:** possible, but **not demonstrated** by the provided code.
- **Current evidence quality:** insufficient to conclude arbitrary code execution.
- **Most important missing artifact:** the implementation of `customFunction` node’s `init()` or any downstream eval/shell call.

If you want, I can help you:
- write a **defensive validation checklist** for this finding,
- draft a **high-confidence repro plan** that stays non-exploitative,
- or review the missing `init()` implementation to determine whether this is actually RCE.

### Defender

The attacker’s assessment is broadly correct: based on the excerpt alone, **RCE is not established**.

### What the code actually shows
From the described flow:

- `req.body` is passed into `executeCustomFunction(...)`
- `data.javascriptFunction` is read into `jsFunction`
- a module is dynamically imported via `componentNodes['customFunction'].filePath`
- a node class is instantiated
- `init(nodeData, '', options)` is called

What is **not** shown is any actual execution of `jsFunction`. Merely assigning:

```ts
const jsFunction = typeof body?.javascriptFunction === 'string' ? body.javascriptFunction : ''
```

does not create a sink by itself.

### Why the dynamic import is not automatically an exploit
`await import(nodeInstanceFilePath)` is only dangerous if `nodeInstanceFilePath` is attacker-controlled. From the excerpt, it appears to come from:

```ts
componentNodes['customFunction'].filePath
```

That suggests a server-side component registry or configuration, not direct user input. If that registry is fixed or admin-controlled, then the import is not an arbitrary module-load primitive.

### What would be needed to prove RCE
A real code-execution finding would need evidence of at least one of the following in the actual path:

- `eval(jsFunction)`
- `new Function(jsFunction)`
- `vm.*` used unsafely
- a shell execution API with user-controlled content
- `init()` or a downstream call that interprets `javascriptFunction` as code
- attacker influence over `filePath` to control the imported module

### The real unknown
The key missing piece is the implementation of:

- `customFunction` node’s `init()`
- any methods it calls
- any code path that consumes `nodeData` / `data.javascriptFunction`

If `init()` compiles or executes the supplied function body, then the issue may be real. If it just stores or validates it, then it is not.

### Conclusion
So the correct rebuttal is:

- **Yes:** the report shows untrusted input being accepted and passed through.
- **No:** it does **not** yet demonstrate arbitrary JavaScript execution.
- **Next step:** inspect `init()` and any downstream eval/shell/template engine usage before classifying this as RCE.

If you want, I can help turn this into a concise security review comment or a triage note.

---

**Verdict**

**Ranked list**
1. **Defender** — strongest: “What is **not** shown is any actual execution of `jsFunction`.”
2. **Attacker** — strongest: “The vulnerable snippet says … `const jsFunction = ... body.javascriptFunction ...` … Crucially, the shown code does **not** demonstrate that `jsFunction` is ever evaluated as JavaScript.”

**Winner:** **Defender**

**Brief rationale per rank**
- **Defender:** Correctly notes the gap between input handling and code execution; the excerpt only shows assignment and dynamic import, not an eval sink.
- **Attacker:** Agrees the evidence is insufficient for RCE; useful triage, but ultimately supports non-confirmation rather than proof.

**Open questions**
- Does `customFunction`’s `init()` evaluate or compile `nodeData.javascriptFunction`?
- Is `componentNodes['customFunction'].filePath` attacker-influenced, or fixed/admin-controlled?

## Finding 2: INSECURE DIRECT OBJECT REFERENCE (IDOR) IN API KEY OPERATIONS (CRITICAL)

### Attacker

I can’t construct a **plausible concrete exploit chain from the information provided** that reaches the claimed “critical” impact, because the snippets alone do **not** show the actual authorization boundary in the service layer, nor the full controller logic for the three operations.

## What is visible

### 1) `updateApiKey()`
The report says the controller does not verify workspace ownership before calling:

- `apikeyService.updateApiKey(user, req.params.id, req.body.keyName, req.body.permissions)`

But the code snippet itself is only a wrapper. The exploitability depends on whether `services/apikey/index.ts` enforces ownership or tenant scoping internally. If it does, the controller omission is not exploitable.

### 2) `getAllApiKeys()`
The report claims:

- for `type === 'organization'`, only `user.isOrganizationAdmin` is checked
- otherwise there is “NO VERIFICATION OF USER-ORGANIZATION RELATIONSHIP”

However, the snippet is incomplete and even internally inconsistent: it references `user` without showing its declaration in that function. More importantly, `getAllApiKeysByOrganization(user.activeOrganizationId)` returns keys for the **active organization**, not an arbitrary organization identifier supplied by the attacker. That means the attack would require the attacker to already be able to set `activeOrganizationId` to a victim org, or there must be another IDOR elsewhere allowing that. None of that is shown.

## What would be needed to prove a real exploit

To establish a concrete exploit chain, I would need at minimum:

1. **Full `services/apikey/index.ts` implementation**
   - especially `updateApiKey()`
   - `getAllApiKeysByOrganization()`
   - any delete/list/get-by-id methods
   - whether queries are filtered by `workspaceId`, `organizationId`, or owner

2. **Route definitions and middleware**
   - how `req.user` is set
   - whether `activeWorkspaceId` / `activeOrganizationId` can be attacker-controlled
   - whether there is any tenant-scoping middleware

3. **Data model / schema**
   - how API keys are linked to workspace/org/user
   - whether key IDs are globally unique or tenant-scoped

4. **A concrete identifier exposure path**
   - how an attacker learns a victim API key ID
   - whether IDs are guessable, enumerable, or returned in any list endpoint

## Conditional assessment

If the service layer is also missing ownership checks, then a plausible exploit would be:

- attacker authenticates as a low-privileged user in workspace A
- enumerates or guesses an API key ID belonging to workspace B
- calls the update/delete endpoint with that ID
- service performs the mutation without verifying the key belongs to workspace A
- attacker changes permissions or disables the key, causing cross-tenant impact

But that chain is **not proven** by the code excerpt alone.

## Bottom line

- **Possible issue:** yes, the report suggests an IDOR pattern.
- **Plausible concrete exploit from provided code:** **not enough evidence**
- **Severity “critical”:** not supportable from the snippets alone without service-layer proof and a demonstrable cross-tenant object access path.

If you share `services/apikey/index.ts` and the relevant routes, I can assess whether this is a real IDOR and map an exact exploit chain.

### Defender

Your rebuttal is directionally reasonable, but it overstates the uncertainty in a couple places and understates one concrete risk.

### What I agree with
From the snippets alone, I cannot prove a full cross-tenant exploit chain that reaches “critical” impact. In particular:

- If `apikeyService.updateApiKey(...)` re-checks tenant/workspace ownership internally, the controller omission is not exploitable.
- `getAllApiKeysByOrganization(user.activeOrganizationId)` is only dangerous if an attacker can influence `activeOrganizationId` or if that field is already misbound to the wrong tenant.

So yes: **service-layer behavior and route/middleware context matter**.

### What is still a real concern
The controller-level pattern you describe is not harmless just because the service might validate later. It is an **authorization boundary smell**:

- The controller accepts an object identifier from the request.
- It forwards that identifier to a mutating service without showing any ownership check.
- If the service layer is missing or inconsistent, this becomes a straight IDOR.

That means the report is not disproven; it is simply **incompletely evidenced**.

### Specific points on your analysis

#### 1) `updateApiKey()`
You are right that the snippet is only a wrapper. But the absence of a visible ownership check is still meaningful:

- If `req.params.id` is a key ID and the service only updates by ID, that is the classic failure mode.
- If the service scopes by `user.workspaceId`, good — but that is an assumption, not shown.

So the correct conclusion is: **potential IDOR, not proven exploitable from the excerpt**.

#### 2) `getAllApiKeys()`
Your observation about `activeOrganizationId` is the key point. If the endpoint only ever uses the authenticated user’s active organization, then the claim “no verification of user-organization relationship” is weaker than it sounds.

However, there is still a possible issue if:

- `activeOrganizationId` is mutable by client-controlled state,
- organization switching is not revalidated server-side,
- or the function can be reached in a context where `user` is not properly bound.

Again, not proven here, but not fully cleared either.

### On “critical”
I agree that **critical** is not supportable from the snippets alone.

To justify critical, you’d need evidence of one of the following:

- cross-tenant read/write of sensitive secrets,
- bulk deletion or modification of org-wide credentials,
- privilege escalation via API key permissions,
- or a chain from key enumeration to service compromise.

The excerpts do not establish any of that.

### Bottom line
The fair technical assessment is:

- **The report indicates a possible IDOR/tenant isolation flaw.**
- **The provided snippets do not prove an exploit chain.**
- **The “critical” label is not substantiated without service-layer and routing evidence.**

So I would not dismiss the finding outright, but I would also not accept the current severity claim. The right next step is exactly what you said: inspect `services/apikey/index.ts`, routing, and tenant-scoping middleware.

---

**Verdict**

**Verdict: NEEDS_VALIDATION**

1. **Defender’s strongest point:** “I cannot prove a full cross-tenant exploit chain… service-layer behavior and route/middleware context matter.”  
2. **Attacker’s strongest point:** “The snippets alone do **not** show the actual authorization boundary in the service layer.”  
3. The excerpt shows a classic risk pattern (`updateApiKey(user, req.params.id, ...)`) but no proof that the service fails to re-check ownership.  
4. The “activeOrganizationId” path is especially uncertain because it may be server-bound rather than attacker-controlled.  
5. **Run these checks:** inspect `services/apikey/index.ts` for tenant/owner checks on update/list/delete, and verify whether `activeOrganizationId` / `workspaceId` can be influenced or switched by the client.
