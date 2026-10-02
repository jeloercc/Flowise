# Zero-Context Guard — Technical Design

Branch: `zero-context-guard`  
Author: IBM Bob (Plan mode)  
Date: 2025-07-30  
Resolves: AUDIT.md findings F-01 through F-10

---

## 1. Overview

The Zero-Context Guard prevents raw secret values from ever reaching the LLM,
sandbox code, tracing services, or outbound HTTP destinations.

The approach has two orthogonal halves:

| Half                     | What it does                                                                                                                                                                | Findings addressed                 |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| **Secret isolation**     | Removes `$vars` from sandbox scope; replaces it with `$secureRequest(credentialId, url, options)`, a server-side helper that resolves credentials and enforces an allowlist | F-01, F-02, F-03, F-05             |
| **Redaction middleware** | A pure function `redact(text, secrets)` that scrubs known secret values and pattern tokens from any string before it leaves the server                                      | F-04, F-06, F-07, F-08, F-09, F-10 |

Backward compatibility is guaranteed: a Custom Tool that declares no secret
bindings receives the same sandbox it receives today.

---

## 2. Guiding invariants

1. **Zero knowledge in the sandbox.** At the moment `executeJavaScriptCode`
   is called, no resolved secret string exists in the `sandbox` object or in
   any string that will be serialized into the E2B script.

2. **One resolution point.** `getCredentialData` is called exactly once per
   `$secureRequest` invocation, inside the Guard, in the Node.js host process.

3. **Allowlist-only outbound.** The Guard enforces `allowedHosts` on the initial
   URL and on every redirect hop (reusing `secureAxiosRequest`).

4. **Redact-before-emit.** Every string that leaves the Node.js process boundary
   (SSE stream, logger, tracing callback) passes through `redact()` first.

5. **No new runtime dependencies.** All new code uses packages already present
   in `packages/components`.

---

## 3. New files

| File                                           | Purpose                                                                          |
| ---------------------------------------------- | -------------------------------------------------------------------------------- |
| `packages/components/src/guardRedact.ts`       | Pure `redact(text, secrets)` function and pattern constants                      |
| `packages/components/src/guardRequest.ts`      | `makeSecureRequestHelper(options)` factory — builds the `$secureRequest` closure |
| `packages/components/src/guardRequest.test.ts` | Unit tests for the request helper                                                |
| `packages/components/src/guardRedact.test.ts`  | Unit tests for the redaction function                                            |

---

## 4. Modified files

| File                                                       | Change summary                                                                                                                                                                                                                                                                                                                                                                                                 |
| ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `packages/components/src/utils.ts`                         | (a) `prepareSandboxVars` — add runtime-variable key denylist; (b) `createCodeExecutionSandbox` — accept optional `secureRequestHelper` param and add it as `$secureRequest`; (c) E2B branch of `executeJavaScriptCode` — strip `$vars` from `variableDeclarations` when the tool has secret bindings and replace with a server-side proxy call; (d) NodeVM branch — add `$secureRequest` to the sandbox object |
| `packages/components/nodes/tools/CustomTool/core.ts`       | Add `private secretBindings: SecretBinding[]` field; add `setSecretBindings()`; call `makeSecureRequestHelper` in `_call()` and pass the helper to `createCodeExecutionSandbox`; wrap `result` in `redact()` before returning                                                                                                                                                                                  |
| `packages/components/nodes/tools/CustomTool/CustomTool.ts` | Parse `secretBindings` from `nodeData.inputs` and call `dynamicStructuredTool.setSecretBindings(bindings)`                                                                                                                                                                                                                                                                                                     |
| `packages/components/src/handler.ts`                       | (a) `CustomStreamingHandler.handleToolEnd` — apply `redact()` to `toolOutput`; (b) `CustomStreamingHandler.handleToolError` — apply `redact()` to `error.message`; (c) `ConsoleCallbackHandler.onToolEnd` / `onToolError` — apply `redact()` to logged strings                                                                                                                                                 |

---

## 5. New data type: `SecretBinding`

```
SecretBinding {
  name:         string        // Identifier visible to sandbox code  e.g. "github"
  credentialId: string        // UUID in the Credential table — never seen by the LLM
  allowedHosts: string[]      // Exact hostnames the Guard will accept, e.g. ["api.github.com"]
}
```

Declared by an admin at tool-design time.  
The LLM only knows the `name`; `credentialId` and `allowedHosts` are backend-only.

---

## 6. Step-by-step data flow

```
Admin configures tool
  └─ nodeData.inputs.secretBindings = [{ name, credentialId, allowedHosts }]

───── INIT TIME (CustomTool.ts:init) ─────────────────────────────────────────
  1. getVars(...)            → IVariable[]      (workspace static/runtime vars)
  2. setVariables(vars)      stored on tool instance
  3. setSecretBindings(bindings)  stored on tool instance
  4. tool returned to agent executor

───── CALL TIME (_call in core.ts) ───────────────────────────────────────────
  5. Build additionalSandbox from tool arg map ($arg1, $arg2, …)
  6. Merge flow object
  7. makeSecureRequestHelper(bindings, options)
       For each name in bindings:
         Returns async function $secureRequest(name, url, opts):
           a. Look up binding by name  (credentialId + allowedHosts)
           b. getCredentialData(credentialId, options)  → raw key  [NEVER enters sandbox]
           c. checkAllowedHost(url, allowedHosts)       → throws if denied
           d. secureAxiosRequest({ ...opts, url, headers: { Authorization: injected } })
                ↳ enforces SSRF deny list on every redirect hop
           e. Return clean response body (string)
  8. createCodeExecutionSandbox(
         '',
         variables,          ← IVariable[] still passed for non-secret vars
         flow,
         { ...additionalSandbox, $secureRequest: helper }
     )
     CHANGE: $vars is NOT added to sandbox when secretBindings.length > 0
             (or can be left as a thin object with only static/non-sensitive vars)
  9. executeJavaScriptCode(code, sandbox)
       NodeVM path:  sandbox.$secureRequest is available; $vars absent or stripped
       E2B path:     $vars serialization omitted; $secureRequest cannot be injected
                     directly (remote process) — see §8 for E2B strategy

─────  RESULT / ERROR ─────────────────────────────────────────────────────────
 10. result = raw string returned from executeJavaScriptCode
 11. resolvedSecrets = bindings.map(b => resolvedValueCache[b.credentialId])
 12. redact(result, resolvedSecrets)  → sanitized string
 13. (on error) redact(e.message, resolvedSecrets)  → rethrow sanitized error

─────  CALLBACKS ────────────────────────────────────────────────────────────────
 14. handleToolEnd(sanitized)   → SSE stream
 15. ConsoleCallbackHandler.onToolEnd  → logger.verbose(sanitized)
 16. Tracing providers receive sanitized string (through LangChain callback chain)
```

---

## 7. `guardRedact.ts` — specification

### 7.1 Exported function

```
redact(text: string, resolvedSecrets: string[]): string
```

Replaces all occurrences of each string in `resolvedSecrets` with
`[REDACTED]`, then applies each pattern in `REDACT_PATTERNS`.

### 7.2 Static patterns (`REDACT_PATTERNS`)

| Pattern                     | What it catches        | Replacement              |
| --------------------------- | ---------------------- | ------------------------ |
| `/sk-[A-Za-z0-9]{10,}/g`    | OpenAI-style keys      | `[REDACTED:sk-token]`    |
| `/ghp_[A-Za-z0-9]{10,}/g`   | GitHub personal tokens | `[REDACTED:gh-token]`    |
| `/Bearer\s+[^\s"',]{8,}/g`  | Bearer auth headers    | `[REDACTED:Bearer]`      |
| `/xoxb-[0-9A-Za-z-]{10,}/g` | Slack bot tokens       | `[REDACTED:slack-token]` |
| `/AIza[0-9A-Za-z_-]{35}/g`  | Google API keys        | `[REDACTED:google-key]`  |

### 7.3 Constraints

-   `redact` must be a **pure function** — no I/O, no side effects.
-   Empty `resolvedSecrets` array must be a no-op cost-free path.
-   When `text` is `undefined` or `null`, return the input unchanged.
-   Secret values shorter than 8 characters are skipped (avoids false positives
    from short variable values like `"true"`, `"1"`, etc.).

---

## 8. E2B sandbox strategy (F-01, F-05)

The E2B sandbox runs code in a remote VM operated by e2b.dev. It is not
possible to inject a server-side closure (`$secureRequest`) into it.

**Design decision:** When `secretBindings.length > 0` (i.e. the tool requires
secrets), the E2B path is **disabled** for that tool and the NodeVM path is
used instead, regardless of whether `E2B_APIKEY` is set.

Implementation: in `executeJavaScriptCode`, accept an optional
`options.disableE2B: boolean` flag. `createCodeExecutionSandbox` (or the call
site in `_call`) sets `disableE2B: true` when secret bindings are present.

This is the minimal change: it adds zero new dependencies and eliminates the
entire class of E2B secret serialisation problems for any tool that uses
`$secureRequest`.

For tools without secret bindings, E2B continues to work exactly as today.

---

## 9. `prepareSandboxVars` runtime-key denylist (F-03)

Add a constant `BLOCKED_ENV_KEY_PATTERNS` to `utils.ts`:

```
const BLOCKED_ENV_KEY_PATTERNS = [
  /SECRET/i, /KEY/i, /TOKEN/i, /PASSWORD/i, /PASSWD/i,
  /CREDENTIAL/i, /APIKEY/i, /API_KEY/i, /ACCESS_KEY/i,
  /PRIVATE/i, /ENCRYPTION/i, /JWT/i, /CERT/i, /FLOWISE_/i
]
```

In `prepareSandboxVars`, skip any `IVariable` with `type === 'runtime'` whose
`name` matches any pattern above. Log a `console.warn` (not `error`) with the
variable name (not the value) so admins can diagnose misconfigurations.

---

## 10. F-07 / F-09 — non-CustomTool code nodes

LLMNode, Agent, Condition, ConditionAgent, ToolNode, ChatPromptTemplate and
others also call `createCodeExecutionSandbox` with `$vars` in scope.

**Design decision for this iteration:** those nodes are out of scope for
code changes in this PR. Instead, the design adds:

1. The runtime-key denylist (§9 above) globally affects `prepareSandboxVars`
   and therefore already closes the worst cases in those nodes for free.
2. A **documentation note** is added to `AGENTS.md` / in-code JSDoc noting
   that condition and prompt-template code must not echo `$vars`.

Full mitigation for those nodes (replacing `$vars` with a capabilities model)
is a separate, larger change that can follow once this PR is merged.

---

## 11. Test plan

All tests must pass by running:

```
pnpm --filter flowise-components test
```

No new runtime dependencies. Existing 910 tests must remain green.

### 11.1 `src/guardRedact.test.ts`

| Test name                                                      | What it verifies   |
| -------------------------------------------------------------- | ------------------ |
| `redact: returns text unchanged when resolvedSecrets is empty` | No-op fast path    |
| `redact: replaces a single resolved secret`                    | Basic substitution |
| `redact: replaces multiple resolved secrets in one pass`       | Multi-value        |
| `redact: replaces resolved secret that appears more than once` | Global replace     |
| `redact: skips secrets shorter than 8 chars`                   | Short-value guard  |
| `redact: applies sk- pattern`                                  | Static regex       |
| `redact: applies ghp_ pattern`                                 | Static regex       |
| `redact: applies Bearer pattern`                               | Static regex       |
| `redact: does not mutate its inputs`                           | Purity check       |
| `redact: handles null/undefined text gracefully`               | Edge case          |
| `redact: handles empty string text`                            | Edge case          |

### 11.2 `src/guardRequest.test.ts`

| Test name                                                          | What it verifies      |
| ------------------------------------------------------------------ | --------------------- |
| `$secureRequest: resolves credential and makes GET request`        | Happy path            |
| `$secureRequest: injects Authorization header from credential`     | Auth injection        |
| `$secureRequest: throws when url host not in allowedHosts`         | Allowlist enforcement |
| `$secureRequest: throws when allowedHosts is empty`                | Empty allowlist guard |
| `$secureRequest: throws when binding name not found`               | Unknown name guard    |
| `$secureRequest: follows redirects only to allowed hosts`          | Redirect enforcement  |
| `$secureRequest: does not expose credentialId in error message`    | Non-disclosure        |
| `$secureRequest: does not expose resolved secret in error message` | Non-disclosure        |

### 11.3 `src/utils.test.ts` additions

| Test name                                                                           | What it verifies |
| ----------------------------------------------------------------------------------- | ---------------- |
| `prepareSandboxVars: skips runtime var whose name matches BLOCKED_ENV_KEY_PATTERNS` | F-03 denylist    |
| `prepareSandboxVars: includes runtime var with safe name`                           | Non-regression   |
| `createCodeExecutionSandbox: includes $secureRequest when helper provided`          | Injection wiring |
| `createCodeExecutionSandbox: does not include $vars when disableVars flag set`      | F-01/F-02        |

### 11.4 `src/handler.test.ts` additions

| Test name                                                      | What it verifies |
| -------------------------------------------------------------- | ---------------- |
| `handleToolEnd: redacts known secret pattern before streaming` | F-04             |
| `handleToolEnd: passes through clean output unchanged`         | Non-regression   |
| `handleToolError: redacts known pattern in error.message`      | F-06             |

### 11.5 `nodes/tools/CustomTool/core.test.ts` (new)

| Test name                                                                     | What it verifies             |
| ----------------------------------------------------------------------------- | ---------------------------- |
| `DynamicStructuredTool: call() without secretBindings works as before`        | Non-regression (F-05 compat) |
| `DynamicStructuredTool: setSecretBindings stores bindings`                    | Binding storage              |
| `DynamicStructuredTool: _call() injects $secureRequest when bindings present` | Guard wiring                 |
| `DynamicStructuredTool: result is redacted before returning`                  | F-02 at exit point           |
| `DynamicStructuredTool: error message is redacted before re-throw`            | F-06                         |

---

## 12. Backward compatibility rules

| Scenario                                            | Behaviour after this change                                                                        |
| --------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Custom Tool with no `secretBindings` field          | Unchanged. `$vars` is still in scope. `$secureRequest` is not injected. E2B is used if configured. |
| Custom Tool with `secretBindings: []` (empty array) | Treated as "no bindings" — same as above.                                                          |
| Custom Tool with one or more secret bindings        | `$vars` removed from sandbox. `$secureRequest` injected. E2B disabled for this tool.               |
| Any node other than CustomTool                      | No change at all.                                                                                  |

This guarantees the existing 910 tests continue to pass without modification.

---

## 13. Sub-task breakdown for implementation

Implementation should proceed in this order, one subtask per commit:

| #   | Subtask                                                                                                                                 | Mitigates                |
| --- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------ |
| 1   | Create `src/guardRedact.ts` + `src/guardRedact.test.ts`                                                                                 | F-04, F-06, F-08 partial |
| 2   | Create `src/guardRequest.ts` + `src/guardRequest.test.ts`                                                                               | F-05                     |
| 3   | Modify `prepareSandboxVars` in `utils.ts` (runtime-key denylist)                                                                        | F-03                     |
| 4   | Modify `createCodeExecutionSandbox` and `executeJavaScriptCode` in `utils.ts` (disableVars + disableE2B flags, inject `$secureRequest`) | F-01, F-02               |
| 5   | Modify `core.ts` — add `secretBindings`, `setSecretBindings`, wire helper + redact output/errors                                        | F-01, F-02, F-05, F-06   |
| 6   | Modify `CustomTool.ts` — parse and attach `secretBindings`                                                                              | (wiring)                 |
| 7   | Modify `handler.ts` — redact in `handleToolEnd`, `handleToolError`, `onToolEnd`, `onToolError`                                          | F-04, F-06, F-08, F-10   |
| 8   | Add tests for all modified files (steps 3–7)                                                                                            | Test plan §11            |

Each subtask produces a single, reviewable, passing commit.

---

## 14. Audit traceability

| Finding | Sub-task(s) | Mechanism                                                                 |
| ------- | ----------- | ------------------------------------------------------------------------- |
| F-01    | 4           | E2B disabled when bindings present; `$vars` not serialised                |
| F-02    | 4, 5        | `$vars` absent from NodeVM sandbox when bindings present                  |
| F-03    | 3           | `BLOCKED_ENV_KEY_PATTERNS` in `prepareSandboxVars`                        |
| F-04    | 7           | `redact()` in `handleToolEnd`                                             |
| F-05    | 2, 5        | `$secureRequest` enforces `allowedHosts` + SSRF deny list                 |
| F-06    | 5, 7        | `redact()` on caught errors before re-throw and before SSE emit           |
| F-07    | 3 (partial) | Denylist removes worst-case runtime vars; full fix deferred               |
| F-08    | 7           | `redact()` before `logger.verbose` in `onToolEnd`/`onToolError`           |
| F-09    | 3 (partial) | Denylist; full ChatPromptTemplate fix deferred                            |
| F-10    | 7           | Tracing callbacks receive output after `handleToolEnd` applies `redact()` |
