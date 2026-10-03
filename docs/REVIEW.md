# Zero-Context Guard — Self-Review

Reviewer: IBM Bob (fresh-eyes pass)  
Date: 2025-07-30  
Branch: `zero-context-guard`  
Commit: `8c485a9d`

This review does not edit code. It records what is true, what is exaggerated, and what
is missing, so those facts can drive the next iteration.

---

## 1. Finding Status Table (F-01 – F-10)

| ID   | Status                               | Mechanism                                                                                                                                                                                                                                                                                                                                                                                                                                     | Evidence (file : line)                                                                                                                                                                                                                                 |
| ---- | ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| F-01 | **Closed**                           | `disableE2B: hasBindings` forces NodeVM; E2B branch never reached for tools with secret bindings                                                                                                                                                                                                                                                                                                                                              | `utils.ts:1647` `const shouldUseE2BSandbox = useSandbox && !disableE2B && process.env.E2B_APIKEY`; `core.ts:146-150` `executeJavaScriptCode(code, sandbox, { disableE2B: hasBindings })`                                                               |
| F-02 | **Closed (conditional)**             | When `hasBindings`, `createCodeExecutionSandbox` injects `$secureRequest` and skips the `$vars` assignment; sandbox receives no secret strings                                                                                                                                                                                                                                                                                                | `utils.ts:1885-1891`: `if (secureRequestHelper) { sandbox['$secureRequest'] = … } else { sandbox['$vars'] = prepareSandboxVars(variables) }`                                                                                                           |
| F-02 | **NOT closed for no-bindings tools** | Tools with no `secretBindings` still receive full `$vars`; return statement `return JSON.stringify($vars)` still works                                                                                                                                                                                                                                                                                                                        | Same code, `else` branch. This is the documented backward-compat path.                                                                                                                                                                                 |
| F-03 | **Closed (globally)**                | `BLOCKED_ENV_KEY_PATTERNS` (14 patterns) skips matching runtime vars in `prepareSandboxVars`; applies to all node types                                                                                                                                                                                                                                                                                                                       | `utils.ts:1023-1038` (patterns); `utils.ts:1047-1057` (skip logic)                                                                                                                                                                                     |
| F-04 | **Closed for binding-enabled tools** | `redact(result, resolvedSecretValues)` called at `_call()` return. `resolvedSecretValues` is populated by the `onSecretResolved` callback in `makeSecureRequestHelper` — each credential value resolved by `$secureRequest` is appended before execution returns. Static patterns always fire; custom secrets also caught. For legacy tools (no bindings): `resolvedSecretValues` is `[]`, static patterns only.                              | `core.ts:135-140`; `guardRequest.ts:165-177`; commit `5242be3c`                                                                                                                                                                                        |
| F-05 | **Closed**                           | E2B disabled for tools with bindings (F-01 mechanism); for tools without bindings, `$secureRequest` is not injected and the issue was pre-existing / out of scope                                                                                                                                                                                                                                                                             | `core.ts:148-150`; `utils.ts:1647`                                                                                                                                                                                                                     |
| F-06 | **Closed for binding-enabled tools** | Same fix as F-04: `resolvedSecretValues` is populated by `onSecretResolved` callback; `redact(error, resolvedSecretValues)` in catch block catches custom secrets as well as static patterns. For legacy tools (no bindings): static patterns only.                                                                                                                                                                                           | `core.ts:153`; `guardRequest.ts:165-177`; commit `5242be3c`                                                                                                                                                                                            |
| F-07 | **Partial — denylist only**          | `BLOCKED_ENV_KEY_PATTERNS` blocks the worst-case keys from `prepareSandboxVars` globally; `$vars` is still present in LLMNode, Agent, ConditionAgent, Condition, ToolNode sandboxes for all other variable names                                                                                                                                                                                                                              | `utils.ts:1047-1057`. Full `$vars` removal from these nodes is deferred.                                                                                                                                                                               |
| F-08 | **Closed (static patterns only)**    | `redact(run.outputs?.output?.trim() ?? '', [])` and `redact(safeError, [])` in `ConsoleCallbackHandler.onToolEnd/onToolError`                                                                                                                                                                                                                                                                                                                 | `handler.ts:317`, `handler.ts:325`                                                                                                                                                                                                                     |
| F-09 | **Partial — denylist only**          | Same as F-07: worst-case names blocked globally; `$vars` still present in ChatPromptTemplate sandbox for non-blocked names                                                                                                                                                                                                                                                                                                                    | `utils.ts:1047-1057`. Removal from ChatPromptTemplate deferred.                                                                                                                                                                                        |
| F-10 | **NOT closed**                       | `CustomStreamingHandler.handleToolEnd` applies `redact()` to the SSE stream it controls. The 7 third-party tracing handlers (LangSmith, LangFuse, Lunary, Arize, Phoenix, LangWatch, Opik) are **separate** `BaseCallbackHandler` instances in the LangChain callback chain; they receive the raw `Run` object directly from LangChain's tracer infrastructure — not from `CustomStreamingHandler`. No per-provider redaction wrapper exists. | `handler.ts:516-690` (`additionalCallbacks`); `handler.ts:2006-2021` (`handleToolEnd`, SSE only). The comment in `handleToolEnd` at `handler.ts:2011` says "F-04, F-10" but this is inaccurate: it only covers the SSE path, not the tracer callbacks. |

### Summary (updated after Steps 1 & 2)

| Status                                              | Count | Findings                                 |
| --------------------------------------------------- | ----- | ---------------------------------------- |
| Fully closed (global)                               | 2     | F-03, + redirect cross-host header (new) |
| Closed for binding-enabled tools                    | 5     | F-01, F-02, F-04, F-05, F-06             |
| Closed (static patterns only)                       | 1     | F-08                                     |
| Partial (denylist only, deferred)                   | 2     | F-07, F-09                               |
| Partial (static patterns on SSE; tracers untouched) | 1     | F-10                                     |
| Not closed                                          | 0     | —                                        |

**README.md and HACKATHON_README.md have been corrected in Step 3 to reflect these counts accurately.**

---

## 2. Redirect Cross-Host Header Strip

### The question

> Is `Authorization` or any custom header kept when a redirect changes host in
> `secureAxiosRequest` / `secureFetch`?

### The code

**`secureAxiosRequest` (`httpSecurity.ts:167-221`):**

```typescript
// Line 167-173: currentConfig starts as spread of the original config
let currentConfig: AxiosRequestConfig = {
    ...config,       // ← Authorization header carried in here
    maxRedirects: 0,
    ...
}

while (redirects <= maxRedirects) {
    // Line 179-187: each loop iteration builds a NEW currentConfig by spreading the OLD one
    currentConfig = {
        ...currentConfig,   // ← Authorization header PRESERVED across every hop
        url: currentUrl,
        headers: {
            ...currentConfig.headers,    // ← Authorization preserved
            Host: target.hostname        // only Host is updated
        }
    }
    // ...
    // Line 208: new URL is resolved (SSRF deny-list checked) but headers not scrubbed
    currentUrl = new URL(location, currentUrl).toString()
    // No Authorization header removal on host change
}
```

**`secureFetch` (`httpSecurity.ts:241-286`):**

```typescript
// Line 243: currentInit starts as spread of the original init
let currentInit = { ...init, redirect: 'manual' as const }

while (redirectCount <= maxRedirects) {
    const response = await fetch(currentUrl, { ...currentInit, agent: () => agent })
    // ...
    // Line 277-280: only method and body are modified on 301/302/303
    currentInit = {
        ...currentInit, // ← Authorization header PRESERVED
        method: 'GET',
        body: undefined
    }
    // No Authorization header removal on host change
}
```

### Finding

**`Authorization` (and all other custom headers) are carried through every redirect hop
regardless of whether the destination hostname changes.** The new hostname is validated
against the SSRF deny list, but if the redirect goes to a different allowed domain (e.g.
from `api.github.com` → `uploads.github.com`), the `Authorization: Bearer <token>` header
is sent to the new host.

For the Zero-Context Guard this has limited impact because:

1. `allowedHosts` is checked **only on the initial URL** in `guardRequest.ts:149-152`.
   A redirect to a different hostname is **not** re-checked against `allowedHosts`.
2. The SSRF deny list blocks private IP redirects, but not redirects to other public hosts.

This is a **pre-existing vulnerability in `httpSecurity.ts`** (the SSRF code predates this
project), but the Guard's own `allowedHosts` check does not re-validate redirect
destinations, creating a credential-forwarding gap.

### Test coverage

There is **no test** in `httpSecurity.test.ts` covering cross-host redirect behaviour.
`httpSecurity.test.ts` tests only `isDeniedIP` — it contains zero calls to
`secureAxiosRequest` or `secureFetch`. The `guardRequest.test.ts` mocks
`secureAxiosRequest` entirely, so redirect behaviour is not exercised.

---

## 3. F-10: What Is NOT Covered

The README tracing note (lines 117–123) is broadly correct but understates the gap.

### What `handleToolEnd` actually covers

`CustomStreamingHandler.handleToolEnd` (`handler.ts:2006-2021`) applies `redact()` to the
string it emits over the SSE stream to the **browser**. That is all it covers.

### What the tracing providers receive

The 7 tracing providers configured in `additionalCallbacks` (`handler.ts:516-690`) are
`BaseCallbackHandler` instances registered on the LangChain `CallbackManager`. LangChain
calls their `handleToolEnd` / `handleChainEnd` / `handleLLMEnd` methods directly with the
raw `Run` object. These calls happen **in parallel** with `CustomStreamingHandler`'s
callbacks — not downstream from it. There is no interception point in this codebase that
modifies the `Run` objects before they reach the tracing providers.

**Concretely uncovered:**

-   `LangChainTracer` (`handler.ts:550`) → sends full tool output to LangSmith
-   `CallbackHandler` (`handler.ts:572`) → sends full tool output to LangFuse
-   `ExtendedLunaryHandler` (`handler.ts:589`) → sends full tool output to Lunary
-   Arize, Phoenix, LangWatch, Opik handlers (`handler.ts:600-690`) → same

The `_call()` redaction (`core.ts:162`) does reduce exposure: after `_call()` returns, the
`result` reaching `callbackManager_.handleToolEnd()` at `core.ts:109` is already
redacted for static token patterns. However, `resolvedSecrets` is `[]` at that point, so
any custom secret value that does not match sk-, ghp\_, Bearer, xoxb-, or AIza will reach
all 7 tracing providers verbatim.

### What README.md must say honestly

The current README (lines 117–123) already acknowledges this gap ("their inputs are
therefore protected only by the static-pattern redaction that already happened in
`_call()`"). **This is accurate.** However, the `handleToolEnd` comment in the Improvements
table at line 149 says _"Receive only post-`handleToolEnd` redacted string"_ for F-10 —
that is **inaccurate**. They receive the `result` from `_call()`, which has static-pattern
redaction but not resolved-secret redaction.

---

## 4. README Claims Audit

The following claims in `README.md` and the 100-word description in
`docs/HACKATHON_README.md` are not 100% backed by code or tests:

### README.md

| Line    | Claim                                                                      | Verdict                                                                                                                                                                                            |
| ------- | -------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 13      | "8 OWASP LLM02 findings fully closed"                                      | **Inaccurate.** Only 3 are fully closed (F-01, F-03, F-05). F-02 is conditional, 4 are partial, 1 (F-10) is not closed. The most generous defensible count is "8 addressed (3 closed, 5 partial)". |
| 149     | Tracing providers "Receive only post-`handleToolEnd` redacted string"      | **Inaccurate.** Tracers receive the `Run` object from LangChain's own callback infrastructure. `CustomStreamingHandler.handleToolEnd` covers only the SSE path.                                    |
| 152–155 | F-07 "Worst-case names blocked by denylist" described as partial mitigated | Accurate — this is the denylist-only partial.                                                                                                                                                      |
| 204     | "33 new guard tests"                                                       | **Verified.** guardRedact.test.ts has 20 tests, guardRequest.test.ts has 13 tests. Total = 33. ✓                                                                                                   |
| 257     | "Expected: Test Suites: 22 passed Tests: 943 passed Time: ~110 s"          | **Verified** against BASELINE.md post-Guard snapshot. ✓                                                                                                                                            |
| 94      | "14 patterns total" for BLOCKED_ENV_KEY_PATTERNS                           | **Verified** — 14 patterns at `utils.ts:1023-1038`. ✓                                                                                                                                              |
| 53      | "Layer 1 — Secret Isolation (F-01, F-02, F-03, F-05)"                      | **Partially accurate.** F-02 is only closed when `secretBindings` is declared; it is explicit in line 88 but the heading implies all 4 are unconditional.                                          |

### HACKATHON_README.md (100-word description, lines 3–13)

| Claim                                                                                                                               | Verdict                                                                                                                                                                                                                                                                                                                        |
| ----------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| "A redaction layer strips token patterns from **every** tool output, error, log line, and trace event before it leaves the process" | **Inaccurate in two ways:** (a) "every tool output" — applies only to Custom Tool outputs via the guard, not all tool types at the `_call()` level; `handleToolEnd`/`handleToolError` in handler.ts applies to all streaming tools but only covers the SSE path. (b) "trace event" — tracers (LangSmith etc.) are not covered. |
| "10 confirmed OWASP LLM02 findings closed"                                                                                          | **Inaccurate.** 10 were _found_. The number closed is 3 (fully) + 1 (conditional) + partial mitigations for the rest.                                                                                                                                                                                                          |

### HACKATHON_README.md (Improvements table, row 8, line 137)

| Claim                                                                 | Verdict                                                                                                                                  |
| --------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| Tracing providers "Receive only post-`handleToolEnd` redacted string" | **Inaccurate.** See §3 above. Tracers receive the `Run` object from LangChain directly, not from `CustomStreamingHandler.handleToolEnd`. |

---

## 5. Tracked Secret Files

```
$ git ls-files | grep -E '\.(env|key|sqlite|db)$'
(no output)

$ git ls-files | grep -E '(encryption|\.key$|\.pem$)'
packages/server/src/enterprise/utils/encryption.util.ts
```

**No `.env` files, `encryption.key`, `.sqlite` files, or `.pem` files are tracked.**
`encryption.util.ts` is a TypeScript source file (utility code), not a key file.
The check is clean.

---

## 6. Issues Fixed After Review

| #   | Issue                                                                        | Fix applied                                                                      | Commit     |
| --- | ---------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | ---------- |
| 1   | README.md / HACKATHON_README.md overclaim ("8 fully closed", "10 closed")    | Rewritten with accurate counts; Known Limitations section added                  | Step 3     |
| 2   | HACKATHON_README.md table row 8 (tracers "receive only redacted string")     | Row corrected to "static patterns only; tracers not mitigated"                   | Step 3     |
| 3   | README.md table row 10 — same tracer overclaim                               | Corrected to "⚠️ Not closed"                                                     | Step 3     |
| 4   | `handler.ts:2011` comment says "F-04, F-10"                                  | Replaced with accurate comment: SSE only, F-10 NOT closed by this line           | Step 3     |
| 5   | `guardRequest.ts`: `allowedHosts` checked only on initial URL                | Redirect loop moved into `$secureRequest`; every hop re-checks `allowedHosts`    | `4cff856f` |
| 6   | No test for cross-host redirect header stripping                             | 9 tests added to `httpSecurity.test.ts`; 3 tests added to `guardRequest.test.ts` | `4cff856f` |
| 7   | F-04/F-06: `redact()` called with `[]` — custom secrets missed               | `onSecretResolved` callback populates `resolvedSecretValues`; real values passed | `5242be3c` |
| 8   | No test proving custom secret (non-static-pattern) is redacted               | 10 tests added (core.test.ts × 6, guardRequest.test.ts × 4)                      | `5242be3c` |
| 9   | 100-word description claimed "trace events" covered and "10 findings closed" | Rewritten to be accurate; verified at exactly 100 words                          | Step 3     |

---

_This document was produced by IBM Bob. All findings cite the exact file and line._
