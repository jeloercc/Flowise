# Zero-Context Guard for Flowise

## IBM Bob Hackathon 2025 — Theme 2: Modernize What Matters

> Flowise is end-of-life, and its Custom Tools receive every workspace variable,
> including API keys, as plain text; a prompt injection can exfiltrate them. Using
> IBM Bob we audited it (10 findings) and built a Zero-Context Guard: tools call
> `$secureRequest` with a secret name, the backend injects the credential only for
> allow-listed hosts, and real secret values are redacted from outputs and errors.
> Cross-origin redirects strip credentials; DNS rebinding is mitigated. 71 new tests,
> 981 passing, no new dependencies. Limits are documented.

---

## The Problem: Legacy Agent Tools Are a Secret-Exfiltration Vector

Flowise (Apache 2.0, code-frozen 2026-07-29, EOL 2026-08-31) powers LLM agents that call
**Custom Tools** — user-written JavaScript executed inside a Node.js VM. Before this
project, every Custom Tool ran with a `$vars` object in scope containing every workspace
variable, including **runtime variables resolved from `process.env`**. The LLM chooses
which tool to call and what arguments to pass; prompt injection via tool arguments is
a realistic, low-effort attack.

This creates a confirmed path to [OWASP LLM02:2025 — Sensitive Information Disclosure][llm02]:

| Attack                   | One-line repro                                                                                      | Audit finding |
| ------------------------ | --------------------------------------------------------------------------------------------------- | ------------- |
| **Direct exfiltration**  | Tool code: `return JSON.stringify($vars)` → LLM receives all secrets as a ToolMessage               | F-02          |
| **E2B remote leak**      | `$vars` serialised as `const $vars = {...}` and sent to a remote VM at e2b.dev                      | F-01          |
| **SSRF bypass via E2B**  | NodeVM SSRF deny list not applied in E2B; sandbox calls native `fetch` to any host                  | F-05          |
| **Error channel leak**   | `JSON.parse($vars.SECRET)` throws; raw value emitted verbatim over SSE                              | F-06          |
| **Runtime env leak**     | Variable named `FLOWISE_SECRETKEY_OVERWRITE` with `type=runtime` puts the master key in `$vars`     | F-03          |
| **Tracing exfiltration** | LangSmith / LangFuse / Lunary / Arize receive unredacted Custom Tool output via LangChain callbacks | F-10          |

An IBM Bob Secret Leak Audit ([`docs/AUDIT.md`](docs/AUDIT.md)) traced **10 confirmed
findings** across 4 sinks, all with file:line citations and minimal reproductions. See that
document for the full table.

[llm02]: https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/

---

## The Solution: Zero-Context Guard

The guard has two independent layers. Neither introduces new runtime dependencies.
Both layers apply **only to the Custom Tool node** (`DynamicStructuredTool`); other
node types are not modified in this iteration.

### Layer 1 — Secret Isolation (F-01, F-02, F-03, F-05)

**`$vars` is removed from the sandbox scope when a tool declares secret bindings.**
In its place, an admin-declared `SecretBinding` array maps a short name to a
`credentialId` and an `allowedHosts` list:

```
SecretBinding {
  name:         "github"               // only identifier the LLM or sandbox code sees
  credentialId: "cred-uuid-…"          // stays in the host process, never in sandbox
  allowedHosts: ["api.github.com"]     // exact-hostname check, no substring match
}
```

**Call-time data flow:**

```
LLM calls tool
  → _call() in core.ts
      → makeSecureRequestHelper(bindings, options)   [guardRequest.ts]
          → returns $secureRequest closure (a function — never serialised into sandbox)
      → createCodeExecutionSandbox(..., secureRequestHelper)
          → sandbox.$secureRequest = closure
          → sandbox.$vars = *** ABSENT ***
      → executeJavaScriptCode(code, sandbox, { disableE2B: true })

Sandbox code calls:  $secureRequest('github', 'https://api.github.com/user', {})
  → closure executes IN THE HOST PROCESS:
      1. getCredentialData('cred-uuid-…')   → raw token (never touches sandbox)
      2. hostname check: 'api.github.com' ∈ allowedHosts ✓
      3. secureAxiosSingleHop({url, headers: {Authorization: 'Bearer <token>'}})
           ↳ DNS resolved once → IP validated against SSRF deny list → IP pinned
             into http.Agent (eliminating DNS-rebinding TOCTOU window)
           ↳ allowedHosts re-checked on every redirect hop  [guardRequest.ts]
      4. returns clean response body string to sandbox
```

Tools **without** `secretBindings` are completely unchanged — `$vars` remains in scope,
E2B is used if configured, the sandbox behaves exactly as before.

**Runtime environment variable denylist (F-03):** `prepareSandboxVars` now skips any
`runtime`-type variable whose name matches patterns such as `SECRET`, `KEY`, `TOKEN`,
`PASSWORD`, `FLOWISE_`, `ENCRYPTION`, etc. (14 patterns total). This closes the worst-case
path globally for every node type that calls `prepareSandboxVars`, not just Custom Tools.

### Layer 2 — Redaction Middleware (F-04, F-06, F-08, F-10)

[`guardRedact.ts`](packages/components/src/guardRedact.ts) exports a pure `redact(text,
resolvedSecrets)` function applied at four boundaries within the Custom Tool execution
path:

| Applied at                                     | What it protects                                                                                             |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `DynamicStructuredTool._call()` return value   | Static token patterns + resolved credential values in Custom Tool output before it reaches LLM or SSE (F-04) |
| `DynamicStructuredTool._call()` catch block    | Static token patterns + resolved credential values in error messages before re-throw (F-06)                  |
| `CustomStreamingHandler.handleToolEnd()`       | SSE `agent_trace` stream for any tool type — static patterns only (F-04 partial)                             |
| `CustomStreamingHandler.handleToolError()`     | SSE error payload for any tool type — static patterns only (F-06 partial)                                    |
| `ConsoleCallbackHandler.onToolEnd/onToolError` | Verbose server logs at `DEBUG=true` for any tool type — static patterns only (F-08)                          |

> **Resolved-secret redaction:** When a tool declares `secretBindings`, each time
> `$secureRequest` resolves a credential it invokes an `onSecretResolved` callback in
> `_call()` that appends the plaintext value to `resolvedSecretValues[]`. After execution,
> `redact(result, resolvedSecretValues)` and `redact(error, resolvedSecretValues)` replace
> any matching substrings with `[REDACTED]`. This closes F-04 and F-06 for tools that use
> the Guard. For tools without `secretBindings` (legacy path), `resolvedSecretValues` is
> `[]` and only static regex patterns fire.

> **Tracing note (F-10, not yet closed):** `CustomStreamingHandler.handleToolEnd` covers
> the SSE stream only. Third-party tracing callbacks (LangSmith, LangFuse, Lunary, Arize,
> Phoenix, LangWatch, Opik) are registered as separate LangChain `BaseCallbackHandler`
> instances and receive the raw `Run` object from LangChain's own tracer infrastructure —
> **not** from `CustomStreamingHandler`. The `_call()` static-pattern redaction reduces
> exposure for known token formats, but a custom credential value that matches no static
> pattern will still reach all 7 providers. Per-provider redaction wrappers are not
> implemented in this iteration. See [Known Limitations](#known-limitations) below.

Static patterns caught without needing resolved secrets:

| Pattern                               | Catches                               |
| ------------------------------------- | ------------------------------------- |
| `sk-[A-Za-z0-9_-]{10,}`               | OpenAI API keys                       |
| `ghp_[A-Za-z0-9]{10,}`                | GitHub personal access tokens         |
| `Bearer\s+(?!\[REDACTED)[^\s"',]{8,}` | Any Bearer authorization header value |
| `xoxb-[0-9A-Za-z-]{10,}`              | Slack bot tokens                      |
| `AIza[0-9A-Za-z_-]{35}`               | Google API keys                       |

A negative lookahead on the Bearer pattern prevents double-redaction when an earlier pass
already replaced the token with `[REDACTED]`.

---

## Improvements Made

| #   | Area                                                       | Before                                                              | After                                                                                                                      | Finding    | Status                                |
| --- | ---------------------------------------------------------- | ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | ---------- | ------------------------------------- |
| 1   | Sandbox scope (Custom Tool)                                | `$vars` with all secrets in NodeVM scope                            | `$vars` absent when `secretBindings` declared; `$secureRequest` injected                                                   | F-02       | ✅ Closed (requires secretBindings)   |
| 2   | E2B remote VM                                              | Full `$vars` serialised and sent to e2b.dev                         | E2B disabled for tools with secret bindings                                                                                | F-01       | ✅ Closed (requires secretBindings)   |
| 3   | SSRF in E2B sandbox                                        | No deny-list; sandbox used native `fetch` freely                    | E2B blocked; only `secureAxiosSingleHop` path available for binding tools                                                  | F-05       | ✅ Closed (requires secretBindings)   |
| 4   | Runtime env vars in `$vars`                                | Any `process.env` key reachable via `runtime` variable              | 14-pattern denylist blocks `SECRET`, `KEY`, `TOKEN`, `FLOWISE_`, etc. globally                                             | F-03       | ✅ Closed (global)                    |
| 5   | Tool output to LLM (binding tools)                         | Raw output returned as ToolMessage                                  | `redact(result, resolvedSecretValues)` in `_call()` — both static patterns and resolved values                             | F-04       | ✅ Closed (requires secretBindings)   |
| 6   | Error messages (binding tools)                             | Execution error could embed raw secret values                       | `redact(error, resolvedSecretValues)` before re-throw — both static patterns and resolved values                           | F-06       | ✅ Closed (requires secretBindings)   |
| 7   | SSE `agent_trace` stream                                   | Raw output emitted verbatim                                         | `redact(output, [])` in `handleToolEnd` / `handleToolError` — static patterns only                                         | F-04, F-06 | ⚠️ Partial (static patterns only)     |
| 8   | Server logs at verbose level                               | Raw output at `logger.verbose` when `DEBUG=true`                    | `redact(output, [])` in `onToolEnd` / `onToolError` — static patterns only                                                 | F-08       | ⚠️ Partial (static patterns only)     |
| 9   | Outbound HTTP auth (Custom Tool)                           | Sandbox received raw token values; injected them in `fetch` headers | Auth header injected by host process; sandbox never receives token                                                         | F-05       | ✅ Closed (requires secretBindings)   |
| 10  | Redirect cross-origin credential forwarding                | Authorization/Cookie forwarded on any redirect, even cross-origin   | Sensitive headers stripped when redirect changes **full origin (scheme+hostname+port)**; `allowedHosts` re-checked per hop | (new)      | ✅ Closed                             |
| 11  | DNS-rebinding TOCTOU window                                | `checkDenyList` + `axios` resolved hostname twice; IP could change  | `secureAxiosSingleHop` pins validated IP into `http.Agent`; DNS resolved once per hop                                      | (new)      | ✅ Closed                             |
| 12  | Resolved-secret redaction                                  | `redact()` called with `[]`; custom secrets not caught              | `onSecretResolved` callback populates `resolvedSecretValues`; real values passed to `redact()`                             | F-04, F-06 | ✅ Closed (requires secretBindings)   |
| 13  | Tracing providers (all 7 listed)                           | Received full unredacted output via LangChain callback chain        | Protected by static-pattern redaction in `_call()` only; no per-provider wrapper; custom secrets still leak                | F-10       | ⚠️ Not closed — see Known Limitations |
| 14  | `$vars` in LLMNode / ConditionAgent / Condition / ToolNode | `$vars` with sensitive runtime vars in scope                        | Worst-case names blocked by denylist; full `$vars` removal deferred                                                        | F-07       | ⚠️ Partial (denylist only)            |
| 15  | `$vars` in ChatPromptTemplate                              | `$vars` in scope; sensitive key names reachable                     | Worst-case names blocked by denylist; full removal deferred                                                                | F-09       | ⚠️ Partial (denylist only)            |

### Upstream bug fixed

`createPinnedAgent` in the upstream Flowise codebase (confirmed against `upstream/main`) used the scalar callback form `cb(null, address, family)` in the custom `lookup` function. Node's `http.Agent` calls custom `lookup` functions with `{ all: true }` when requesting all addresses, at which point the callback contract changes to the array form `cb(null, [{address, family}])`. Passing scalars in that case causes Node's internals to call `ipaddr.parse(undefined)` → `"Invalid IP address: undefined"`. This made `secureAxiosRequest` fail for any URL with a hostname (not a raw IP literal). Observed on Node v24.11.0; the `{ all: true }` behavior has been present since at least Node v12, so it likely affects all Node versions in the Flowise supported range (≥20).

Fix: [`httpSecurity.ts`](packages/components/src/httpSecurity.ts) — `createPinnedAgent` now checks `opts.all` and returns the array form when required. Covered by 4 integration tests in [`httpSecurity.pinnedAgent.test.ts`](packages/components/src/httpSecurity.pinnedAgent.test.ts) with real TCP servers.

### What did not change

-   Any Custom Tool with **no** `secretBindings` field behaves identically to before,
    except that secret-named runtime variables (matching 14 key patterns: `SECRET`, `KEY`,
    `TOKEN`, `PASSWORD`, `FLOWISE_`, etc.) are now filtered out of `$vars` globally (F-03).
-   All 910 pre-existing tests pass without modification.
-   Zero new runtime npm dependencies.
-   All node types other than `CustomTool` are unmodified.

---

## Known Limitations

The following gaps are documented honestly. They are deferred to a future iteration, not hidden.

| Limitation                              | Affected findings            | Detail                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| --------------------------------------- | ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **F-10: tracing providers not covered** | F-10                         | LangSmith, LangFuse, Lunary, Arize, Phoenix, LangWatch, and Opik receive `Run` objects from LangChain's own callback chain — independently of `CustomStreamingHandler`. Static-pattern redaction in `_call()` catches known token formats; any custom secret value that does not match sk-, ghp\_, Bearer, xoxb-, or AIza will reach all 7 providers. A per-provider redaction wrapper (subclassing each `BaseCallbackHandler`) is the correct fix. |
| **F-07/F-09: other node types**         | F-07, F-09                   | `$vars` is still present in LLMNode, Agent, ConditionAgent, Condition, ToolNode, and ChatPromptTemplate sandboxes. The 14-pattern denylist blocks the worst-case keys (`FLOWISE_SECRETKEY_OVERWRITE`, `OPENAI_API_KEY`, etc.) globally, but non-blocked variable names remain accessible. Full `$vars` removal from these nodes is deferred.                                                                                                        |
| **Secrets < 8 chars not redacted**      | F-04, F-06                   | `guardRedact.ts` sets `MIN_SECRET_LENGTH = 8` to avoid false positives. Short credential values are not redacted.                                                                                                                                                                                                                                                                                                                                   |
| **No base64 / URL-encoded variants**    | F-04, F-06                   | Redaction operates on plaintext. A secret value that has been base64-encoded or percent-encoded before appearing in output will not be caught.                                                                                                                                                                                                                                                                                                      |
| **Legacy tools (no secretBindings)**    | F-01, F-02, F-04, F-05, F-06 | All Guard protections for secret isolation and resolved-secret redaction require the admin to declare `secretBindings`. Tools that do not declare bindings continue to receive `$vars` and are not protected by the Guard's secret isolation layer.                                                                                                                                                                                                 |

---

## Run the Demo

No server, no credentials, no setup — just Node ≥ 20 and a cloned repo.

```bash
# Show attacks using ORIGINAL upstream Flowise code (commit 9291856d snapshot):
#   Attack 1: $vars exfiltration — LLM receives all workspace secrets
#   Attack 2: Authorization forwarded on same-hostname/different-port redirect
#             (upstream has NO cross-origin header-stripping logic)
bash demo/before.sh
# Expected: runs in < 40 s; prints ⚠️ for each demonstrated leak; exits 0

# Show all defences live against real TCP servers (our fixed code)
bash demo/after.sh
# Expected: runs in < 40 s; prints ✅ for each defence; exits 0
#   Defence 1:  $vars absent; resolved values redacted from output
#   Defence 2a: allowedHosts blocks initial call to non-allowed host
#   Defence 2b: live redirect (localhost:4001 → 127.0.0.1:4002) blocked at hop 1
#   Defence 3a: same-hostname/different-port redirect strips Authorization
#               (same request as before.sh Attack 2 — now fixed by origin-based check)
#   Defence 3b: same-origin redirect keeps Authorization (precision)
```

Both scripts set `HTTP_SECURITY_CHECK=false` internally (loopback allowed inside the demo
process only) and enforce a 30-second hard timeout. After they exit, no processes linger:
`pgrep -f "run-after|run-before"` returns nothing.

---

## How IBM Bob Was Used

Bob was used as an active engineering participant — not a web search or prose generator —
with every claim grounded in file:line evidence read from the actual codebase.

### Session 1 — Baseline (Agent mode)

Bob ran `node --version`, `pnpm install`, `pnpm build`, and the full test suite, then wrote
[`docs/BASELINE.md`](docs/BASELINE.md) recording Node v24.11.0, pnpm 10.30.3, build 6/6,
910 tests passing, 0 pre-existing failures.

### Session 2 — Audit (Secret Leak Auditor mode)

Bob read every relevant source file without speculation and produced
[`docs/AUDIT.md`](docs/AUDIT.md): 10 confirmed findings with file:line evidence, severity
ratings, minimal reproductions, and 5 disproved claims.

Files read: [`src/utils.ts`](packages/components/src/utils.ts),
[`nodes/tools/CustomTool/core.ts`](packages/components/nodes/tools/CustomTool/core.ts),
[`src/handler.ts`](packages/components/src/handler.ts),
[`src/httpSecurity.ts`](packages/components/src/httpSecurity.ts).

### Session 3 — Design (Plan mode)

Bob authored [`docs/DESIGN.md`](docs/DESIGN.md) — the full technical specification
covering the `SecretBinding` type, call-time data flow, E2B strategy, `BLOCKED_ENV_KEY_PATTERNS`
denylist, redaction middleware spec, backward-compatibility rules, an 8-subtask breakdown,
and audit traceability. Three open design questions were raised and answered before
implementation began.

### Session 4 — Implementation (Guard Engineer mode, TDD)

Bob implemented the guard test-first, running `jest` after every subtask:

1. **`src/guardRedact.ts`** — 20 tests written first. Real bug found and fixed mid-cycle: a negative lookahead was needed to prevent the Bearer pattern from re-matching `Bearer [REDACTED]` after a resolved-secret pass.
2. **`src/guardRequest.ts`** — 13 initial tests. Additional tests added after self-review: redirect re-check, cross-host header stripping, `onSecretResolved`, `onAudit` callbacks, origin-based stripping. Final count: 27 tests.
3. **`src/utils.ts`** — `BLOCKED_ENV_KEY_PATTERNS`, `secureRequestHelper` param, `disableE2B` flag.
4. **`core.ts` + `CustomTool.ts`** — `secretBindings`, `setSecretBindings()`, `setExecutionOptions()`, wiring, `redact()` on outputs and errors. 6 new tests in `core.test.ts`.
5. **`handler.ts`** — `redact()` in all four callback methods.
6. **`httpSecurity.ts`** — cross-origin redirect strips Authorization/Cookie using `urlOrigin()` (scheme+host+port); `secureAxiosSingleHop` closes DNS-rebinding TOCTOU window; upstream `createPinnedAgent` lookup bug fixed. 14 new tests in `httpSecurity.test.ts`, 4 in `httpSecurity.pinnedAgent.test.ts`.
7. Full suite: **981 tests, 0 failures, 24 suites** (baseline: 910 tests, 20 suites). Pre-commit hooks (prettier, eslint, lint-staged) pass automatically.

### Measurable Bob contribution

| Activity                                              | Bob's role                                                                         | Human role                |
| ----------------------------------------------------- | ---------------------------------------------------------------------------------- | ------------------------- |
| Codebase traversal (4 source files, ~2000 lines read) | Read all files; cited every claim                                                  | None required             |
| Audit table (10 findings, 5 disproved)                | Authored [`docs/AUDIT.md`](docs/AUDIT.md)                                          | Reviewed                  |
| Architecture design                                   | Authored [`docs/DESIGN.md`](docs/DESIGN.md)                                        | Signed off on 3 decisions |
| TDD implementation                                    | Wrote tests first, then implementations                                            | None                      |
| Bug discovery (3)                                     | Bearer double-redaction; DNS-rebinding TOCTOU; upstream `createPinnedAgent` lookup | None                      |
| Self-review                                           | Authored [`docs/REVIEW.md`](docs/REVIEW.md); 9 issues found and fixed              | None                      |
| Test validation                                       | Ran `jest` after every subtask                                                     | None                      |
| Commit authorship                                     | Staged, wrote commit messages, committed                                           | None                      |
| Accuracy audit                                        | Verified every README claim against AUDIT.md and source                            | None                      |

Every claim in this document is backed by a file in this repository. No numbers were
invented. See [`docs/BOB_LOG.md`](docs/BOB_LOG.md) for the per-session log.

---

## Repository Structure

```
packages/components/
  src/
    guardRedact.ts               ← NEW: pure redact() function (static patterns + resolved secrets)
    guardRedact.test.ts          ← NEW: 20 tests
    guardRequest.ts              ← NEW: makeSecureRequestHelper factory + redirect loop + audit events
    guardRequest.test.ts         ← NEW: 27 tests (redirect, header-strip, onSecretResolved, onAudit, origin-based)
    httpSecurity.ts              ← MODIFIED: secureAxiosSingleHop (DNS-pin); urlOrigin() cross-origin strip;
                                              createPinnedAgent lookup all:true fix
    httpSecurity.test.ts         ← MODIFIED: +14 redirect/origin-based header-stripping tests
    httpSecurity.pinnedAgent.test.ts ← NEW: 4 integration tests (real TCP servers)
    utils.ts                     ← MODIFIED: BLOCKED_ENV_KEY_PATTERNS, secureRequestHelper param,
                                              disableE2B flag
    handler.ts                   ← MODIFIED: redact() in 4 callback methods
  nodes/tools/CustomTool/
    core.ts                      ← MODIFIED: secretBindings, $secureRequest wiring, resolvedSecretValues
    core.test.ts                 ← NEW: 6 tests for resolved-secret redaction
    CustomTool.ts                ← MODIFIED: parse + attach secretBindings from nodeData.inputs

docs/
  BASELINE.md                    ← pre-Guard and post-Guard test snapshots
  AUDIT.md                       ← 10 confirmed findings, 5 disproved
  DESIGN.md                      ← full technical specification
  REVIEW.md                      ← self-review findings and fix list (9 issues, all addressed)
  BOB_LOG.md                     ← per-session IBM Bob usage log
  HACKATHON_README.md            ← submission README
  FLOWISE_README.md              ← original Flowise README (preserved)

demo/
  before.sh / run-before.ts      ← BEFORE demo: runs upstream Flowise snapshot (commit 9291856d)
  after.sh  / run-after.ts       ← AFTER demo: guarded defence (real TCP servers; < 40 s, exits clean)
  mock-servers.js                ← two-server redirect harness
  legacy/
    httpSecurity.upstream.ts     ← verbatim upstream httpSecurity.ts at 9291856d (Apache-2.0)
```

## Running the Tests

```bash
pnpm install
pnpm --filter flowise-components exec jest --ci --forceExit --silent
# Expected: Test Suites: 24 passed  Tests: 981 passed  Time: ~120 s
```

---

_Branch: `zero-context-guard` · Commits: `8c485a9d` → `4cff856f` → `5242be3c` → `8c355358` → `baeef186` · IBM Bob Hackathon 2025 · Theme 2: Modernize What Matters_

---

> **Original Flowise README:** [docs/FLOWISE_README.md](docs/FLOWISE_README.md)
