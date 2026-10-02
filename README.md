# Zero-Context Guard for Flowise

## IBM Bob Hackathon 2025 — Theme 2: Modernize What Matters

> Flowise is end-of-life and ships with a critical class of vulnerabilities: every Custom
> Tool executed by an LLM receives raw `$vars` — workspace secrets, API keys, and
> environment variables — in plain text inside the sandbox. One prompt injection is all an
> attacker needs to exfiltrate them. We modernized this with a **Zero-Context Guard**:
> credentials are resolved server-side and injected only through `$secureRequest`, a
> host-allowlisted proxy wrapping the existing SSRF deny list. A redaction layer strips
> token patterns from Custom Tool outputs, errors, and log lines before they leave the
> process. Result: 8 OWASP LLM02 findings fully closed, 2 partially mitigated, 33 new
> tests, zero breaking changes, no new dependencies.

---

## The Problem: Legacy Agent Tools Are a Secret-Exfiltration Vector

Flowise (Apache 2.0, code-frozen 2026-07-29, EOL 2026-08-31) powers LLM agents that call
**Custom Tools** — user-written JavaScript executed inside a Node.js VM. Before this
project, every Custom Tool ran with a `$vars` object in scope containing every workspace
variable, including **runtime variables resolved from `process.env`**. The LLM chooses
which tool to call and what arguments to pass; prompt injection via tool arguments is
a realistic, low-effort attack.

This creates a confirmed path to [OWASP LLM02 — Insecure Output Handling][llm02]
and [LLM06 — Sensitive Information Disclosure][llm06]:

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

[llm02]: https://owasp.org/www-project-top-10-for-large-language-model-applications/
[llm06]: https://owasp.org/www-project-top-10-for-large-language-model-applications/

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
      3. secureAxiosRequest({url, headers: {Authorization: 'Bearer <token>'}})
           ↳ SSRF deny list enforced on every redirect hop  [httpSecurity.ts]
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

| Applied at                                     | What it protects                                                                        |
| ---------------------------------------------- | --------------------------------------------------------------------------------------- |
| `DynamicStructuredTool._call()` return value   | Static token patterns in Custom Tool output before it reaches LLM or SSE (F-04 partial) |
| `DynamicStructuredTool._call()` catch block    | Static token patterns in error messages before re-throw (F-06 partial)                  |
| `CustomStreamingHandler.handleToolEnd()`       | SSE `agent_trace` stream for any tool type (F-04)                                       |
| `CustomStreamingHandler.handleToolError()`     | SSE error payload for any tool type (F-06)                                              |
| `ConsoleCallbackHandler.onToolEnd/onToolError` | Verbose server logs at `DEBUG=true` for any tool type (F-08)                            |

> **Scope note:** The `_call()` redaction calls `redact(result, [])` — the resolved-secrets
> array is always empty at that call site because credential values are never materialised
> in the host process outside the `$secureRequest` closure. The redaction there applies
> **static regex patterns only** (sk-, ghp\_, Bearer, xoxb-, AIza). For a tool using
> `$secureRequest`, the secret value is never in a string that could reach `_call()`'s
> return statement, making the empty-array call still correct.

> **Tracing note (F-10):** `CustomStreamingHandler.handleToolEnd` applies `redact()` to
> the SSE stream. Third-party tracing callbacks (LangSmith, LangFuse, Lunary, Arize,
> Phoenix, LangWatch, Opik) are registered as separate LangChain `BaseCallbackHandler`
> instances and receive the raw `Run` object from LangChain's own tracer infrastructure —
> not from `CustomStreamingHandler`. Their inputs are therefore protected only by the
> static-pattern redaction that already happened in `_call()`, not by a per-tracing-provider
> redaction pass. F-10 is partially mitigated.

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

| #   | Area                                                       | Before                                                              | After                                                                                      | Finding    | Status                      |
| --- | ---------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ | ---------- | --------------------------- |
| 1   | Sandbox scope (Custom Tool)                                | `$vars` with all secrets in NodeVM scope                            | `$vars` absent when `secretBindings` declared; `$secureRequest` injected                   | F-02       | ✅ Closed                   |
| 2   | E2B remote VM                                              | Full `$vars` serialised and sent to e2b.dev                         | E2B disabled for tools with secret bindings                                                | F-01       | ✅ Closed                   |
| 3   | SSRF in E2B sandbox                                        | No deny-list; sandbox used native `fetch` freely                    | E2B blocked; only `secureAxiosRequest` path available                                      | F-05       | ✅ Closed                   |
| 4   | Runtime env vars in `$vars`                                | Any `process.env` key reachable via `runtime` variable              | 14-pattern denylist blocks `SECRET`, `KEY`, `TOKEN`, `FLOWISE_`, etc.                      | F-03       | ✅ Closed                   |
| 5   | Tool output to LLM                                         | Raw output returned as ToolMessage                                  | Static-pattern `redact()` applied in `_call()` before return                               | F-04       | ✅ Closed (static patterns) |
| 6   | SSE `agent_trace` stream                                   | Raw output emitted verbatim                                         | `redact()` in `handleToolEnd` / `handleToolError`                                          | F-04, F-06 | ✅ Closed                   |
| 7   | Server logs at verbose level                               | Raw output at `logger.verbose` when `DEBUG=true`                    | `redact()` in `onToolEnd` / `onToolError`                                                  | F-08       | ✅ Closed                   |
| 8   | Error messages (Custom Tool)                               | Execution error could embed raw secret values                       | Static-pattern `redact()` applied before re-throw                                          | F-06       | ✅ Closed (static patterns) |
| 9   | Outbound HTTP auth (Custom Tool)                           | Sandbox received raw token values; injected them in `fetch` headers | Auth header injected by host process; sandbox never receives token                         | F-05       | ✅ Closed                   |
| 10  | Tracing providers (all 7 listed)                           | Received full unredacted output via LangChain callback chain        | Protected by static-pattern redaction in `_call()` only; per-provider pass not implemented | F-10       | ⚠️ Partial                  |
| 11  | `$vars` in LLMNode / ConditionAgent / Condition / ToolNode | `$vars` with sensitive runtime vars in scope                        | Worst-case names blocked by denylist; full `$vars` removal deferred                        | F-07       | ⚠️ Partial                  |
| 12  | `$vars` in ChatPromptTemplate                              | `$vars` in scope; sensitive key names reachable                     | Worst-case names blocked by denylist; full removal deferred                                | F-09       | ⚠️ Partial                  |

### What did not change

-   Any Custom Tool with **no** `secretBindings` field behaves identically to before.
-   All 910 pre-existing tests pass without modification.
-   Zero new runtime npm dependencies.
-   The SSRF deny list, NodeVM `axios`/`node-fetch` wrappers, and `secureAxiosRequest`
    are unchanged and continue to protect all tool types.
-   All node types other than `CustomTool` are unmodified.

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
2. **`src/guardRequest.ts`** — 13 tests written first, including subdomain bypass rejection, empty allowlist guard, and explicit checks that `credentialId` and the resolved secret never appear in error messages.
3. **`src/utils.ts`** — `BLOCKED_ENV_KEY_PATTERNS`, `secureRequestHelper` param, `disableE2B` flag. Ran 54 existing `utils.test.ts` tests — all passed.
4. **`core.ts` + `CustomTool.ts`** — `secretBindings`, `setSecretBindings()`, `setExecutionOptions()`, wiring, `redact()` on outputs and errors.
5. **`handler.ts`** — `redact()` in all four callback methods.
6. Full suite: **943 tests, 0 failures, 22 suites**. Pre-commit hooks (prettier, eslint, lint-staged) passed automatically. Committed as `8c485a9d`.

### Measurable Bob contribution

| Activity                                              | Bob's role                                               | Human role                |
| ----------------------------------------------------- | -------------------------------------------------------- | ------------------------- |
| Codebase traversal (4 source files, ~2000 lines read) | Read all files; cited every claim                        | None required             |
| Audit table (10 findings, 5 disproved)                | Authored [`docs/AUDIT.md`](docs/AUDIT.md)                | Reviewed                  |
| Architecture design                                   | Authored [`docs/DESIGN.md`](docs/DESIGN.md)              | Signed off on 3 decisions |
| TDD implementation                                    | Wrote tests first, then implementations                  | None                      |
| Bug discovery                                         | Found Bearer double-redaction bug during red-green cycle | None                      |
| Test validation                                       | Ran `jest` after every subtask                           | None                      |
| Commit authorship                                     | Staged, wrote commit message, committed                  | None                      |
| Accuracy audit                                        | Verified every README claim against AUDIT.md and source  | None                      |

Every claim in this document is backed by a file in this repository. No numbers were
invented. See [`docs/BOB_LOG.md`](docs/BOB_LOG.md) for the per-session log.

---

## Repository Structure

```
packages/components/
  src/
    guardRedact.ts          ← NEW: pure redact() function (static token patterns)
    guardRedact.test.ts     ← NEW: 20 tests
    guardRequest.ts         ← NEW: makeSecureRequestHelper factory + SecretBinding type
    guardRequest.test.ts    ← NEW: 13 tests
    utils.ts                ← MODIFIED: BLOCKED_ENV_KEY_PATTERNS, secureRequestHelper param, disableE2B flag
    handler.ts              ← MODIFIED: redact() in 4 callback methods
  nodes/tools/CustomTool/
    core.ts                 ← MODIFIED: secretBindings field, $secureRequest wiring, redact() on outputs/errors
    CustomTool.ts           ← MODIFIED: parse + attach secretBindings from nodeData.inputs

docs/
  BASELINE.md               ← pre-Guard and post-Guard test snapshots
  AUDIT.md                  ← 10 confirmed findings, 5 disproved
  DESIGN.md                 ← full technical specification
  BOB_LOG.md                ← per-session IBM Bob usage log
  HACKATHON_README.md       ← original submission README
  FLOWISE_README.md         ← original Flowise README (preserved)
```

## Running the Tests

```bash
pnpm install
pnpm --filter flowise-components exec jest --ci --forceExit --silent
# Expected: Test Suites: 22 passed  Tests: 943 passed  Time: ~110 s
```

---

_Branch: `zero-context-guard` · Commit: `8c485a9d` · IBM Bob Hackathon 2025 · Theme 2: Modernize What Matters_

---

> **Original Flowise README:** [docs/FLOWISE_README.md](docs/FLOWISE_README.md)
