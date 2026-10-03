# AFTER: Zero-Context Guard Active

This document describes what the demo shows and the expected output when running `demo/after.sh`.

## What is demonstrated

The `after` demo exercises the guarded Flowise Custom Tool execution path.
It imports the **real** guard code (`guardRequest.ts`, `guardRedact.ts`, `httpSecurity.ts`)
directly via `ts-node`. A module-cache patch injects a stub `getCredentialData` so no
database is required. No real credentials are used.

### Defence 1 — `$vars` absent; resolved credential values redacted

When `secretBindings` is declared, `createCodeExecutionSandbox` is called with
`secureRequestHelper != null`. This activates the guard branch:

```
if (secureRequestHelper) {
    sandbox['$secureRequest'] = secureRequestHelper  // helper injected
    // sandbox['$vars'] = ...   ← OMITTED
}
```

The tool calls `$secureRequest('myapi', url, {})`. The `onSecretResolved` callback
appends the resolved credential values to `resolvedSecretValues[]`. Even if the tool
output contains the key (e.g. via an accidental echo), `redact(output, resolvedSecretValues)`
replaces every resolved value with `[REDACTED]`.

### Defence 2 — `allowedHosts` blocks redirect to non-allowed host

`$secureRequest` re-checks `allowedHosts` against every redirect hop **before** following
it. A request to `evil.example.com` (not in `allowedHosts`) throws immediately:

```
BLOCKED: $secureRequest: host "evil.example.com" is not in allowedHosts for binding "strict"
```

### Defence 3 — Authorization stripped on cross-host redirect

`secureAxiosRequest` tracks `originHostname`. When a redirect leads to a different
hostname, `stripSensitiveHeaders()` removes `Authorization`, `Cookie`, and any header
matching `/key|token|secret|auth|cookie/i` before the next hop is made.

The demo uses `localhost` → `127.0.0.1` as the cross-origin pair.
Note: `localhost` resolves to `::1` (IPv6 loopback) which is blocked by the default SSRF
deny list — itself correct security behaviour. The header-strip logic is verified by
9 passing tests in `httpSecurity.test.ts`.

## How to run

```bash
bash demo/after.sh
```

## Expected output (trimmed)

```
════════════════════════════════════════════════════════════
  AFTER: Zero-Context Guard active
════════════════════════════════════════════════════════════

── Defence 1 — $vars absent; resolved credential values redacted from output ──
  $secureRequest returned: {"status":"ok","data":"response-from-api"}
  resolvedSecretValues collected: sk-aaa…, my-db-…

  Raw tool output (before redact):
    result: {…}, hint: sk-aaa…, pw: my-db-…

  Output after redact(output, resolvedSecretValues):
    result: {…}, hint: [REDACTED], pw: [REDACTED]

  ✅ No credential values reach the LLM or trace

── Defence 2 — redirect to non-allowed host blocked by $secureRequest ──
  BLOCKED: $secureRequest: host "evil.example.com" is not in allowedHosts…
  ✅ allowedHosts enforcement confirmed

── Defence 3 — Authorization stripped on cross-host redirect ──
  ✅ Cross-host header strip verified in httpSecurity tests (9 passing)

── Audit event (no secret values, safe to log or emit) ──
  { "ts": "…", "tool": "custom-tool", "secretsIn": "[NEVER LOGGED]" }
```
