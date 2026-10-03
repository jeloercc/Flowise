# Demo — Zero-Context Guard Before/After

Reproducible, no-dependency demonstration of the security fix.
All secrets are fake values built at runtime. No real credentials are used.
Both scripts finish in about 10 seconds and clean up all ports on exit.

## Files

| File              | Purpose                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mock-servers.js` | Two tiny Node HTTP servers (no npm deps). Server A (port 4001) redirects to Server B (port 4002). Server B logs every credential header it receives. Usable standalone or imported.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `run-before.ts`   | TypeScript script that exercises the **unpatched** path: `$vars` in scope, `secureAxiosRequest` forwarding headers on cross-host redirect.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `run-after.ts`    | TypeScript script that exercises the **guarded** path: `$vars` absent, `$secureRequest` + `onSecretResolved`, `allowedHosts` re-check on redirects, cross-host header strip. **Stubbed**: `getCredentialData` (the Flowise credential-store lookup in `utils.ts`) is replaced via a Node module-cache patch with a function that returns fake runtime-built keys — no database, no `appDataSource`, no encryption key needed. **Real**: `makeSecureRequestHelper` (guard factory + redirect loop + `onAudit`/`onSecretResolved` callbacks), `redact()`, `secureAxiosRequest`, `secureAxiosSingleHop` (called inside the guard loop), and `createPinnedAgent` (called inside `secureAxiosSingleHop`) all execute as production code. |
| `before.sh`       | Shell wrapper: `bash demo/before.sh` from repo root.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `after.sh`        | Shell wrapper: `bash demo/after.sh` from repo root.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `before.md`       | Narrative + expected output for the before demo.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `after.md`        | Narrative + expected output for the after demo.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |

## How to run

```bash
# From the repository root — one command each, no extra setup needed:

bash demo/before.sh   # shows the leak (no guard)
bash demo/after.sh    # shows the guard blocking it
```

Prerequisites: `pnpm install` must have been run (provides `node_modules/.bin/ts-node`).

## What each demo shows

### Before (`before.sh`)

1. **`$vars` exfiltration** — tool code `return JSON.stringify($vars)` sends every
   workspace secret to the LLM as a `ToolMessage`. `DB_PASSWORD` survives even a
   static-pattern `redact()` call because it matches no regex.
2. **Redirect credential forwarding** — `Authorization: Bearer <key>` is forwarded
   verbatim to the redirect destination (the "attacker" Server B).

### After (`after.sh`)

1. **`$vars` absent** — `sandbox.$vars` is never set; `$secureRequest` is injected instead.
   The `onSecretResolved` callback collects resolved credential values; `redact(output,
resolvedSecretValues)` replaces both the OpenAI key and the DB password with `[REDACTED]`.
2. **allowedHosts blocks non-listed host** — `$secureRequest('strict', 'http://evil.example.com/steal')`
   throws: `"host evil.example.com is not in allowedHosts"`.
3. **Cross-host redirect strips headers** — `localhost` → `127.0.0.1` triggers the
   sensitive-header strip; `Authorization` is removed before the hop.
   (Also verified by 9 passing unit tests in `httpSecurity.test.ts`.)

## Guard code exercised

| Guard module                              | Entry point used in demo                                  |
| ----------------------------------------- | --------------------------------------------------------- |
| `packages/components/src/guardRequest.ts` | `makeSecureRequestHelper()` + `onSecretResolved` callback |
| `packages/components/src/guardRedact.ts`  | `redact(text, resolvedSecretValues)`                      |
| `packages/components/src/httpSecurity.ts` | `secureAxiosRequest()` with cross-origin redirect         |
