# BEFORE: No Zero-Context Guard

This document describes what the demo shows and the expected output when running `demo/before.sh`.

## What is demonstrated

The `before` demo exercises the unpatched Flowise Custom Tool execution path.
It uses **no real credentials** — all secrets are built at runtime from short fragments
and never appear as complete literals in source.

### Attack 1 — `$vars` returned in tool output

Without secret bindings declared, the sandbox receives `$vars` containing every
workspace variable. Tool code (or a prompt-injected payload) can call:

```javascript
return JSON.stringify($vars)
```

The entire variable map — including `OPENAI_API_KEY` and `DB_PASSWORD` — is returned
as the `ToolMessage` that the LLM receives verbatim.

The demo also shows that `redact(output, [])` with an empty `resolvedSecrets` array
(the old behaviour) does **not** catch `DB_PASSWORD` because it matches no static pattern.

### Attack 2 — Authorization header forwarded on cross-host redirect

The sandbox calls `secureAxiosRequest` with an `Authorization: Bearer <key>` header
pointed at Server A (port 4001). Server A replies with `302 Location: Server B (port 4002)`.

In the unpatched version, `secureAxiosRequest` spreads `currentConfig` on every hop,
forwarding the `Authorization` header verbatim to Server B (the "attacker").

## How to run

```bash
bash demo/before.sh
```

## Expected output (trimmed)

```
════════════════════════════════════════════════════════════
  BEFORE: no Zero-Context Guard
════════════════════════════════════════════════════════════

── Attack 1 — tool code returns $vars directly ──
  Tool output (what LLM receives as ToolMessage):
  {"OPENAI_API_KEY":"sk-aaa…","DB_PASSWORD":"my-db-…","APP_NAME":"my-flowise-app"}

  ⚠️  LLM sees OPENAI_API_KEY = sk-aaa…
  ⚠️  LLM sees DB_PASSWORD    = my-db-…

  After static-pattern redact(output, []):
  {"OPENAI_API_KEY":"[REDACTED:sk-token]","DB_PASSWORD":"my-db-…","APP_NAME":…}
  ⚠️  DB_PASSWORD still visible in SSE trace (no static pattern for it)

── Attack 2 — Authorization header forwarded on cross-host redirect ──
  Headers received by attacker server (B):
    authorization: Bearer sk-aaa…

  ⚠️  CREDENTIAL FORWARDED to redirect destination!
```
