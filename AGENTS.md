# Project context for IBM Bob: Zero-Context Guard for Flowise

Bob loads this file automatically in every mode. Keep it short and true.

## What we are building

A security modernization of Flowise for the IBM Bob Hackathon (Theme 2: Modernize What Matters).
Flowise is end-of-life: code freeze 2026-07-29, repository archived 2026-08-13, EOL 2026-08-31 (Apache 2.0, forks encouraged). No more upstream security patches.

Goal: the LLM and the Custom Tool code never see raw secret values.
A tool asks for a secret by name. A backend "Zero-Context Guard" resolves it from Flowise's encrypted credential store, checks that the destination host is allowed for that secret, performs the request, and redacts secrets from results, errors and traces before anything goes back to the LLM.

## Codebase map (pnpm monorepo, Node >= 20)

- `packages/components`: nodes and integrations. **Our main change area.**
  - `src/utils.ts`: `getCredentialData`, `decryptCredentialData`, `getVars`, `prepareSandboxVars`, `createCodeExecutionSandbox`, `executeJavaScriptCode`, `handleErrorMessage`, `parseJsonBody`
  - `src/httpSecurity.ts`: `checkDenyList`, `secureAxiosRequest`, `secureFetch` (SSRF deny list for private IPs and localhost; manual redirect loop)
  - `nodes/tools/CustomTool/CustomTool.ts`: node definition (`inputs` are rendered by the UI automatically) and `init()`, which calls `setVariables(getVars(...))`
  - `nodes/tools/CustomTool/core.ts`: `DynamicStructuredTool.call()` and `_call()`. **Interception point.**
- `packages/server`: Express backend. Touch only if strictly needed, and ask first.
- `packages/ui`: React frontend. **Do not modify.**

## Commands

- Install: `pnpm install`
- Build: `pnpm build` (if the heap runs out: `NODE_OPTIONS=--max-old-space-size=4096 pnpm build`)
- Run: `pnpm start`, then open http://localhost:3000
- Component tests (Jest + ts-jest): `pnpm --filter flowise-components test`
- One test file: `pnpm --filter flowise-components test -- <pattern>`

## Non-negotiable rules

1. Never modify `packages/ui`.
2. Never read, print, log or commit real secrets: `.env*`, `encryption.key`, `~/.flowise/`, database files. Use fake values like `sk-FAKE-DEMO-0000000000` in tests and demos.
3. Backward compatibility: a Custom Tool without secret bindings must behave exactly as before. Existing tests must keep passing.
4. Small, reviewable changes. One concern per commit. Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`, `refactor:`).
5. New behavior ships with unit tests in the same change.
6. Every claim about the code cites `file:line-range`. If you are not sure, write "UNVERIFIED" and say how to verify it.
7. No new runtime dependencies without asking.
8. If a task needs files outside your mode's allowed paths, stop and ask instead of working around it.
9. When you finish a task, append one row to `docs/BOB_LOG.md`: `| date | mode | task | output (files or commit) | notes |`.

## Key terms

- **Secret binding**: `{ name, credentialId, allowedHosts[] }`, declared on the Custom Tool node by an admin. The LLM never sees or chooses `credentialId`.
- **`$secureRequest(name, url, options)`**: sandbox helper. The guard injects the auth header, enforces `allowedHosts` on the first request and on every redirect hop, and returns a redacted response.
- **Redaction**: replace every resolved secret value, and common key patterns (`sk-…`, `ghp_…`, `Bearer …`), with `[REDACTED:<name>]` in results, errors and anything passed to `handleToolEnd`.
- **Audit event**: `{ ts, tool, secretName, host, decision: allowed|blocked, reason }`. Never contains secret values.
