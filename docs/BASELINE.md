# Flowise Fork — Baseline

Recorded on branch `zero-context-guard`.

## Environment

| Item    | Value               |
| ------- | ------------------- |
| Node.js | v24.11.0            |
| pnpm    | 10.30.3             |
| OS      | darwin 23.6.0 (x64) |
| Date    | 2025-07-30          |

## Commands run

```sh
# 1. Check toolchain
node --version   # v24.11.0
pnpm --version   # 10.30.3

# 2. Install dependencies
pnpm install
# Resolved 4097 packages; 2808 reused, 1253 downloaded; ~3m 19s

# 3. Build all packages
NODE_OPTIONS=--max-old-space-size=4096 pnpm build
# 6 packages built via turbo; all cached on second run

# 4. Run component tests (pre-Guard baseline, no source changes)
pnpm --filter flowise-components test -- --forceExit --testTimeout=60000

# 5. Run component tests (post-Guard, after commit 8c485a9d)
pnpm --filter flowise-components exec jest --ci --forceExit --silent
```

## Build result

| Status        | Packages |
| ------------- | -------- |
| ✅ Successful | 6 / 6    |

Build ran with `NODE_OPTIONS=--max-old-space-size=4096` as a precaution (first run required it; turbo cached on subsequent runs). Vite emitted "dynamic import will not move module" warnings for ~20 UI views and "chunks larger than 500 kB" warnings — both are pre-existing, non-blocking.

## Test results (`flowise-components`)

### Pre-Guard snapshot (unmodified upstream, 2025-07-30)

| Metric        | Count  |
| ------------- | ------ |
| Test suites   | 20     |
| Tests passed  | 910    |
| Tests failed  | 0      |
| Tests skipped | 0      |
| Duration      | ~299 s |

### Post-Guard snapshot (after commit `8c485a9d`, 2025-07-30)

Command: `pnpm --filter flowise-components exec jest --ci --forceExit --silent`

| Metric        | Count  | Delta vs pre-Guard             |
| ------------- | ------ | ------------------------------ |
| Test suites   | 22     | +2 (guardRedact, guardRequest) |
| Tests passed  | 943    | +33 new guard tests            |
| Tests failed  | 0      | —                              |
| Tests skipped | 0      | —                              |
| Duration      | ~108 s | —                              |

Jest printed a "worker process has failed to exit gracefully" warning and was force-exited in both snapshots. This is a pre-existing leaked async timer in some integration tests, **not** a test failure.

## Failing tests (pre-existing)

**None.** Zero failures in both the pre-Guard and post-Guard runs.

## Notable warnings (non-blocking)

| Source                           | Warning                                                                                                                                                |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `AWSChatBedrock.test.ts`         | `console.warn` about ARN in endpoint host, full URL in endpoint host, path separator in endpoint host — expected, generated deliberately by test cases |
| `AWSChatBedrockImported.test.ts` | LangChain deprecation notice for `AIMessage` with `tool_calls` in `additional_kwargs` — upstream library churn, not our code                           |
| `jest` runner                    | "worker process has failed to exit gracefully" / force-exit — open timer leak in integration tests; does not affect pass/fail counts                   |
| `pnpm install`                   | Several ETIMEDOUT retries on slow packages; all resolved after retry                                                                                   |
| `pnpm install`                   | `pnpm` update available (10.30.3 → 12.8.1) — cosmetic, not required                                                                                    |
| Vite (ui build)                  | "dynamic import will not move module" (20 routes) and chunk size warnings — pre-existing UI build configuration                                        |
