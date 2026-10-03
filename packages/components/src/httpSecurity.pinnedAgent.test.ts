/**
 * Integration tests for secureAxiosRequest / secureFetch via a real HTTP server.
 *
 * These tests do NOT mock axios, dns, or node-fetch.  They start real Node.js
 * HTTP servers on loopback ports and make actual TCP connections so that
 * Node's net/http stack exercises the custom `lookup` callback injected by
 * createPinnedAgent.
 *
 * HTTP_SECURITY_CHECK is set to 'false' so the private-IP deny-list (127/8)
 * does not block loopback — this is the documented env var to allow localhost
 * inside a controlled environment (tests / demo).
 *
 * Bug being guarded: createPinnedAgent passed (null, ip, family) scalars to
 * the http.Agent lookup callback, but when the agent is constructed with
 * `all:true` in its options, Node expects the callback form
 * `cb(null, [{address, family}])`.  The scalar form caused Node's internals to
 * call ipaddr.parse(undefined) → "Invalid IP address: undefined".
 */

import * as http from 'http'
import { secureAxiosRequest } from './httpSecurity'

// Allow loopback for this test file — tests explicitly document this is safe
// because they only ever start servers on 127.0.0.1 / ::1.
const OLD_HTTP_SECURITY_CHECK = process.env.HTTP_SECURITY_CHECK
beforeAll(() => {
    process.env.HTTP_SECURITY_CHECK = 'false'
})
afterAll(() => {
    if (OLD_HTTP_SECURITY_CHECK === undefined) {
        delete process.env.HTTP_SECURITY_CHECK
    } else {
        process.env.HTTP_SECURITY_CHECK = OLD_HTTP_SECURITY_CHECK
    }
})

/** Starts a one-shot HTTP server on a random port on 127.0.0.1. */
function startServer(
    handler: (req: http.IncomingMessage, res: http.ServerResponse) => void
): Promise<{ server: http.Server; port: number }> {
    return new Promise((resolve, reject) => {
        const server = http.createServer(handler)
        server.listen(0, '127.0.0.1', () => {
            const addr = server.address() as { port: number }
            resolve({ server, port: addr.port })
        })
        server.on('error', reject)
    })
}

function closeServer(server: http.Server): Promise<void> {
    return new Promise((resolve) => server.close(() => resolve()))
}

describe('secureAxiosRequest — pinned-agent lookup with all:true (regression)', () => {
    /**
     * Regression: createPinnedAgent's lookup callback used scalar form
     * `cb(null, ip, family)`.  When Node's http.Agent calls the custom lookup
     * with `{ all: true }` in opts, the callback must return an array
     * `[{ address, family }]`.  The scalar form caused the error:
     *   "Invalid IP address: undefined"
     */

    it('completes a direct GET to 127.0.0.1:<port> without throwing "Invalid IP address: undefined"', async () => {
        // Direct IP — takes the ipaddr.isValid branch in resolveAndValidate;
        // the pinned agent is created with ip=127.0.0.1, family=4.
        const { server, port } = await startServer((_, res) => {
            res.writeHead(200)
            res.end('direct-ok')
        })

        try {
            const response = await secureAxiosRequest({
                url: `http://127.0.0.1:${port}/`,
                method: 'GET'
            })
            expect(response.status).toBe(200)
            expect(response.data).toBe('direct-ok')
        } finally {
            await closeServer(server)
        }
    })

    it('completes a GET to "localhost:<port>" without throwing "Invalid IP address: undefined"', async () => {
        // "localhost" is NOT a valid IP, so resolveAndValidate calls
        // dns.lookup(hostname, { all: true }) → returns [{address, family}].
        // The chosen record is passed to createPinnedAgent, whose lookup cb
        // must handle the agent calling it back with {all:true} in opts.
        // Before the fix this threw: "Invalid IP address: undefined".
        const { server, port } = await startServer((_, res) => {
            res.writeHead(200)
            res.end('localhost-ok')
        })

        try {
            const response = await secureAxiosRequest({
                url: `http://localhost:${port}/`,
                method: 'GET'
            })
            expect(response.status).toBe(200)
            expect(response.data).toBe('localhost-ok')
        } finally {
            await closeServer(server)
        }
    })

    it('completes a cross-host redirect (localhost → 127.0.0.1) and strips Authorization', async () => {
        // This is the exact scenario that was broken in the demo:
        // localhost:A → 302 → 127.0.0.1:B
        // After fix: request completes, Authorization header stripped on cross-host.
        const receivedByB: Record<string, string | string[] | undefined> = {}

        const { server: serverB, port: portB } = await startServer((req, res) => {
            Object.assign(receivedByB, req.headers)
            res.writeHead(200)
            res.end('collected')
        })

        const { server: serverA, port: portA } = await startServer((_, res) => {
            res.writeHead(302, { location: `http://127.0.0.1:${portB}/collect` })
            res.end()
        })

        try {
            const response = await secureAxiosRequest({
                url: `http://localhost:${portA}/start`,
                method: 'GET',
                headers: { Authorization: 'Bearer sk-FAKE-TOKEN-0000000000000000' }
            })

            expect(response.status).toBe(200)
            // Authorization must be stripped because the redirect crosses origins:
            // origin(localhost:portA) ≠ origin(127.0.0.1:portB) — both hostname and host differ
            expect(receivedByB['authorization']).toBeUndefined()
        } finally {
            await closeServer(serverA)
            await closeServer(serverB)
        }
    })

    it('strips Authorization on same-hostname but different-port redirect (127.0.0.1:A → 127.0.0.1:B)', async () => {
        // Origin-based check: http://127.0.0.1:portA ≠ http://127.0.0.1:portB
        // Even though hostname is the same, the port change means a different origin.
        // This is the attack scenario: server A could redirect to server B on a different
        // port controlled by an attacker, leaking the Authorization header.
        const receivedByB: Record<string, string | string[] | undefined> = {}

        const { server: serverB, port: portB } = await startServer((req, res) => {
            Object.assign(receivedByB, req.headers)
            res.writeHead(200)
            res.end('diff-port-collected')
        })

        const { server: serverA, port: portA } = await startServer((_, res) => {
            res.writeHead(302, { location: `http://127.0.0.1:${portB}/collect` })
            res.end()
        })

        try {
            const response = await secureAxiosRequest({
                url: `http://127.0.0.1:${portA}/start`,
                method: 'GET',
                headers: { Authorization: 'Bearer sk-FAKE-TOKEN-0000000000000000' }
            })

            expect(response.status).toBe(200)
            // Different port = different origin → Authorization MUST be stripped
            expect(receivedByB['authorization']).toBeUndefined()
        } finally {
            await closeServer(serverA)
            await closeServer(serverB)
        }
    })
})
