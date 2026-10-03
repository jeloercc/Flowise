/**
 * Unit tests for the Zero-Context Guard request helper.
 *
 * We mock axios and checkDenyList so no real network calls are made.
 * All credential resolution is simulated via a stub options object.
 */
import { makeSecureRequestHelper, SecretBinding } from './guardRequest'

// ── Mocks ─────────────────────────────────────────────────────────────────────

// Mock axios default export (used by guardRequest for per-hop requests)
jest.mock('axios')

jest.mock('./httpSecurity', () => ({
    checkDenyList: jest.fn().mockResolvedValue(undefined)
}))

// We mock getCredentialData at the utils module level used inside guardRequest.
jest.mock('./utils', () => ({
    getCredentialData: jest.fn()
}))

import axios from 'axios'
import { checkDenyList } from './httpSecurity'
import { getCredentialData } from './utils'

const mockAxios = axios as jest.MockedFunction<typeof axios>
const mockCheckDenyList = checkDenyList as jest.MockedFunction<typeof checkDenyList>
const mockGetCred = getCredentialData as jest.MockedFunction<typeof getCredentialData>

// Shared fake options object (simulates what core.ts passes in)
const fakeOptions = { appDataSource: {}, databaseEntities: {} } as any

// ── Fake secrets built at runtime so secret-scanners see no complete literal ──
const FAKE_GH_TOKEN = 'ghp_' + 'b'.repeat(36)
const FAKE_SLACK_TOKEN = 'xoxb-' + '1'.repeat(24)
const FAKE_CUSTOM_PW = ['my', 'custom', 'db', 'password', '99999'].join('-')

// ── Helpers ───────────────────────────────────────────────────────────────────

const binding: SecretBinding = {
    name: 'github',
    credentialId: 'cred-uuid-1234',
    allowedHosts: ['api.github.com']
}

beforeEach(() => {
    jest.clearAllMocks()
    mockGetCred.mockResolvedValue({ githubToken: FAKE_GH_TOKEN })
    mockCheckDenyList.mockResolvedValue(undefined)
    mockAxios.mockResolvedValue({ data: '{"ok":true}', status: 200, headers: {} } as any)
})

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('makeSecureRequestHelper', () => {
    it('returns a function named $secureRequest', () => {
        const helper = makeSecureRequestHelper([binding], fakeOptions)
        expect(typeof helper).toBe('function')
    })

    it('returns undefined (no-op helper) when bindings array is empty', () => {
        const helper = makeSecureRequestHelper([], fakeOptions)
        expect(helper).toBeUndefined()
    })

    describe('$secureRequest', () => {
        it('resolves credential and makes a GET request to an allowed host', async () => {
            const helper = makeSecureRequestHelper([binding], fakeOptions)!
            const result = await helper('github', 'https://api.github.com/repos/test', {})

            expect(mockGetCred).toHaveBeenCalledWith('cred-uuid-1234', fakeOptions)
            expect(mockAxios).toHaveBeenCalledWith(
                expect.objectContaining({
                    url: 'https://api.github.com/repos/test',
                    method: 'GET',
                    maxRedirects: 0,
                    validateStatus: expect.any(Function)
                })
            )
            expect(result).toBe('{"ok":true}')
        })

        it('injects the credential value as an Authorization Bearer header', async () => {
            const helper = makeSecureRequestHelper([binding], fakeOptions)!
            await helper('github', 'https://api.github.com/user', {})

            expect(mockAxios).toHaveBeenCalledWith(
                expect.objectContaining({
                    headers: expect.objectContaining({
                        Authorization: `Bearer ${FAKE_GH_TOKEN}`
                    })
                })
            )
        })

        it('uses custom Authorization header key from credential when present', async () => {
            mockGetCred.mockResolvedValueOnce({ apiKey: 'my-raw-key-12345678' })
            const apiBinding: SecretBinding = {
                name: 'myapi',
                credentialId: 'cred-api',
                allowedHosts: ['api.example.com']
            }
            const helper = makeSecureRequestHelper([apiBinding], fakeOptions)!
            await helper('myapi', 'https://api.example.com/data', {
                headers: { 'X-Api-Key': '{{apiKey}}' }
            })

            // The helper must substitute {{apiKey}} with the resolved value
            const call = mockAxios.mock.calls[0][0] as any
            expect(Object.values(call.headers ?? {}).some((v) => v === 'my-raw-key-12345678')).toBe(true)
        })

        it('throws when the binding name is not found', async () => {
            const helper = makeSecureRequestHelper([binding], fakeOptions)!
            await expect(helper('unknown', 'https://api.github.com/user', {})).rejects.toThrow(/unknown binding/i)
        })

        it('throws when the URL host is not in allowedHosts', async () => {
            const helper = makeSecureRequestHelper([binding], fakeOptions)!
            await expect(helper('github', 'https://evil.example.com/steal', {})).rejects.toThrow(/not in allowedHosts/i)
        })

        it('throws when allowedHosts is empty', async () => {
            const emptyBinding: SecretBinding = {
                name: 'empty',
                credentialId: 'cred-empty',
                allowedHosts: []
            }
            const helper = makeSecureRequestHelper([emptyBinding], fakeOptions)!
            await expect(helper('empty', 'https://api.github.com/user', {})).rejects.toThrow(/not in allowedHosts/i)
        })

        it('does not expose credentialId in the error message', async () => {
            const helper = makeSecureRequestHelper([binding], fakeOptions)!
            let caught: Error | undefined
            try {
                await helper('github', 'https://evil.example.com/steal', {})
            } catch (e: any) {
                caught = e
            }
            expect(caught).toBeDefined()
            expect(caught!.message).not.toContain('cred-uuid-1234')
        })

        it('does not expose the resolved secret in the error message', async () => {
            const helper = makeSecureRequestHelper([binding], fakeOptions)!
            let caught: Error | undefined
            try {
                await helper('github', 'https://evil.example.com/steal', {})
            } catch (e: any) {
                caught = e
            }
            expect(caught).toBeDefined()
            expect(caught!.message).not.toContain(FAKE_GH_TOKEN)
        })

        it('returns response data as a string', async () => {
            mockAxios.mockResolvedValueOnce({ data: { nested: 'object' }, status: 200, headers: {} } as any)
            const helper = makeSecureRequestHelper([binding], fakeOptions)!
            const result = await helper('github', 'https://api.github.com/repo', {})
            expect(typeof result).toBe('string')
        })

        it('supports multiple bindings and dispatches by name', async () => {
            const bindingB: SecretBinding = {
                name: 'slack',
                credentialId: 'cred-slack',
                allowedHosts: ['slack.com']
            }
            mockGetCred.mockResolvedValueOnce({ slackToken: FAKE_SLACK_TOKEN })

            const helper = makeSecureRequestHelper([binding, bindingB], fakeOptions)!
            await helper('slack', 'https://slack.com/api/test', {})

            expect(mockGetCred).toHaveBeenCalledWith('cred-slack', fakeOptions)
        })

        it('validates host exactly, rejecting subdomain bypass attempts', async () => {
            const helper = makeSecureRequestHelper([binding], fakeOptions)!
            await expect(helper('github', 'https://evil.api.github.com/steal', {})).rejects.toThrow(/not in allowedHosts/i)
        })
    })
})

describe('$secureRequest — redirect allowedHosts re-check', () => {
    /**
     * These tests verify that when axios returns a redirect response,
     * guardRequest re-checks allowedHosts against the redirect destination
     * before following it.
     */

    const redirectBinding: SecretBinding = {
        name: 'api',
        credentialId: 'cred-api-redir',
        allowedHosts: ['api.allowed.com']
    }

    beforeEach(() => {
        jest.clearAllMocks()
        mockGetCred.mockResolvedValue({ token: 'tok-FAKE-REDIRECT-12345' })
        mockCheckDenyList.mockResolvedValue(undefined)
        mockAxios.mockResolvedValue({ data: 'ok', status: 200, headers: {} } as any)
    })

    it('allows request when initial URL is in allowedHosts', async () => {
        const helper = makeSecureRequestHelper([redirectBinding], fakeOptions)!
        await expect(helper('api', 'https://api.allowed.com/data', {})).resolves.toBe('ok')
    })

    it('blocks redirect to a host not in allowedHosts', async () => {
        // axios returns a 302 with Location pointing outside allowedHosts.
        // The guard must check the Location hostname before following.
        mockAxios
            .mockResolvedValueOnce({
                status: 302,
                headers: { location: 'https://evil.example.com/steal' },
                data: ''
            } as any)
            .mockResolvedValueOnce({ status: 200, data: 'stolen', headers: {} } as any)

        const helper = makeSecureRequestHelper([redirectBinding], fakeOptions)!
        await expect(helper('api', 'https://api.allowed.com/data', {})).rejects.toThrow(
            /not in allowedHosts|redirect.*not allowed|blocked/i
        )
    })

    it('allows a redirect within the same allowed host', async () => {
        // Both initial and redirect target are on api.allowed.com → should succeed.
        mockAxios
            .mockResolvedValueOnce({
                status: 301,
                headers: { location: 'https://api.allowed.com/v2/data' },
                data: ''
            } as any)
            .mockResolvedValueOnce({ status: 200, data: 'result', headers: {} } as any)

        const helper = makeSecureRequestHelper([redirectBinding], fakeOptions)!
        await expect(helper('api', 'https://api.allowed.com/data', {})).resolves.toBeDefined()
    })
})

// ── Integration: onSecretResolved callback populates resolvedSecretValues ─────

describe('makeSecureRequestHelper — onSecretResolved callback (F-04, F-06 fix)', () => {
    beforeEach(() => {
        jest.resetAllMocks()
        mockCheckDenyList.mockResolvedValue(undefined)
        mockAxios.mockResolvedValue({ data: 'ok', status: 200, headers: {} } as any)
        mockGetCred.mockResolvedValue({ token: 'placeholder-token-1234' })
    })

    it('invokes onSecretResolved with resolved credential string values', async () => {
        const collected: string[] = []
        mockGetCred.mockResolvedValue({
            password: FAKE_CUSTOM_PW,
            username: 'dbuser1234'
        })

        const helper = makeSecureRequestHelper(
            [{ name: 'db', credentialId: 'cred-db', allowedHosts: ['db.example.com'] }],
            fakeOptions,
            (v) => collected.push(v)
        )!

        await helper('db', 'https://db.example.com/query', {})

        expect(collected).toContain(FAKE_CUSTOM_PW)
        expect(collected).toContain('dbuser1234')
    })

    it('does not invoke onSecretResolved before the request is made', async () => {
        const collected: string[] = []
        mockGetCred.mockResolvedValue({ token: 'some-token-12345' })

        makeSecureRequestHelper([{ name: 'svc', credentialId: 'cred-svc', allowedHosts: ['svc.example.com'] }], fakeOptions, (v) =>
            collected.push(v)
        )

        // Callback must NOT be called at factory time — only when $secureRequest is invoked
        expect(collected).toHaveLength(0)
    })

    it('does not call onSecretResolved for values shorter than 8 chars', async () => {
        const collected: string[] = []
        mockGetCred.mockResolvedValue({ short: 'abc', long: 'long-value-12345678' })

        const helper = makeSecureRequestHelper(
            [{ name: 'svc', credentialId: 'cred-svc', allowedHosts: ['svc.example.com'] }],
            fakeOptions,
            (v) => collected.push(v)
        )!

        await helper('svc', 'https://svc.example.com/api', {})

        expect(collected).not.toContain('abc')
        expect(collected).toContain('long-value-12345678')
    })

    it('custom secret missing from static patterns IS redacted via resolved path', () => {
        const { redact: realRedact } = jest.requireActual('./guardRedact') as { redact: (text: string, secrets: string[]) => string }

        const secret = FAKE_CUSTOM_PW
        const output = `query result: ${secret} was found`

        // Without resolved secrets: static patterns do not catch it
        expect(realRedact(output, [])).toBe(output)

        // With resolved secrets: it IS caught
        const redacted = realRedact(output, [secret])
        expect(redacted).not.toContain(secret)
        expect(redacted).toContain('[REDACTED]')
    })
})

// ── onAudit callback tests ────────────────────────────────────────────────────

describe('makeSecureRequestHelper — onAudit callback', () => {
    const auditBinding = {
        name: 'svc',
        credentialId: 'cred-audit',
        allowedHosts: ['api.example.com']
    }

    beforeEach(() => {
        jest.resetAllMocks()
        mockCheckDenyList.mockResolvedValue(undefined)
        mockAxios.mockResolvedValue({ data: 'ok', status: 200, headers: {} } as any)
        mockGetCred.mockResolvedValue({ token: 'tok-AUDIT-FAKE-99999' })
    })

    it('emits an allowed audit event after a successful request', async () => {
        const events: any[] = []
        const helper = makeSecureRequestHelper([auditBinding], fakeOptions, undefined, (e) => events.push(e))!

        await helper('svc', 'https://api.example.com/data', {})

        expect(events).toHaveLength(1)
        expect(events[0].outcome).toBe('allowed')
        expect(events[0].binding).toBe('svc')
        expect(events[0].host).toBe('api.example.com')
        expect(events[0].ts).toMatch(/^\d{4}-\d{2}-\d{2}T/)
    })

    it('emits a blocked audit event when initial host is not in allowedHosts', async () => {
        const events: any[] = []
        const helper = makeSecureRequestHelper([auditBinding], fakeOptions, undefined, (e) => events.push(e))!

        try {
            await helper('svc', 'https://evil.example.com/steal', {})
        } catch (_) {
            // expected
        }

        expect(events).toHaveLength(1)
        expect(events[0].outcome).toBe('blocked')
        expect(events[0].host).toBe('evil.example.com')
        expect(events[0].reason).toMatch(/not in allowedHosts/)
    })

    it('emits a blocked event when redirect goes to non-allowed host', async () => {
        const events: any[] = []
        mockAxios
            .mockResolvedValueOnce({ status: 302, headers: { location: 'https://evil.example.com/steal' }, data: '' } as any)
            .mockResolvedValueOnce({ status: 200, data: 'stolen', headers: {} } as any)

        const helper = makeSecureRequestHelper([auditBinding], fakeOptions, undefined, (e) => events.push(e))!

        try {
            await helper('svc', 'https://api.example.com/data', {})
        } catch (_) {
            // expected
        }

        expect(events).toHaveLength(1)
        expect(events[0].outcome).toBe('blocked')
        expect(events[0].host).toBe('evil.example.com')
        expect(events[0].reason).toMatch(/redirect to host/)
    })

    it('audit event never contains the resolved secret value', async () => {
        const events: any[] = []
        const secretToken = 'tok-AUDIT-FAKE-99999'
        mockGetCred.mockResolvedValue({ token: secretToken })

        const helper = makeSecureRequestHelper([auditBinding], fakeOptions, undefined, (e) => events.push(e))!
        await helper('svc', 'https://api.example.com/data', {})

        const eventJson = JSON.stringify(events[0])
        expect(eventJson).not.toContain(secretToken)
        expect(events[0]).not.toHaveProperty('credentials')
        expect(events[0]).not.toHaveProperty('token')
        expect(events[0]).not.toHaveProperty('secret')
    })
})
