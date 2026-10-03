/**
 * Unit tests for the Zero-Context Guard request helper.
 *
 * We mock secureAxiosRequest so no real network calls are made.
 * All credential resolution is simulated via a stub options object.
 */
import { makeSecureRequestHelper, SecretBinding } from './guardRequest'

// ── Mocks ─────────────────────────────────────────────────────────────────────

jest.mock('./httpSecurity', () => ({
    secureAxiosRequest: jest.fn()
}))

// We mock getCredentialData at the utils module level used inside guardRequest.
jest.mock('./utils', () => ({
    getCredentialData: jest.fn()
}))

import { secureAxiosRequest } from './httpSecurity'
import { getCredentialData } from './utils'

const mockSecureAxios = secureAxiosRequest as jest.MockedFunction<typeof secureAxiosRequest>
const mockGetCred = getCredentialData as jest.MockedFunction<typeof getCredentialData>

// Shared fake options object (simulates what core.ts passes in)
const fakeOptions = { appDataSource: {}, databaseEntities: {} } as any

// ── Helpers ───────────────────────────────────────────────────────────────────

const binding: SecretBinding = {
    name: 'github',
    credentialId: 'cred-uuid-1234',
    allowedHosts: ['api.github.com']
}

beforeEach(() => {
    jest.clearAllMocks()
    mockGetCred.mockResolvedValue({ githubToken: 'ghp_FAKEFAKEFAKEFAKEFAKE1234567890' })
    mockSecureAxios.mockResolvedValue({ data: '{"ok":true}', status: 200 } as any)
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
            expect(mockSecureAxios).toHaveBeenCalledWith(
                expect.objectContaining({
                    url: 'https://api.github.com/repos/test',
                    method: 'GET'
                }),
                0 // guard manages redirects itself, passes maxRedirects=0 to secureAxiosRequest
            )
            expect(result).toBe('{"ok":true}')
        })

        it('injects the credential value as an Authorization Bearer header', async () => {
            const helper = makeSecureRequestHelper([binding], fakeOptions)!
            await helper('github', 'https://api.github.com/user', {})

            expect(mockSecureAxios).toHaveBeenCalledWith(
                expect.objectContaining({
                    headers: expect.objectContaining({
                        Authorization: 'Bearer ghp_FAKEFAKEFAKEFAKEFAKE1234567890'
                    })
                }),
                0 // guard manages redirects itself
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
            const call = mockSecureAxios.mock.calls[0][0]
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
            expect(caught!.message).not.toContain('ghp_FAKEFAKEFAKEFAKEFAKE1234567890')
        })

        it('returns response data as a string', async () => {
            mockSecureAxios.mockResolvedValueOnce({ data: { nested: 'object' }, status: 200 } as any)
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
            mockGetCred.mockResolvedValueOnce({ slackToken: 'xoxb-12345-FAKE-SLACK-TOKEN-9999' })

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
     * These tests verify that when secureAxiosRequest follows a redirect,
     * guardRequest re-checks allowedHosts against the redirect destination.
     * A redirect to a host NOT in allowedHosts must throw even if the
     * original URL was allowed.
     *
     * We simulate redirect behaviour by making mockSecureAxios throw the
     * error that the implementation is expected to throw when it re-validates
     * the redirect target URL against allowedHosts.
     *
     * For the positive case (redirect within allowed host), we verify the
     * request completes normally when secureAxiosRequest is called with the
     * final allowed URL.
     */

    const redirectBinding: SecretBinding = {
        name: 'api',
        credentialId: 'cred-api-redir',
        allowedHosts: ['api.allowed.com']
    }

    beforeEach(() => {
        jest.clearAllMocks()
        mockGetCred.mockResolvedValue({ token: 'tok-FAKE-REDIRECT-12345' })
        mockSecureAxios.mockResolvedValue({ data: 'ok', status: 200 } as any)
    })

    it('allows request when initial URL is in allowedHosts', async () => {
        const helper = makeSecureRequestHelper([redirectBinding], fakeOptions)!
        await expect(helper('api', 'https://api.allowed.com/data', {})).resolves.toBe('ok')
    })

    it('blocks redirect to a host not in allowedHosts', async () => {
        // Simulate: secureAxiosRequest follows a redirect to evil.example.com.
        // The guard must re-check the redirect destination against allowedHosts
        // before calling secureAxiosRequest (or by intercepting the result).
        // We test the guard's own pre-call check by having it receive a
        // redirect response whose Location header points outside allowedHosts.
        //
        // Implementation contract: makeSecureRequestHelper wraps secureAxiosRequest
        // with an onRedirect callback that re-validates the Location header hostname
        // against allowedHosts. If the redirect target is not allowed, it throws.
        //
        // To simulate a redirect response, mockSecureAxios is configured to
        // return 302 + Location on first call, then 200 on second call.
        // The guard must intercept before the second call and throw.
        mockSecureAxios
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
        mockSecureAxios
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
    // Use the REAL guardRequest module for this test (unmock it).
    // We mock only httpSecurity and utils at module level above.

    beforeEach(() => {
        jest.resetAllMocks()
        mockSecureAxios.mockResolvedValue({ data: 'ok', status: 200 } as any)
        mockGetCred.mockResolvedValue({ token: 'placeholder-token-1234' })
    })

    it('invokes onSecretResolved with resolved credential string values', async () => {
        const collected: string[] = []
        mockGetCred.mockResolvedValue({
            password: 'my-custom-db-password-xyz-99999',
            username: 'dbuser1234'
        })

        const helper = makeSecureRequestHelper(
            [{ name: 'db', credentialId: 'cred-db', allowedHosts: ['db.example.com'] }],
            fakeOptions,
            (v) => collected.push(v)
        )!

        await helper('db', 'https://db.example.com/query', {})

        expect(collected).toContain('my-custom-db-password-xyz-99999')
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

        const secret = 'my-custom-db-password-xyz-99999'
        const output = `query result: ${secret} was found`

        // Without resolved secrets: static patterns do not catch it
        expect(realRedact(output, [])).toBe(output)

        // With resolved secrets: it IS caught
        const redacted = realRedact(output, [secret])
        expect(redacted).not.toContain(secret)
        expect(redacted).toContain('[REDACTED]')
    })
})
