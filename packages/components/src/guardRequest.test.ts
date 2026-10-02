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
                })
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
