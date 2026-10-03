import { describe, expect, it } from '@jest/globals'
import { isDeniedIP } from './httpSecurity'

// Test deny list covering common SSRF targets
const TEST_DENY_LIST = [
    '0.0.0.0',
    '10.0.0.0/8', // RFC1918 Class A
    '127.0.0.0/8', // Loopback
    '169.254.0.0/16', // Link-local (includes cloud metadata)
    '169.254.169.254', // AWS metadata (specific)
    '172.16.0.0/12', // RFC1918 Class B
    '192.168.0.0/16', // RFC1918 Class C
    '224.0.0.0/4', // Multicast
    '240.0.0.0/4', // Reserved
    '255.255.255.255/32', // Broadcast
    '::1', // IPv6 loopback
    'fc00::/7', // IPv6 ULA
    'fe80::/10', // IPv6 link-local
    'ff00::/8' // IPv6 multicast
]

describe('isDeniedIP - SSRF Protection', () => {
    describe('IPv4 Address Blocking (Normal Cases)', () => {
        it('should block loopback address 127.0.0.1', () => {
            expect(() => isDeniedIP('127.0.0.1', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should block AWS metadata endpoint 169.254.169.254', () => {
            expect(() => isDeniedIP('169.254.169.254', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should block RFC1918 private address 10.0.0.1', () => {
            expect(() => isDeniedIP('10.0.0.1', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should block RFC1918 private address 192.168.1.1', () => {
            expect(() => isDeniedIP('192.168.1.1', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should block RFC1918 private address 172.16.0.1', () => {
            expect(() => isDeniedIP('172.16.0.1', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should block 0.0.0.0', () => {
            expect(() => isDeniedIP('0.0.0.0', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should block multicast address 224.0.0.1', () => {
            expect(() => isDeniedIP('224.0.0.1', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should block reserved address 240.0.0.1', () => {
            expect(() => isDeniedIP('240.0.0.1', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should block broadcast address 255.255.255.255', () => {
            expect(() => isDeniedIP('255.255.255.255', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should allow public IPv4 address 8.8.8.8', () => {
            expect(() => isDeniedIP('8.8.8.8', TEST_DENY_LIST)).not.toThrow()
        })

        it('should allow public IPv4 address 1.1.1.1', () => {
            expect(() => isDeniedIP('1.1.1.1', TEST_DENY_LIST)).not.toThrow()
        })
    })

    describe('IPv4-Mapped IPv6 Address Blocking (SSRF Bypass Prevention)', () => {
        it('should block IPv4-mapped IPv6 loopback ::ffff:127.0.0.1', () => {
            expect(() => isDeniedIP('::ffff:127.0.0.1', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should block IPv4-mapped IPv6 AWS metadata ::ffff:169.254.169.254', () => {
            expect(() => isDeniedIP('::ffff:169.254.169.254', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should block IPv4-mapped IPv6 private address ::ffff:10.0.0.1', () => {
            expect(() => isDeniedIP('::ffff:10.0.0.1', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should block IPv4-mapped IPv6 private address ::ffff:192.168.1.1', () => {
            expect(() => isDeniedIP('::ffff:192.168.1.1', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should block IPv4-mapped IPv6 private address ::ffff:172.16.0.1', () => {
            expect(() => isDeniedIP('::ffff:172.16.0.1', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should block IPv4-mapped IPv6 link-local ::ffff:169.254.0.1', () => {
            expect(() => isDeniedIP('::ffff:169.254.0.1', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should block IPv4-mapped IPv6 broadcast ::ffff:255.255.255.255', () => {
            expect(() => isDeniedIP('::ffff:255.255.255.255', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should block IPv4-mapped IPv6 multicast ::ffff:224.0.0.1', () => {
            expect(() => isDeniedIP('::ffff:224.0.0.1', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should allow IPv4-mapped IPv6 public address ::ffff:8.8.8.8', () => {
            expect(() => isDeniedIP('::ffff:8.8.8.8', TEST_DENY_LIST)).not.toThrow()
        })

        it('should allow IPv4-mapped IPv6 public address ::ffff:1.1.1.1', () => {
            expect(() => isDeniedIP('::ffff:1.1.1.1', TEST_DENY_LIST)).not.toThrow()
        })
    })

    describe('IPv6 Address Blocking', () => {
        it('should block IPv6 loopback ::1', () => {
            expect(() => isDeniedIP('::1', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should block IPv6 link-local fe80::1', () => {
            expect(() => isDeniedIP('fe80::1', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should block IPv6 ULA fc00::1', () => {
            expect(() => isDeniedIP('fc00::1', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should block IPv6 multicast ff02::1', () => {
            expect(() => isDeniedIP('ff02::1', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should allow public IPv6 address 2001:4860:4860::8888', () => {
            expect(() => isDeniedIP('2001:4860:4860::8888', TEST_DENY_LIST)).not.toThrow()
        })
    })

    describe('CIDR Range Matching', () => {
        it('should block IP at start of CIDR range 10.0.0.0', () => {
            expect(() => isDeniedIP('10.0.0.0', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should block IP in middle of CIDR range 10.128.0.1', () => {
            expect(() => isDeniedIP('10.128.0.1', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should block IP at end of CIDR range 10.255.255.255', () => {
            expect(() => isDeniedIP('10.255.255.255', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should block IP in 172.16.0.0/12 range - 172.31.255.255', () => {
            expect(() => isDeniedIP('172.31.255.255', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should allow IP just outside 172.16.0.0/12 range - 172.32.0.1', () => {
            expect(() => isDeniedIP('172.32.0.1', TEST_DENY_LIST)).not.toThrow()
        })

        it('should block IP in 169.254.0.0/16 range - 169.254.100.100', () => {
            expect(() => isDeniedIP('169.254.100.100', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })
    })

    describe('CIDR Range Matching with IPv4-Mapped IPv6', () => {
        it('should block IPv4-mapped IPv6 at start of CIDR range ::ffff:10.0.0.0', () => {
            expect(() => isDeniedIP('::ffff:10.0.0.0', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should block IPv4-mapped IPv6 in middle of CIDR range ::ffff:10.128.0.1', () => {
            expect(() => isDeniedIP('::ffff:10.128.0.1', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should block IPv4-mapped IPv6 at end of CIDR range ::ffff:10.255.255.255', () => {
            expect(() => isDeniedIP('::ffff:10.255.255.255', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should block IPv4-mapped IPv6 in 169.254.0.0/16 range - ::ffff:169.254.100.100', () => {
            expect(() => isDeniedIP('::ffff:169.254.100.100', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should allow IPv4-mapped IPv6 outside deny ranges - ::ffff:172.32.0.1', () => {
            expect(() => isDeniedIP('::ffff:172.32.0.1', TEST_DENY_LIST)).not.toThrow()
        })
    })

    describe('Exact IP Match (Non-CIDR)', () => {
        it('should block exact match 169.254.169.254', () => {
            expect(() => isDeniedIP('169.254.169.254', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should block exact match 0.0.0.0', () => {
            expect(() => isDeniedIP('0.0.0.0', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })
    })

    describe('Edge Cases and Security', () => {
        it('should handle empty deny list without errors', () => {
            expect(() => isDeniedIP('127.0.0.1', [])).not.toThrow()
        })

        it('should handle multiple CIDR entries correctly', () => {
            const multiCIDR = ['10.0.0.0/8', '192.168.0.0/16', '172.16.0.0/12']
            expect(() => isDeniedIP('10.5.5.5', multiCIDR)).toThrow('Access to this host is denied by policy.')
            expect(() => isDeniedIP('192.168.5.5', multiCIDR)).toThrow('Access to this host is denied by policy.')
            expect(() => isDeniedIP('172.20.5.5', multiCIDR)).toThrow('Access to this host is denied by policy.')
        })

        it('should block all variations of loopback', () => {
            expect(() => isDeniedIP('127.0.0.1', TEST_DENY_LIST)).toThrow()
            expect(() => isDeniedIP('127.1.1.1', TEST_DENY_LIST)).toThrow()
            expect(() => isDeniedIP('127.255.255.255', TEST_DENY_LIST)).toThrow()
        })

        it('should block all variations of loopback via IPv4-mapped IPv6', () => {
            expect(() => isDeniedIP('::ffff:127.0.0.1', TEST_DENY_LIST)).toThrow()
            expect(() => isDeniedIP('::ffff:127.1.1.1', TEST_DENY_LIST)).toThrow()
            expect(() => isDeniedIP('::ffff:127.255.255.255', TEST_DENY_LIST)).toThrow()
        })
    })

    describe('Cloud Metadata Endpoints (Real-world SSRF Targets)', () => {
        it('should block AWS metadata endpoint 169.254.169.254', () => {
            expect(() => isDeniedIP('169.254.169.254', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should block AWS metadata via IPv4-mapped IPv6 ::ffff:169.254.169.254', () => {
            expect(() => isDeniedIP('::ffff:169.254.169.254', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should block any IP in 169.254.0.0/16 range (link-local)', () => {
            expect(() => isDeniedIP('169.254.1.1', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
            expect(() => isDeniedIP('169.254.255.255', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should block link-local via IPv4-mapped IPv6', () => {
            expect(() => isDeniedIP('::ffff:169.254.1.1', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
            expect(() => isDeniedIP('::ffff:169.254.255.255', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })
    })

    describe('Regression Tests - CVE-2026-31829 Related', () => {
        it('should not allow bypassing via IPv4-mapped IPv6 to localhost', () => {
            // This would have bypassed the old vulnerable code
            expect(() => isDeniedIP('::ffff:127.0.0.1', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should not allow bypassing via IPv4-mapped IPv6 to private networks', () => {
            // These would have bypassed the old vulnerable code
            expect(() => isDeniedIP('::ffff:10.0.0.1', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
            expect(() => isDeniedIP('::ffff:192.168.0.1', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
            expect(() => isDeniedIP('::ffff:172.16.0.1', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })

        it('should not allow bypassing via IPv4-mapped IPv6 to cloud metadata', () => {
            // Critical SSRF target that would have been bypassed
            expect(() => isDeniedIP('::ffff:169.254.169.254', TEST_DENY_LIST)).toThrow('Access to this host is denied by policy.')
        })
    })

    describe('IPv4-Mapped IPv6 CIDR in Deny List', () => {
        const mappedCIDRDenyList = [
            '::ffff:10.0.0.0/104', // Equivalent to 10.0.0.0/8
            '::ffff:127.0.0.0/104', // Equivalent to 127.0.0.0/8
            '::ffff:192.168.0.0/112' // Equivalent to 192.168.0.0/16
        ]

        it('should block IPv4 address matching IPv4-mapped IPv6 CIDR in deny list', () => {
            expect(() => isDeniedIP('10.5.5.5', mappedCIDRDenyList)).toThrow('Access to this host is denied by policy.')
            expect(() => isDeniedIP('127.0.0.1', mappedCIDRDenyList)).toThrow('Access to this host is denied by policy.')
            expect(() => isDeniedIP('192.168.1.1', mappedCIDRDenyList)).toThrow('Access to this host is denied by policy.')
        })

        it('should block IPv4-mapped IPv6 address matching IPv4-mapped IPv6 CIDR in deny list', () => {
            expect(() => isDeniedIP('::ffff:10.5.5.5', mappedCIDRDenyList)).toThrow('Access to this host is denied by policy.')
            expect(() => isDeniedIP('::ffff:127.0.0.1', mappedCIDRDenyList)).toThrow('Access to this host is denied by policy.')
            expect(() => isDeniedIP('::ffff:192.168.1.1', mappedCIDRDenyList)).toThrow('Access to this host is denied by policy.')
        })

        it('should allow IPv4 address outside IPv4-mapped IPv6 CIDR in deny list', () => {
            expect(() => isDeniedIP('8.8.8.8', mappedCIDRDenyList)).not.toThrow()
            expect(() => isDeniedIP('1.1.1.1', mappedCIDRDenyList)).not.toThrow()
        })

        it('should correctly match CIDR boundaries with IPv4-mapped IPv6 in deny list', () => {
            // Test edge cases for the mask adjustment logic
            expect(() => isDeniedIP('10.0.0.0', mappedCIDRDenyList)).toThrow('Access to this host is denied by policy.')
            expect(() => isDeniedIP('10.255.255.255', mappedCIDRDenyList)).toThrow('Access to this host is denied by policy.')
            expect(() => isDeniedIP('192.168.0.0', mappedCIDRDenyList)).toThrow('Access to this host is denied by policy.')
            expect(() => isDeniedIP('192.168.255.255', mappedCIDRDenyList)).toThrow('Access to this host is denied by policy.')
        })
    })

    describe('Non-Canonical IPv6 Address Matching', () => {
        it('should block IPv6 address when deny list has uppercase variant', () => {
            // Deny list has FE80::1 (uppercase), should still match fe80::1
            const denyListUppercase = ['FE80::1']
            expect(() => isDeniedIP('fe80::1', denyListUppercase)).toThrow('Access to this host is denied by policy.')
        })

        it('should block IPv6 address when deny list has leading zeros', () => {
            // Deny list has 2001:0DB8::1 (leading zeros), should still match 2001:db8::1
            const denyListLeadingZeros = ['2001:0DB8::1']
            expect(() => isDeniedIP('2001:db8::1', denyListLeadingZeros)).toThrow('Access to this host is denied by policy.')
        })

        it('should block canonical IPv6 when deny list has non-canonical form', () => {
            // Deny list has non-canonical form, canonical request should still be blocked
            const denyListNonCanonical = ['FE80:0000:0000:0000:0000:0000:0000:0001']
            expect(() => isDeniedIP('fe80::1', denyListNonCanonical)).toThrow('Access to this host is denied by policy.')
        })

        it('should block non-canonical IPv6 when deny list has canonical form', () => {
            // Deny list has canonical form, non-canonical request should still be blocked
            const denyListCanonical = ['fe80::1']
            expect(() => isDeniedIP('FE80::1', denyListCanonical)).toThrow('Access to this host is denied by policy.')
            expect(() => isDeniedIP('FE80:0000:0000:0000:0000:0000:0000:0001', denyListCanonical)).toThrow(
                'Access to this host is denied by policy.'
            )
        })

        it('should block IPv4-mapped IPv6 with mixed case in deny list', () => {
            // Deny list has ::FFFF:127.0.0.1 (uppercase), should match any variant
            const denyListMixedCase = ['::FFFF:127.0.0.1']
            expect(() => isDeniedIP('::ffff:127.0.0.1', denyListMixedCase)).toThrow('Access to this host is denied by policy.')
            expect(() => isDeniedIP('127.0.0.1', denyListMixedCase)).toThrow('Access to this host is denied by policy.')
        })

        it('should normalize both sides when deny list has non-canonical IPv4-mapped IPv6', () => {
            // Deny list has 0000:0000:0000:0000:0000:FFFF:7F00:0001 (non-canonical form of ::ffff:127.0.0.1)
            const denyListLongForm = ['0000:0000:0000:0000:0000:FFFF:7F00:0001']
            expect(() => isDeniedIP('::ffff:127.0.0.1', denyListLongForm)).toThrow('Access to this host is denied by policy.')
            expect(() => isDeniedIP('127.0.0.1', denyListLongForm)).toThrow('Access to this host is denied by policy.')
        })

        it('should allow IPv6 addresses that do not match despite normalization', () => {
            const denyListFe80 = ['FE80::1']
            expect(() => isDeniedIP('fe80::2', denyListFe80)).not.toThrow()
            expect(() => isDeniedIP('2001:4860:4860::8888', denyListFe80)).not.toThrow()
        })
    })

    describe('Malformed IPv4-Mapped IPv6 CIDR Handling', () => {
        it('should skip malformed IPv4-mapped IPv6 CIDR with mask < 96', () => {
            // ::ffff:10.0.0.0/64 would create negative adjustedMask (-32)
            const malformedList = ['::ffff:10.0.0.0/64']

            // Public IPs should NOT be blocked
            expect(() => isDeniedIP('8.8.8.8', malformedList)).not.toThrow()
            expect(() => isDeniedIP('1.1.1.1', malformedList)).not.toThrow()
        })

        it('should skip malformed entry but still check other valid entries', () => {
            // Mix malformed and valid entries
            const mixedList = [
                '::ffff:10.0.0.0/64', // Malformed - should be skipped
                '127.0.0.0/8' // Valid - should still work
            ]

            // Should block based on valid entry
            expect(() => isDeniedIP('127.0.0.1', mixedList)).toThrow('Access to this host is denied by policy.')

            // Should allow public IPs (malformed entry skipped)
            expect(() => isDeniedIP('8.8.8.8', mixedList)).not.toThrow()
        })

        it('should accept valid IPv4-mapped IPv6 CIDR with mask >= 96', () => {
            // Valid: mask = 104 >= 96, adjustedMask = 104 - 96 = 8
            const validList = ['::ffff:10.0.0.0/104']

            // Should block 10.x.x.x
            expect(() => isDeniedIP('10.5.5.5', validList)).toThrow('Access to this host is denied by policy.')

            // Should allow public IPs
            expect(() => isDeniedIP('8.8.8.8', validList)).not.toThrow()
        })

        it('should handle edge case: mask = 96 (exactly at boundary)', () => {
            // Valid: mask = 96, adjustedMask = 96 - 96 = 0 (matches all IPv4)
            const boundaryList = ['::ffff:0.0.0.0/96']

            // Should block all IPv4 (which is valid behavior for /96)
            expect(() => isDeniedIP('8.8.8.8', boundaryList)).toThrow('Access to this host is denied by policy.')
            expect(() => isDeniedIP('1.1.1.1', boundaryList)).toThrow('Access to this host is denied by policy.')
        })

        it('should skip multiple malformed entries', () => {
            // Multiple malformed entries
            const multiMalformedList = [
                '::ffff:10.0.0.0/64', // Malformed
                '::ffff:192.168.0.0/50', // Malformed
                '8.8.8.8' // Valid exact match
            ]

            // Should block exact match
            expect(() => isDeniedIP('8.8.8.8', multiMalformedList)).toThrow('Access to this host is denied by policy.')

            // Should allow other IPs (malformed entries skipped)
            expect(() => isDeniedIP('1.1.1.1', multiMalformedList)).not.toThrow()
            expect(() => isDeniedIP('10.0.0.1', multiMalformedList)).not.toThrow()
        })
    })
})

// ── Redirect cross-host header-stripping tests ────────────────────────────────
//
// These tests verify that sensitive headers (Authorization, Cookie, X-Api-Key,
// X-Auth-Token, X-Secret) are stripped when a redirect changes the origin
// (host), but kept when the redirect stays on the same host.
//
// Both secureAxiosRequest and secureFetch are tested.
// All DNS/network calls are fully mocked so no real network traffic is made.

import { secureAxiosRequest, secureFetch } from './httpSecurity'

// We need to mock the DNS resolver and axios/node-fetch so tests run offline.
jest.mock('dns/promises', () => ({
    lookup: jest.fn()
}))

jest.mock('axios', () => {
    const mockAxios = jest.fn()
    return mockAxios
})

jest.mock('node-fetch', () => {
    const mockFetch = jest.fn()
    return mockFetch
})

import dns from 'dns/promises'
import axios from 'axios'
import nodeFetch from 'node-fetch'

const mockDns = dns.lookup as jest.MockedFunction<typeof dns.lookup>
const mockAxios = axios as unknown as jest.MockedFunction<(config: any) => Promise<any>>
const mockFetch = nodeFetch as unknown as jest.MockedFunction<(url: any, opts: any) => Promise<any>>

function fakeResponse(status: number, headers: Record<string, string> = {}, data: any = 'ok') {
    return {
        status,
        headers: {
            ...headers,
            get: (k: string) => headers[k.toLowerCase()] ?? null
        },
        data,
        text: async () => (typeof data === 'string' ? data : JSON.stringify(data))
    }
}

function setupDns(ip = '93.184.216.34') {
    // Return a benign public IP for any hostname lookup.
    mockDns.mockResolvedValue([{ address: ip, family: 4 }] as any)
}

describe('secureAxiosRequest — redirect header handling', () => {
    beforeEach(() => {
        jest.clearAllMocks()
        setupDns()
    })

    it('keeps Authorization header on same-host redirect', async () => {
        // First call → 302 to same host; second call → 200.
        mockAxios
            .mockResolvedValueOnce(fakeResponse(302, { location: 'https://api.example.com/v2/data' }))
            .mockResolvedValueOnce(fakeResponse(200, {}, 'data'))

        await secureAxiosRequest({
            url: 'https://api.example.com/v1/data',
            method: 'GET',
            headers: { Authorization: 'Bearer secret-token-1234' }
        })

        const secondCall = mockAxios.mock.calls[1][0]
        expect(secondCall.headers['Authorization']).toBe('Bearer secret-token-1234')
    })

    it('strips Authorization header on cross-host redirect', async () => {
        mockAxios
            .mockResolvedValueOnce(fakeResponse(302, { location: 'https://other.example.com/page' }))
            .mockResolvedValueOnce(fakeResponse(200, {}, 'data'))

        await secureAxiosRequest({
            url: 'https://api.example.com/v1/data',
            method: 'GET',
            headers: { Authorization: 'Bearer secret-token-1234' }
        })

        const secondCall = mockAxios.mock.calls[1][0]
        expect(secondCall.headers['Authorization']).toBeUndefined()
    })

    it('strips Cookie header on cross-host redirect', async () => {
        mockAxios
            .mockResolvedValueOnce(fakeResponse(302, { location: 'https://other.example.com/page' }))
            .mockResolvedValueOnce(fakeResponse(200, {}, 'data'))

        await secureAxiosRequest({
            url: 'https://api.example.com/v1/data',
            method: 'GET',
            headers: { Cookie: 'session=abc123' }
        })

        const secondCall = mockAxios.mock.calls[1][0]
        expect(secondCall.headers['Cookie']).toBeUndefined()
    })

    it('strips X-Api-Key header on cross-host redirect', async () => {
        mockAxios
            .mockResolvedValueOnce(fakeResponse(302, { location: 'https://other.example.com/page' }))
            .mockResolvedValueOnce(fakeResponse(200, {}, 'data'))

        await secureAxiosRequest({
            url: 'https://api.example.com/v1/data',
            method: 'GET',
            headers: { 'X-Api-Key': 'my-api-key-99999' }
        })

        const secondCall = mockAxios.mock.calls[1][0]
        expect(secondCall.headers['X-Api-Key']).toBeUndefined()
    })

    it('strips X-Auth-Token header on cross-host redirect', async () => {
        mockAxios
            .mockResolvedValueOnce(fakeResponse(302, { location: 'https://other.example.com/page' }))
            .mockResolvedValueOnce(fakeResponse(200, {}, 'data'))

        await secureAxiosRequest({
            url: 'https://api.example.com/v1/data',
            method: 'GET',
            headers: { 'X-Auth-Token': 'auth-tok-99999' }
        })

        const secondCall = mockAxios.mock.calls[1][0]
        expect(secondCall.headers['X-Auth-Token']).toBeUndefined()
    })

    it('keeps non-sensitive headers on cross-host redirect', async () => {
        mockAxios
            .mockResolvedValueOnce(fakeResponse(302, { location: 'https://other.example.com/page' }))
            .mockResolvedValueOnce(fakeResponse(200, {}, 'data'))

        await secureAxiosRequest({
            url: 'https://api.example.com/v1/data',
            method: 'GET',
            headers: { Authorization: 'Bearer tok', Accept: 'application/json', 'X-Request-Id': 'req-1' }
        })

        const secondCall = mockAxios.mock.calls[1][0]
        expect(secondCall.headers['Authorization']).toBeUndefined()
        expect(secondCall.headers['Accept']).toBe('application/json')
        expect(secondCall.headers['X-Request-Id']).toBe('req-1')
    })
})

describe('secureFetch — redirect header handling', () => {
    beforeEach(() => {
        jest.clearAllMocks()
        setupDns()
    })

    // node-fetch Response-like mock
    function fetchResponse(status: number, headers: Record<string, string> = {}, body = 'ok') {
        return {
            status,
            ok: status >= 200 && status < 300,
            headers: {
                get: (k: string) => headers[k.toLowerCase()] ?? null
            },
            text: async () => body
        }
    }

    it('keeps Authorization header on same-host redirect', async () => {
        mockFetch
            .mockResolvedValueOnce(fetchResponse(302, { location: 'https://api.example.com/v2' }) as any)
            .mockResolvedValueOnce(fetchResponse(200) as any)

        await secureFetch('https://api.example.com/v1', {
            headers: { Authorization: 'Bearer tok-1234' }
        })

        const secondCall = mockFetch.mock.calls[1]
        const secondHeaders: any = secondCall[1]?.headers ?? {}
        const authValue = typeof secondHeaders === 'object' ? secondHeaders['Authorization'] ?? secondHeaders['authorization'] : undefined
        expect(authValue).toBe('Bearer tok-1234')
    })

    it('strips Authorization header on cross-host redirect', async () => {
        mockFetch
            .mockResolvedValueOnce(fetchResponse(302, { location: 'https://other.example.com/page' }) as any)
            .mockResolvedValueOnce(fetchResponse(200) as any)

        await secureFetch('https://api.example.com/v1', {
            headers: { Authorization: 'Bearer secret-9999' }
        })

        const secondCall = mockFetch.mock.calls[1]
        const secondHeaders: any = secondCall[1]?.headers ?? {}
        const authValue = typeof secondHeaders === 'object' ? secondHeaders['Authorization'] ?? secondHeaders['authorization'] : undefined
        expect(authValue).toBeUndefined()
    })

    it('strips Cookie header on cross-host redirect', async () => {
        mockFetch
            .mockResolvedValueOnce(fetchResponse(302, { location: 'https://other.example.com/page' }) as any)
            .mockResolvedValueOnce(fetchResponse(200) as any)

        await secureFetch('https://api.example.com/v1', {
            headers: { Cookie: 'session=xyz' }
        })

        const secondCall = mockFetch.mock.calls[1]
        const secondHeaders: any = secondCall[1]?.headers ?? {}
        expect(secondHeaders['Cookie'] ?? secondHeaders['cookie']).toBeUndefined()
    })
})
