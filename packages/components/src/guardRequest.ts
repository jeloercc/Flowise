/**
 * guardRequest — Zero-Context Guard request helper factory.
 *
 * Builds the `$secureRequest(name, url, options)` closure that is injected
 * into the NodeVM sandbox instead of raw `$vars`.
 *
 * Security invariants:
 *   1. The resolved credential value is NEVER placed in the sandbox scope.
 *   2. `allowedHosts` is checked against the lowercased URL hostname with
 *      exact-match semantics — no substring or prefix matching.
 *   3. `allowedHosts` is re-checked on EVERY redirect hop, not only the
 *      initial URL.  A redirect to a non-allowed host throws immediately.
 *   4. The actual HTTP call goes through `secureAxiosRequest`, which enforces
 *      the SSRF deny list and validates every redirect hop.
 *   5. Neither the credentialId nor the resolved secret value appears in any
 *      thrown error message.
 */

import axios from 'axios'
import { ICommonObject } from './Interface'
import { checkDenyList } from './httpSecurity'
import { getCredentialData } from './utils'

/** Maximum number of redirects the guard will follow. */
const MAX_GUARD_REDIRECTS = 5

/**
 * Audit event emitted by the guard on every $secureRequest call.
 * Never contains resolved secret values.
 */
export interface GuardAuditEvent {
    /** ISO timestamp of the request. */
    ts: string
    /** Binding name used by the sandbox call (not the credentialId). */
    binding: string
    /** Lowercased hostname of the final destination URL. */
    host: string
    /** 'allowed' if the guard completed the request, 'blocked' if it threw. */
    outcome: 'allowed' | 'blocked'
    /** If outcome is 'blocked', the reason. Never contains a secret value. */
    reason?: string
}

/** Admin-declared binding between a name alias and a stored credential. */
export interface SecretBinding {
    /** Identifier the sandbox code uses, e.g. "github" */
    name: string
    /** UUID of the Credential row — never visible to the LLM */
    credentialId: string
    /** Exact hostnames the Guard will allow, e.g. ["api.github.com"] */
    allowedHosts: string[]
}

/**
 * Supported HTTP methods for $secureRequest.
 */
export type SecureRequestMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'

/**
 * Options accepted by the $secureRequest helper.
 */
export interface SecureRequestOptions {
    method?: SecureRequestMethod
    headers?: Record<string, string>
    data?: unknown
    body?: unknown
}

/**
 * Well-known field names inside a credential object that contain a bearer-style
 * token.  Checked in order; the first match wins.
 */
const BEARER_FIELD_NAMES = [
    'token',
    'apiKey',
    'api_key',
    'accessToken',
    'access_token',
    'githubToken',
    'bearerToken',
    'bearer_token',
    'secret',
    'password'
]

/**
 * Extracts the first recognizable bearer-style token from a resolved
 * credential data object.
 */
function extractBearerToken(credentialData: ICommonObject): string | undefined {
    for (const key of BEARER_FIELD_NAMES) {
        if (typeof credentialData[key] === 'string' && credentialData[key]) {
            return credentialData[key] as string
        }
    }
    // Fall back to the first string-valued key
    for (const key of Object.keys(credentialData)) {
        if (typeof credentialData[key] === 'string' && credentialData[key]) {
            return credentialData[key] as string
        }
    }
    return undefined
}

/**
 * Substitutes `{{fieldName}}` placeholders in header values with the
 * corresponding value from `credentialData`.
 * Returns an empty object if `headers` is undefined.
 */
function interpolateHeaders(headers: Record<string, string> | undefined, credentialData: ICommonObject): Record<string, string> {
    if (!headers) return {}
    const result: Record<string, string> = {}
    for (const [key, value] of Object.entries(headers)) {
        result[key] = value.replace(/\{\{(\w+)\}\}/g, (_, field) => {
            const resolved = credentialData[field]
            return typeof resolved === 'string' ? resolved : value
        })
    }
    return result
}

/**
 * Extracts and lowercases the hostname from a URL string.
 * Throws a generic error (without the URL) if parsing fails.
 */
function safeHostname(url: string): string {
    try {
        return new URL(url).hostname.toLowerCase()
    } catch {
        throw new Error('$secureRequest: invalid URL')
    }
}

/**
 * Builds the `$secureRequest` helper function for a given set of secret
 * bindings.
 *
 * Returns `undefined` when `bindings` is empty (no-op; the sandbox gets no
 * helper injected).
 *
 * @param bindings  - Admin-declared bindings for this tool.
 * @param options   - The Flowise options object (contains appDataSource etc.)
 */
export function makeSecureRequestHelper(
    bindings: SecretBinding[],
    options: ICommonObject,
    /**
     * Optional callback invoked each time a credential is resolved.
     * Used by core.ts to collect resolved secret values for post-execution
     * redaction (F-04, F-06) without ever storing them in the sandbox.
     */
    onSecretResolved?: (secretValue: string) => void,
    /**
     * Optional callback invoked after every $secureRequest call with an
     * audit event.  The event never contains resolved secret values.
     */
    onAudit?: (event: GuardAuditEvent) => void
): ((...args: any[]) => Promise<string>) | undefined {
    if (!bindings || bindings.length === 0) return undefined

    // Build a lookup map by name for O(1) dispatch.
    const bindingMap = new Map<string, SecretBinding>()
    for (const b of bindings) {
        bindingMap.set(b.name, b)
    }

    /**
     * $secureRequest(name, url, requestOptions?)
     *
     * @param name           - Binding name declared at tool-design time.
     * @param url            - Destination URL.  Host must be in allowedHosts.
     * @param requestOptions - Optional method, headers, and body.
     * @returns              - Response body as a string.
     */
    return async function $secureRequest(name: string, url: string, requestOptions: SecureRequestOptions = {}): Promise<string> {
        // 1. Resolve binding — error must NOT mention credentialId.
        const binding = bindingMap.get(name)
        if (!binding) {
            throw new Error(`$secureRequest: unknown binding "${name}"`)
        }

        // 2. Check allowedHosts on the initial URL with exact hostname match.
        const hostname = safeHostname(url)
        const allowed = binding.allowedHosts.map((h) => h.toLowerCase())
        if (!allowed.includes(hostname)) {
            const reason = `host "${hostname}" is not in allowedHosts for binding "${name}"`
            if (onAudit) {
                onAudit({ ts: new Date().toISOString(), binding: name, host: hostname, outcome: 'blocked', reason })
            }
            throw new Error(`$secureRequest: ${reason}`)
        }

        // 3. Resolve credential server-side — value never enters sandbox scope.
        const credentialData = await getCredentialData(binding.credentialId, options)

        // Notify caller of all resolved string values so they can be redacted
        // from output and errors without ever placing them in the sandbox.
        if (onSecretResolved) {
            for (const v of Object.values(credentialData)) {
                if (typeof v === 'string' && v.length >= 8) {
                    onSecretResolved(v)
                }
            }
        }

        // 4. Build headers: interpolate {{placeholders}}, then inject bearer token
        //    if the caller hasn't provided their own Authorization header.
        const interpolated = interpolateHeaders(requestOptions.headers, credentialData)
        if (!interpolated['Authorization'] && !interpolated['authorization']) {
            const token = extractBearerToken(credentialData)
            if (token) {
                interpolated['Authorization'] = `Bearer ${token}`
            }
        }

        // 5. Execute hop-by-hop: SSRF-check each URL via checkDenyList, then
        //    call axios with maxRedirects:0/validateStatus so we get the raw
        //    response and can re-check allowedHosts on every redirect hop.
        let currentUrl = url
        let currentHeaders = interpolated
        let method = requestOptions.method ?? 'GET'
        let data: unknown = requestOptions.data ?? requestOptions.body
        let redirects = 0

        while (redirects <= MAX_GUARD_REDIRECTS) {
            // SSRF check before every hop (replaces secureAxiosRequest's resolveAndValidate).
            await checkDenyList(currentUrl)

            const response = await axios({
                url: currentUrl,
                method,
                data,
                headers: currentHeaders,
                maxRedirects: 0,
                validateStatus: () => true
            })

            // Not a redirect — return the final response.
            if (response.status < 300 || response.status >= 400) {
                if (onAudit) {
                    onAudit({
                        ts: new Date().toISOString(),
                        binding: name,
                        host: new URL(currentUrl).hostname.toLowerCase(),
                        outcome: 'allowed'
                    })
                }
                if (typeof response.data === 'string') return response.data
                return JSON.stringify(response.data)
            }

            const location = (response.headers as any)?.location
            if (!location) {
                // Redirect with no Location header — return as-is.
                if (onAudit) {
                    onAudit({
                        ts: new Date().toISOString(),
                        binding: name,
                        host: new URL(currentUrl).hostname.toLowerCase(),
                        outcome: 'allowed'
                    })
                }
                if (typeof response.data === 'string') return response.data
                return JSON.stringify(response.data)
            }

            redirects++
            if (redirects > MAX_GUARD_REDIRECTS) {
                throw new Error('$secureRequest: too many redirects')
            }

            const nextUrl = new URL(location, currentUrl).toString()
            const nextHostname = safeHostname(nextUrl)

            // Re-check allowedHosts for every redirect destination.
            if (!allowed.includes(nextHostname)) {
                const reason = `redirect to host "${nextHostname}" is not in allowedHosts for binding "${name}"`
                if (onAudit) {
                    onAudit({ ts: new Date().toISOString(), binding: name, host: nextHostname, outcome: 'blocked', reason })
                }
                throw new Error(`$secureRequest: ${reason}`)
            }

            currentUrl = nextUrl

            // Honour standard redirect method semantics.
            if (
                response.status === 303 ||
                (response.status !== 307 && response.status !== 308 && ['POST', 'PUT', 'PATCH'].includes(method.toUpperCase()))
            ) {
                method = 'GET'
                data = undefined
            }
        }

        throw new Error('$secureRequest: too many redirects')
    }
}
