/**
 * guardRedact — pure redaction utility for the Zero-Context Guard.
 *
 * Replaces resolved secret values and common token patterns from any string
 * before it leaves the Node.js process boundary (SSE, logger, tracing).
 *
 * Security rules:
 *   - Resolved secrets shorter than 8 characters are skipped to avoid
 *     false-positive replacements of common short words.
 *   - The function is purely functional: no I/O, no side-effects.
 *   - null / undefined inputs are returned as-is.
 */

/** Minimum length for a resolved secret to be eligible for redaction. */
const MIN_SECRET_LENGTH = 8

/**
 * Static patterns that are always redacted regardless of whether the caller
 * provides resolved secrets.  Each entry has a regex and a replacement label.
 */
const REDACT_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
    { pattern: /sk-[A-Za-z0-9_-]{10,}/g, label: 'sk-token' },
    { pattern: /ghp_[A-Za-z0-9]{10,}/g, label: 'gh-token' },
    // Negative lookahead prevents re-matching already-redacted text such as
    // "Bearer [REDACTED]" after an earlier resolved-secret pass.
    { pattern: /Bearer\s+(?!\[REDACTED)[^\s"',]{8,}/g, label: 'Bearer' },
    { pattern: /xoxb-[0-9A-Za-z-]{10,}/g, label: 'slack-token' },
    { pattern: /AIza[0-9A-Za-z_-]{35}/g, label: 'google-key' }
]

/**
 * Escapes all regex special characters in a string so it can be used
 * inside `new RegExp(...)` as a literal value.
 */
function escapeRegExp(s: string): string {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/**
 * Redacts secret values and known token patterns from `text`.
 *
 * @param text            - The string to redact.
 * @param resolvedSecrets - Array of plaintext secret values that should be
 *                          replaced with `[REDACTED]`.
 * @returns The redacted string.  Returns `text` unchanged if it is
 *          `null`, `undefined`, or an empty string.
 */
export function redact(text: string, resolvedSecrets: string[]): string {
    if (text == null || text === '') return text

    let result = text

    // 1. Replace resolved secret values first (before patterns, so that a
    //    secret that also matches a pattern is replaced with the generic
    //    [REDACTED] marker rather than a pattern-specific one).
    for (const secret of resolvedSecrets) {
        if (!secret || secret.length < MIN_SECRET_LENGTH) continue
        const re = new RegExp(escapeRegExp(secret), 'g')
        result = result.replace(re, '[REDACTED]')
    }

    // 2. Apply static patterns.
    for (const { pattern, label } of REDACT_PATTERNS) {
        // Reset lastIndex between calls since we reuse the same RegExp objects.
        pattern.lastIndex = 0
        result = result.replace(pattern, `[REDACTED:${label}]`)
    }

    return result
}
