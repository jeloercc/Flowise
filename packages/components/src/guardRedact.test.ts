import { redact } from './guardRedact'

describe('redact', () => {
    // ── no-op fast paths ──────────────────────────────────────────────────────
    it('returns text unchanged when resolvedSecrets is empty', () => {
        expect(redact('hello world', [])).toBe('hello world')
    })

    it('returns text unchanged when resolvedSecrets contains only short values', () => {
        // Values < 8 chars must be skipped to avoid false-positive replacements
        expect(redact('the value is: yes', ['yes'])).toBe('the value is: yes')
    })

    it('returns undefined unchanged', () => {
        expect(redact(undefined as any, [])).toBeUndefined()
    })

    it('returns null unchanged', () => {
        expect(redact(null as any, [])).toBeNull()
    })

    it('returns empty string unchanged', () => {
        expect(redact('', ['supersecret'])).toBe('')
    })

    // ── resolved-secret substitution ─────────────────────────────────────────
    it('replaces a single resolved secret', () => {
        const secret = 'supersecretvalue123'
        expect(redact(`Authorization: Bearer ${secret}`, [secret])).toBe('Authorization: Bearer [REDACTED]')
    })

    it('replaces all occurrences of a secret in one pass', () => {
        const secret = 'mytoken12345678'
        expect(redact(`${secret} and again ${secret}`, [secret])).toBe('[REDACTED] and again [REDACTED]')
    })

    it('replaces multiple distinct secrets', () => {
        const a = 'secretalpha9999'
        const b = 'secretbeta88888'
        expect(redact(`a=${a} b=${b}`, [a, b])).toBe('a=[REDACTED] b=[REDACTED]')
    })

    it('skips secrets shorter than 8 characters', () => {
        expect(redact('value is: abc', ['abc'])).toBe('value is: abc')
        expect(redact('value is: abcdefg', ['abcdefg'])).toBe('value is: abcdefg')
    })

    it('replaces secrets of exactly 8 characters', () => {
        const secret = 'exactly8'
        expect(redact(`token=${secret}`, [secret])).toBe('token=[REDACTED]')
    })

    it('does not mutate its inputs', () => {
        const text = 'original text with secretvalue99'
        const secrets = ['secretvalue99']
        const original = text
        redact(text, secrets)
        expect(text).toBe(original)
    })

    // ── static pattern: OpenAI sk- tokens ────────────────────────────────────
    it('redacts sk- token pattern', () => {
        expect(redact('key=sk-abc123456789XYZ', [])).toBe('key=[REDACTED:sk-token]')
    })

    it('redacts sk-proj- token pattern', () => {
        expect(redact('Authorization: Bearer sk-proj-Abc123456789', [])).toBe('Authorization: Bearer [REDACTED:sk-token]')
    })

    // ── static pattern: GitHub ghp_ tokens ───────────────────────────────────
    it('redacts ghp_ token pattern', () => {
        expect(redact('token=ghp_abcdef1234567890', [])).toBe('token=[REDACTED:gh-token]')
    })

    // ── static pattern: Bearer header ────────────────────────────────────────
    it('redacts Bearer token pattern', () => {
        expect(redact('Authorization: Bearer mysuperlongtoken123', [])).toBe('Authorization: [REDACTED:Bearer]')
    })

    it('does not redact Bearer with a token shorter than 8 chars', () => {
        // The static pattern only matches tokens ≥ 8 non-whitespace chars
        expect(redact('Authorization: Bearer short', [])).toBe('Authorization: Bearer short')
    })

    // ── static pattern: Slack bot tokens ─────────────────────────────────────
    it('redacts xoxb- Slack token pattern', () => {
        expect(redact('slack=xoxb-12345-67890-abcdef', [])).toBe('slack=[REDACTED:slack-token]')
    })

    // ── static pattern: Google API keys ──────────────────────────────────────
    it('redacts AIza Google API key pattern', () => {
        const googleKey = 'AIzaSyDummyKey1234567890123456789012345'
        expect(redact(`key=${googleKey}`, [])).toBe('key=[REDACTED:google-key]')
    })

    // ── ordering: resolved secrets applied before patterns ───────────────────
    it('applies resolved secrets before static patterns', () => {
        // The resolved secret happens to match no static pattern;
        // it must still be redacted via the resolved-secret path
        const secret = 'custom-secret-value-xyz-9999'
        const result = redact(`data=${secret}`, [secret])
        expect(result).toBe('data=[REDACTED]')
    })

    // ── special characters in secrets ────────────────────────────────────────
    it('handles secrets containing regex special characters', () => {
        const secret = 'my.secret+value(here)123'
        expect(redact(`token=${secret}`, [secret])).toBe('token=[REDACTED]')
    })
})
