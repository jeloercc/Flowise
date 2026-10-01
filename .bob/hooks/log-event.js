// Bob lifecycle hook: appends one JSON line per event to docs/bob/session-log.jsonl.
// This is automatic evidence of how Bob was used during the hackathon.
// It prints nothing to stdout on purpose: for UserPromptSubmit, stdout is injected into Bob's context.
// Usage (from .bob/hooks/log-event.sh): node .bob/hooks/log-event.js <prompt|stop>

const fs = require('fs')
const { execSync } = require('child_process')

const event = process.argv[2] || 'unknown'

const sh = (cmd) => {
    try {
        return execSync(cmd, { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim()
    } catch {
        return ''
    }
}

// Zero-Context applies to our own logs too: never store a key that was pasted into a prompt.
const redact = (text) =>
    String(text || '')
        .replace(/sk-[A-Za-z0-9_-]{8,}/g, '[REDACTED]')
        .replace(/gh[pousr]_[A-Za-z0-9]{20,}/g, '[REDACTED]')
        .replace(/AKIA[0-9A-Z]{16}/g, '[REDACTED]')
        .replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]{10,}/gi, '$1[REDACTED]')

let raw = ''
process.stdin.on('data', (chunk) => (raw += chunk))
process.stdin.on('end', () => {
    try {
        let payload = {}
        try {
            payload = JSON.parse(raw || '{}')
        } catch {
            payload = {}
        }

        const entry = {
            ts: new Date().toISOString(),
            event,
            session: payload.session_id || null,
            branch: sh('git rev-parse --abbrev-ref HEAD')
        }

        if (event === 'prompt') {
            entry.prompt = redact(payload.prompt).slice(0, 4000)
        }
        if (event === 'stop') {
            entry.lastCommit = sh('git log -1 --oneline')
            entry.uncommitted = sh('git diff --stat HEAD | tail -n 1')
        }

        fs.mkdirSync('docs/bob', { recursive: true })
        fs.appendFileSync('docs/bob/session-log.jsonl', JSON.stringify(entry) + '\n')
    } catch (err) {
        process.stderr.write('log-event: ' + err.message + '\n')
    }
    process.exit(0)
})
