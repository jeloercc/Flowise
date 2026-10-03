#!/usr/bin/env bash
# demo/before.sh
# Runs the BEFORE demo — shows what leaks in the ORIGINAL upstream Flowise.
# Attack 1: $vars exfiltration via tool output
# Attack 2: Authorization header forwarded on same-hostname/different-port redirect
#           (upstream commit 9291856d has NO cross-origin header-stripping logic)
# Usage from repo root:  bash demo/before.sh
#
# Clean-exit guarantee:
#   • SIGINT / SIGTERM / EXIT trap forwards the signal to ts-node and waits.
#   • The TypeScript script itself has a 30 s hard timeout + server close().
set -euo pipefail
cd "$(dirname "$0")/.."

UPSTREAM_COMMIT="9291856d"

DEMO_PID=""

cleanup() {
    if [ -n "$DEMO_PID" ] && kill -0 "$DEMO_PID" 2>/dev/null; then
        kill "$DEMO_PID" 2>/dev/null || true
        wait "$DEMO_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

echo ""
echo "Running ORIGINAL upstream Flowise code (snapshot of commit ${UPSTREAM_COMMIT})…"
echo ""

node_modules/.bin/ts-node \
  --project packages/components/tsconfig.json \
  --transpile-only \
  demo/run-before.ts &
DEMO_PID=$!
wait $DEMO_PID
