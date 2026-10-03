#!/usr/bin/env bash
# demo/after.sh
# Runs the AFTER demo — shows the Zero-Context Guard in action.
# Usage from repo root:  bash demo/after.sh
#
# Clean-exit guarantee:
#   • SIGINT / SIGTERM / EXIT trap forwards the signal to ts-node and waits.
#   • The TypeScript script itself has a 30 s hard timeout + closeAllServers().
set -euo pipefail
cd "$(dirname "$0")/.."

DEMO_PID=""

cleanup() {
    if [ -n "$DEMO_PID" ] && kill -0 "$DEMO_PID" 2>/dev/null; then
        kill "$DEMO_PID" 2>/dev/null || true
        wait "$DEMO_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

echo ""
echo "Running AFTER demo (guard active)…"
echo ""

node_modules/.bin/ts-node \
  --project packages/components/tsconfig.json \
  --transpile-only \
  demo/run-after.ts &
DEMO_PID=$!
wait $DEMO_PID
