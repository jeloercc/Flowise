#!/usr/bin/env bash
# demo/before.sh
# Runs the BEFORE demo — shows what leaks WITHOUT the Zero-Context Guard.
# Usage from repo root:  bash demo/before.sh
#
# Clean-exit guarantee:
#   • SIGINT / SIGTERM / EXIT trap forwards the signal to ts-node and waits.
#   • The TypeScript script itself has a 30 s hard timeout + server close().
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
echo "Running BEFORE demo (no guard)…"
echo ""

node_modules/.bin/ts-node \
  --project packages/components/tsconfig.json \
  --transpile-only \
  demo/run-before.ts &
DEMO_PID=$!
wait $DEMO_PID
