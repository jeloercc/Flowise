#!/usr/bin/env bash
# demo/before.sh
# Runs the BEFORE demo — shows what leaks WITHOUT the Zero-Context Guard.
# Usage from repo root:  bash demo/before.sh
set -uo pipefail
cd "$(dirname "$0")/.."

# Hard outer timeout: kill the Node process if it hasn't exited in 35 s
NODE_PID=''
cleanup() {
    if [ -n "$NODE_PID" ] && kill -0 "$NODE_PID" 2>/dev/null; then
        kill "$NODE_PID" 2>/dev/null || true
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
NODE_PID=$!

# Wait up to 35 s for the Node process to exit on its own
TIMEOUT_SECS=35
ELAPSED=0
while kill -0 "$NODE_PID" 2>/dev/null; do
    sleep 1
    ELAPSED=$((ELAPSED + 1))
    if [ "$ELAPSED" -ge "$TIMEOUT_SECS" ]; then
        echo ""
        echo "TIMEOUT: demo/before.sh: Node process did not exit in ${TIMEOUT_SECS}s — killing"
        kill "$NODE_PID" 2>/dev/null || true
        break
    fi
done

wait "$NODE_PID" 2>/dev/null || true
