#!/usr/bin/env bash
# demo/before.sh
# Runs the BEFORE demo — shows what leaks WITHOUT the Zero-Context Guard.
# Usage from repo root:  bash demo/before.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo ""
echo "Running BEFORE demo (no guard)…"
echo ""

node_modules/.bin/ts-node \
  --project packages/components/tsconfig.json \
  --transpile-only \
  demo/run-before.ts
