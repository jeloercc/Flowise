#!/usr/bin/env bash
# demo/after.sh
# Runs the AFTER demo — shows the Zero-Context Guard in action.
# Usage from repo root:  bash demo/after.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo ""
echo "Running AFTER demo (guard active)…"
echo ""

node_modules/.bin/ts-node \
  --project packages/components/tsconfig.json \
  --transpile-only \
  demo/run-after.ts
