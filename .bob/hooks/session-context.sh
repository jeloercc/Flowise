#!/bin/sh
# Bob SessionStart hook. Whatever this prints is added to Bob's context, so keep it short.

echo "Session context (auto, from .bob/hooks/session-context.sh):"
echo "- Branch: $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
echo "- Last commits: $(git log -3 --oneline 2>/dev/null | tr '\n' ';')"
for f in docs/AUDIT.md docs/DESIGN.md docs/BOB_LOG.md; do
  if [ -f "$f" ]; then echo "- $f: present"; else echo "- $f: missing"; fi
done
echo "- Follow AGENTS.md. Never read .env files, encryption.key or database files."
exit 0
