#!/bin/sh
# Bob lifecycle hook wrapper. Finds Node even when Bob was launched from the Dock
# (macOS GUI apps do not inherit the PATH of your terminal), then runs log-event.js.
# Never fails the session: if Node is missing it exits quietly.

if ! command -v node >/dev/null 2>&1; then
  for dir in /opt/homebrew/bin /usr/local/bin "$HOME/.volta/bin"; do
    [ -x "$dir/node" ] && PATH="$dir:$PATH"
  done
  if ! command -v node >/dev/null 2>&1 && [ -s "$HOME/.nvm/nvm.sh" ]; then
    . "$HOME/.nvm/nvm.sh" >/dev/null 2>&1
  fi
fi

command -v node >/dev/null 2>&1 || exit 0
exec node .bob/hooks/log-event.js "$1"
