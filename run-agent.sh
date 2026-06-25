#!/bin/sh
# launchd entrypoint for terminal-agent.
# Reads the pre-shared token from a 0600 file at runtime so the secret never
# lives in the plist. Keep this path in sync with the token you set as the
# Worker's TERMINAL_TOKEN.
set -eu
cd /Users/lishuyu/Codes/terminal-agent
export TERMINAL_AGENT_TOKEN="$(cat /Users/lishuyu/.config/terminal-agent/token)"
exec /Users/lishuyu/.bun/bin/bun run src/index.ts
