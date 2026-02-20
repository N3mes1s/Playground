#!/bin/bash
# Launch OpenCode AI agent inside the Chrome sandbox
# Requires: npm i -g opencode-ai@latest
# Usage: ANTHROPIC_API_KEY=... bash scripts/sandbox-opencode.sh "your prompt here"

set -euo pipefail

PROMPT="${1:-Create a file called hello.txt with 'Hello from OpenCode inside the Chrome sandbox!' and read it back.}"

cd "$(dirname "$0")/.." || exit 1

exec env -i \
  HOME=/tmp \
  PATH="/opt/node22/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:?Set ANTHROPIC_API_KEY}" \
  GLOBAL_AGENT_HTTP_PROXY="${GLOBAL_AGENT_HTTP_PROXY:-}" \
  GLOBAL_AGENT_HTTPS_PROXY="${GLOBAL_AGENT_HTTP_PROXY:-}" \
  HTTP_PROXY="${GLOBAL_AGENT_HTTP_PROXY:-}" \
  HTTPS_PROXY="${GLOBAL_AGENT_HTTP_PROXY:-}" \
  no_proxy="${no_proxy:-}" \
  NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt \
  SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
  TERM=xterm-256color \
  XDG_DATA_HOME=/tmp/.local/share \
  ./sandbox-run-cli/target/release/sandbox-run \
    --network --ioctls tty \
    --readonly '/opt/node22:/usr/share/zoneinfo:/etc/ssl' \
    --policy PERMISSIVE \
    --audit=/tmp/opencode-sandbox.log \
    -- opencode run -m anthropic/claude-haiku-4-5 "$PROMPT"
