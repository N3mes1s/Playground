#!/bin/bash
# Launch Aider AI coding agent inside the Chrome sandbox
# Requires: pip install aider-chat
# Usage: ANTHROPIC_API_KEY=... bash scripts/sandbox-aider.sh "your prompt here"

set -euo pipefail

PROMPT="${1:-Create a file called hello.txt with 'Hello from Aider inside the Chrome sandbox!' and read it back.}"

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
  SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
  REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
  TERM=xterm-256color \
  ./sandbox-run-cli/target/release/sandbox-run \
    --network --ioctls tty \
    --readonly '/usr/local/bin:/usr/local/lib/python3.11:/usr/lib/python3.11:/usr/lib/python3:/usr/share/zoneinfo:/etc/ssl:/lib/x86_64-linux-gnu' \
    --policy PERMISSIVE \
    --audit=/tmp/aider-sandbox.log \
    -- python3 -m aider --model anthropic/claude-haiku-4-5 --yes --no-git --message "$PROMPT"
