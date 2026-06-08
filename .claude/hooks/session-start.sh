#!/bin/bash
# SessionStart hook for Claude Code on the web.
#
# Installs the `llmake` experiment's dependencies (PyYAML + the DSPy engine) so
# its test suite and CLI work in a fresh remote container, and exports
# PYTHONPATH so `python -m llmake.cli ...` runs from anywhere in the session.
#
# Synchronous (no async): the session waits until deps are installed, avoiding a
# race where tests run before the environment is ready.
set -euo pipefail

# Only needed in Claude Code on the web (remote) containers.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "$CLAUDE_PROJECT_DIR/llmake"

# Core deps (idempotent; container state is cached after the hook completes).
python3 -m pip install --quiet -r requirements.txt

# Defensive: a stale system cryptography/cffi can break litellm's import, which
# dspy needs. Only repair if the import actually fails.
python3 -c "import litellm" >/dev/null 2>&1 || \
  python3 -m pip install --quiet --upgrade cffi cryptography

# Make the package importable and the CLI runnable for the rest of the session.
echo "export PYTHONPATH=\"$CLAUDE_PROJECT_DIR/llmake:\${PYTHONPATH:-}\"" >> "$CLAUDE_ENV_FILE"

echo "llmake session-start hook: dependencies ready."
