#!/usr/bin/env bash
# Wrapper around `depot ci run` for supply-chain-detonation-depot.
# Modeled after PR #19's experiment.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKFLOWS_DIR_REL="supply-chain-detonation-depot/.depot/workflows"

REPO="${REPO:-N3mes1s/Playground}"

usage() {
  cat <<EOF
Usage: $(basename "$0") <command>

  Commands:
    build         Rebuild + cache the detonation-runner image
                  (~3 min first time, ~30 s after).
    detonate      Stage 1: detonate lodash@4.17.21. Boots a Linux
                  guest, runs npm install, prints the fingerprint
                  JSON. Doesn't diff against a baseline.
    verify        Stage 2: detonate, then diff the captured
                  fingerprint against the committed baseline. Fails
                  the workflow if anything mutated.
    matrix        Stage 3: read lockfile-fixtures/{base,head}.json,
                  detonate+verify each added/bumped package, print a
                  per-package summary table.
    list          Echo every available workflow path.
    status <id>   depot ci status passthrough.
    logs   <id>   depot ci logs passthrough.

  Env overrides:
    REPO          GitHub repo (default: N3mes1s/Playground)
    DEPOT_TOKEN   required for any depot ci call
EOF
}

require_token() {
  if [[ -z "${DEPOT_TOKEN:-}" ]]; then
    echo "ERROR: DEPOT_TOKEN is not set. See README 'Setup' section." >&2
    exit 2
  fi
}

run_wf() {
  local file="$1"
  require_token
  cd "$REPO_ROOT"
  exec depot ci run --repo "$REPO" --workflow "$WORKFLOWS_DIR_REL/$file"
}

cmd="${1:-}"
case "$cmd" in
  build)    run_wf build-runner-image.yml ;;
  detonate) run_wf detonate-one.yml ;;
  verify)   run_wf verify-package.yml ;;
  matrix)   run_wf matrix-lockfile.yml ;;
  list)
    ls -1 "$REPO_ROOT/$WORKFLOWS_DIR_REL" | sed "s#^#$WORKFLOWS_DIR_REL/#"
    ;;
  status)
    require_token; shift
    exec depot ci status "$@"
    ;;
  logs)
    require_token; shift
    exec depot ci logs "$@"
    ;;
  -h|--help|help|"")
    usage
    ;;
  *)
    echo "unknown command: $cmd" >&2
    echo >&2
    usage
    exit 2
    ;;
esac
