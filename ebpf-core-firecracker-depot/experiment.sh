#!/usr/bin/env bash
# Wrapper around `depot ci run` for the ebpf-core-firecracker-depot
# experiment. Lets you do
#   ./experiment.sh boot
# instead of remembering the full workflow path.
#
# Required env: DEPOT_TOKEN (depot_org_...). See README for setup.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKFLOWS_DIR_REL="ebpf-core-firecracker-depot/.depot/workflows"

REPO="${REPO:-N3mes1s/Playground}"

usage() {
  cat <<EOF
Usage: $(basename "$0") <command>

  Commands:
    build         Rebuild + cache the ebpf-runner image
                  (~3-5 min first time, ~30 s after).
    boot          Boot a single Linux guest (6.8), load probe,
                  capture verdict (~15 s wall after image cached).
    matrix        Boot every kernel baked into the image (5.15,
                  6.1, 6.8), load the same probe in each, print a
                  per-kernel summary table.
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
  build)  run_wf build-runner-image.yml ;;
  boot)   run_wf boot-single-kernel.yml ;;
  matrix) run_wf matrix-kernels.yml ;;
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
