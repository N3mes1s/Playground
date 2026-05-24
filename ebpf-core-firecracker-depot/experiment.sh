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

  Hand-rolled flavor (kernels fetched from Ubuntu apt):
    build         Rebuild + cache the hand-rolled ebpf-runner image
                  (~3-5 min first time, ~30 s after).
    boot          Boot one Linux 6.8 guest, load probe (~15 s wall).
    matrix        Boot the 3 baked-in kernels (5.15, 6.1, 6.8) in
                  sequence, print summary table.

  LVH flavor (kernels pulled from quay.io/lvh-images/complexity-test):
    build-lvh     Same as build, but uses LVH's pre-built kernel
                  catalog. Ships 4 kernels (5.15, 6.1, 6.6, 6.12).
    matrix-lvh    Run the LVH-backed matrix.

  Common:
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
  build)      run_wf build-runner-image.yml ;;
  boot)       run_wf boot-single-kernel.yml ;;
  matrix)     run_wf matrix-kernels.yml ;;
  build-lvh)  run_wf build-runner-lvh-image.yml ;;
  matrix-lvh) run_wf matrix-kernels-lvh.yml ;;
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
