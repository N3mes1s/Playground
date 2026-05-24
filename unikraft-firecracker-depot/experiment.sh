#!/usr/bin/env bash
# Wrapper around `depot ci run` for this experiment. Lets you do
#   ./experiment.sh boot-native
# instead of remembering the full workflow path.
#
# Required env: DEPOT_TOKEN (depot_org_...). See README for setup.

set -euo pipefail

REPO="${REPO:-N3mes1s/Playground}"
WORKFLOWS_DIR="unikraft-firecracker-depot/.depot/workflows"

usage() {
  cat <<EOF
Usage: $(basename "$0") <command>

  Commands (most-useful first):
    boot-helloworld           Boot the prebuilt helloworld unikernel via the
                              cached runner image (~11 s wall).
    boot-native               Boot the from-source aegis-probe unikernel via
                              the cached runner image (~10 s wall).
    smoke                     Boot the official Unikraft catalog images
                              (helloworld, python, nginx, redis) via
                              kraft run (~3 min wall).

  Build commands (only after editing the corresponding sources):
    build-helloworld-image    Rebuild + cache the helloworld runner image.
    build-native-image        Rebuild + cache the native (aegis-probe) runner.

  Slow / no-cache:
    boot-helloworld-inline    Same as boot-helloworld but installs FC +
                              kraft inline at run time (~61 s, doesn't
                              need a project ID).

  Lower-level:
    list                      Echo every available workflow path.
    status <run-id>           depot ci status passthrough.
    logs <attempt-id>         depot ci logs passthrough.

  Env overrides:
    REPO                      GitHub repo (default: N3mes1s/Playground)
    DEPOT_TOKEN               required for any depot ci call
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
  exec depot ci run --repo "$REPO" --workflow "$WORKFLOWS_DIR/$file"
}

cmd="${1:-}"
case "$cmd" in
  boot-helloworld)         run_wf boot-helloworld-cached.yml ;;
  boot-helloworld-inline)  run_wf boot-helloworld-inline.yml ;;
  build-helloworld-image)  run_wf build-helloworld-image.yml ;;
  boot-native)             run_wf boot-native-cached.yml ;;
  build-native-image)      run_wf build-native-image.yml ;;
  smoke)                   run_wf smoke-catalog-images.yml ;;
  list)
    ls -1 "$WORKFLOWS_DIR" | sed "s#^#$WORKFLOWS_DIR/#"
    ;;
  status)
    require_token
    shift
    exec depot ci status "$@"
    ;;
  logs)
    require_token
    shift
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
