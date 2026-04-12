#!/usr/bin/env bash
# Bootstrap the Latent Briefing replication environment.
# Clones the upstream Attention Matching repo and installs its requirements.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UPSTREAM_DIR="${HERE}/upstream/compaction"
UPSTREAM_REPO="https://github.com/adamzweiger/compaction.git"

mkdir -p "${HERE}/upstream"

if [ ! -d "${UPSTREAM_DIR}/.git" ]; then
  echo "[setup] Cloning ${UPSTREAM_REPO} -> ${UPSTREAM_DIR}"
  git clone --depth 1 "${UPSTREAM_REPO}" "${UPSTREAM_DIR}"
else
  echo "[setup] Upstream already present, pulling latest"
  git -C "${UPSTREAM_DIR}" pull --ff-only
fi

echo "[setup] Installing upstream requirements"
pip install -r "${UPSTREAM_DIR}/requirements.txt"

echo "[setup] Installing playground-local requirements"
pip install -r "${HERE}/requirements.txt"

echo "[setup] Done. Try: python demo.py --model Qwen/Qwen3-4B --target-size 0.1"
