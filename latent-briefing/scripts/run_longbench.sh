#!/usr/bin/env bash
# LongBench v2 subset evaluation, matching the setup referenced in the
# Latent Briefing announcement.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UPSTREAM="${HERE}/../upstream/compaction"

if [ ! -d "${UPSTREAM}" ]; then
  echo "Upstream not found at ${UPSTREAM}. Run ../setup.sh first." >&2
  exit 1
fi

cd "${UPSTREAM}"

python -m evaluation.run_qa_evaluation \
  --algorithm-config default \
  --methods original AM-HighestAttnKeys \
  --dataset-name quality \
  --n-articles "${N_ARTICLES:-1}" \
  --compute-stats 1 \
  "$@"
