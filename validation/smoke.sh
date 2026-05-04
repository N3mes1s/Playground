#!/usr/bin/env bash
# Smoke test: end-to-end verification that the pipeline still runs.
#
# Runs cli_pro on the smallest committed intent + an LLM judge,
# confirms the JSON sidecar exists and has the expected shape.
# Cost: ~$0.05 LLM. Wall time: ~60 seconds with gpt-5.4-mini.
#
# Use after a major change to confirm nothing is broken end-to-end.

set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

if [[ -z "${OPENAI_API_KEY:-}" ]]; then
    echo "ERROR: OPENAI_API_KEY not set" >&2
    exit 1
fi

export MODEL="${MODEL:-gpt-5.4-mini}"
export MAX_TOKENS="${MAX_TOKENS:-800}"

OUT_DIR="$(mktemp -d)"
trap 'rm -rf "$OUT_DIR"' EXIT

INTENT="${1:-validation/postmortems/intents/04_gitlab_db_replica.md}"
if [[ ! -f "$INTENT" ]]; then
    echo "ERROR: intent file not found: $INTENT" >&2
    exit 1
fi

echo "=== smoke test ==="
echo "  model:  $MODEL"
echo "  intent: $INTENT"
echo "  out:    $OUT_DIR"
echo

echo "[1/3] cli_pro generates Pareto plans + chaos + SMT"
python3 verified-rollout/cli_pro.py \
    "$INTENT" \
    --n-plans 3 \
    --chaos-pairs 0 \
    --out "$OUT_DIR/cli_pro.md" \
    >/dev/null

JSON="$OUT_DIR/cli_pro.json"
if [[ ! -s "$JSON" ]]; then
    echo "FAIL: no JSON sidecar at $JSON" >&2
    exit 1
fi

# Validate sidecar shape.
python3 - "$JSON" <<'PY'
import json, sys
j = json.loads(open(sys.argv[1]).read())
required = ("plans", "smt", "scores", "constraints", "pareto")
for k in required:
    assert k in j, f"missing key: {k}"
assert len(j["plans"]) >= 2, f"too few plans: {len(j['plans'])}"
assert "winner" in j["pareto"], "no recommendation winner"
print(f"  PASS — {len(j['plans'])} plans, winner={j['pareto']['winner']}")
PY

echo "[2/3] llm_judge scores the recommended plan"
WINNER=$(python3 -c "import json; j=json.loads(open('$JSON').read()); print(j['pareto']['winner'])")
python3 - "$JSON" <<PY
import json, sys
sys.path.insert(0, "$ROOT/dataset/bench")
sys.path.insert(0, "$ROOT")
from llm_judge import judge_element
from mirofish_lab.config import load_config
sidecar = json.loads(open("$JSON").read())
elem = {
    "id": "smoke/test",
    "source": "smoke",
    "intent_md": open("$INTENT").read(),
    "ground_truth": {
        "kind": "smoke", "files_touched": [], "root_cause_keywords": [],
    },
    "metadata": {},
}
v = judge_element(elem, sidecar, cfg=load_config())
print(f"  judge verdict: {v['verdict']} (confidence: {v['judge_confidence']})")
print(f"  rationale: {v['rationale'][:140]}")
assert v["verdict"] in ("caught", "partial", "missed", "no_ground_truth")
print("  PASS")
PY

echo "[3/3] static cascade analysis on the winner plan"
python3 - "$JSON" <<PY
import json, sys
sys.path.insert(0, "$ROOT")
from mirofish_lab.chaos_static import static_chaos_summary
j = json.loads(open("$JSON").read())
plan = j["plans"][j["pareto"]["winner"]]
s = static_chaos_summary(plan, plan_id="smoke")
print(f"  static fragility curve: {s.fragility_curve}")
print(f"  achilles top@k=1: {[(list(e.failure_set), e.fragility) for e in s.achilles_top_per_k.get(1, [])[:3]]}")
print("  PASS")
PY

echo
echo "=== smoke test PASSED ==="
echo "  output: $OUT_DIR/cli_pro.md (deleted on exit)"
