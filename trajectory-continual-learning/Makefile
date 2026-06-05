# Trajectory-CL — one-command full stack.
# Stdlib-only targets use python3; parametric (training) targets use the venv.

PY  ?= python3
VPY ?= ./.venv/bin/python
QWEN ?= Qwen/Qwen2.5-0.5B-Instruct

.PHONY: help setup offline live live-inferred live-robust \
        data train eval parametric dpo qwen full-stack clean

help:
	@echo "Targets:"
	@echo "  setup        install the venv + CPU torch/transformers/peft (for training)"
	@echo "  offline      deterministic A/B proof + 11 tests (no installs, no key)"
	@echo "  live         live Claude proof via 'claude -p' (no API key)"
	@echo "  live-inferred  live, engine infers the rules from edits"
	@echo "  live-robust  live ablation that closes the inference gap to 1.00"
	@echo "  parametric   data -> LoRA SFT -> eval tuned weights (SmolLM2-135M, CPU)"
	@echo "  dpo          data -> DPO on (chosen,rejected) -> eval (SmolLM2-135M)"
	@echo "  qwen         parametric path on $(QWEN) (bigger, cleaner prose)"
	@echo "  full-stack   offline + parametric (the reproducible core, no key)"

# --- no-install, no-key proofs (stdlib only) ---
offline:
	$(PY) experiment.py && $(PY) tests.py

live:           ; $(PY) run_claude_real.py
live-inferred:  ; $(PY) run_inferred_real.py
live-robust:    ; $(PY) run_robust_real.py

# --- training stack (needs `make setup`) ---
setup:
	$(PY) -m venv .venv
	$(VPY) -m pip install -q --upgrade pip
	$(VPY) -m pip install -q torch --index-url https://download.pytorch.org/whl/cpu
	$(VPY) -m pip install -q transformers peft datasets accelerate

data:
	cd parametric && ../$(VPY) data.py

train: data
	cd parametric && ../$(VPY) train_sft.py

eval:
	cd parametric && ../$(VPY) eval_weights.py

parametric: train eval

dpo: data
	cd parametric && ADAPTER_DIR=out_dpo ../$(VPY) train_dpo.py
	cd parametric && ADAPTER_DIR=out_dpo RESULTS_TAG=dpo ../$(VPY) eval_weights.py

qwen: data
	cd parametric && BASE_MODEL=$(QWEN) ADAPTER_DIR=out_qwen EPOCHS=4 ../$(VPY) train_sft.py
	cd parametric && BASE_MODEL=$(QWEN) ADAPTER_DIR=out_qwen RESULTS_TAG=qwen ../$(VPY) eval_weights.py

# the reproducible core, no API key required
full-stack: offline parametric
	@echo "full stack complete — see artifacts/ and artifacts/parametric/"

clean:
	rm -rf parametric/out parametric/out_dpo parametric/out_qwen \
	       parametric/train.jsonl parametric/eval.jsonl __pycache__ */__pycache__
