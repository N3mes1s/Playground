"""Modal harness for the Code2LoRA reproduce/train driver (gpu/c2l_gpu.py).

Cleaner than the vast.ai onstart+logs loop: each config runs as a Modal H100
function that returns its result dict directly to the caller.

    export MODAL_TOKEN_ID=... MODAL_TOKEN_SECRET=...
    modal run gpu/modal_app.py            # runs the regularized sweep
"""
import modal

image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install("torch", "transformers", "huggingface_hub", "pyarrow", "pandas", "accelerate")
    .add_local_dir("gpu", "/root/gpu")  # ships c2l_gpu.py + reference/code2lora_core.py
)
app = modal.App("code2lora-train")


@app.function(image=image, gpu="H100", timeout=3 * 3600)
def run(config: dict):
    import os, sys
    for k, v in config.items():
        os.environ[str(k)] = str(v)
    sys.path.insert(0, "/root/gpu")
    import c2l_gpu
    return c2l_gpu.main()  # returns a plain-typed result dict


@app.local_entrypoint()
def main(mode: str = "perlayer"):
    base = dict(MODE="train", RANK=16, HIDDEN=1024, ALPHA=32, MAXLEN=2048,
                TRAIN_MAXLEN=1024, EVAL_PER_REPO=15, MAXNEW=24, BATCH=6,
                EVAL_EVERY=2000, EVAL_SEED=0, ANCHOR=0.55, LR="1e-4")
    if mode == "repro":
        configs = [dict(base, MODE="repro")]
    elif mode == "perlayer":
        # the improvement attempt: per-layer (FiLM) adapters vs layer-shared
        configs = [
            dict(base, PER_LAYER=1, HEAD_DROPOUT=0.05, WD=0.02, EPOCHS=2, RUNTAG="PL1"),
            dict(base, PER_LAYER=0, HEAD_DROPOUT=0.05, WD=0.02, EPOCHS=2, RUNTAG="SHARED"),
        ]
    else:
        configs = [
            dict(base, HEAD_DROPOUT=0.1, WD=0.05, LR="5e-5", EPOCHS=3, RUNTAG="M1"),
            dict(base, HEAD_DROPOUT=0.0, WD=0.01, LR="1e-4", EPOCHS=3, RUNTAG="M3"),
        ]
    for res in run.map(configs):
        print("RESULT:", res)
