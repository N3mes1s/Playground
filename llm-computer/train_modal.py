"""
GPU training on Modal.com for the WASM-in-transformer interpreter.

Usage:
    pip install modal
    modal setup  # one-time auth
    modal run train_modal.py
"""

import modal

app = modal.App("llm-computer-train")

# Mount the local code directory into the Modal container
code_mount = modal.Mount.from_local_dir(
    "/home/nemesis/code/Playground/llm-computer",
    remote_path="/root/llm-computer",
    condition=lambda path: not any(x in path for x in ['__pycache__', '.pyc', 'target', 'rust_engine', '.venv']),
)

image = modal.Image.debian_slim(python_version="3.11").pip_install(
    "torch", "numpy"
)


@app.function(
    image=image,
    gpu="T4",  # cheapest GPU, sufficient for 612K param model
    timeout=3600,
    mounts=[code_mount],
)
def train_on_gpu():
    import sys
    sys.path.insert(0, "/root/llm-computer")

    import autoregressive_interpreter as ai
    ai.MAX_SEQ = 5000  # small for training

    from train import train, TrainingConfig

    config = TrainingConfig(
        n_steps=2000,
        eval_every=200,
        lr=1e-4,
        batch_size=1,
        max_trace_len=500,
    )

    train(config)


@app.local_entrypoint()
def main():
    train_on_gpu.remote()
