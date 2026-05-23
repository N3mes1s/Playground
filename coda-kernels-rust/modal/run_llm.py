"""Run a real pretrained model (Llama-2-7B-chat) on the CODA-rs CUDA backend.

Pipeline (all on one Modal GPU):
  1. `prepare_llm.py prepare` - convert the Llama-2-7B-chat checkpoint into the
     flat layout the Rust backend expects, tokenize a chat prompt, and save
     reference logits from a genuine HuggingFace forward.
  2. build + run `coda-llm` - load the converted model, verify the CUDA
     forward against the reference logits, and autoregressively generate with
     the device-resident decode loop (the 27 GB weight set uploads once).
  3. `prepare_llm.py decode` - turn the generated token ids back into text.

Usage:
    modal run coda-kernels-rust/modal/run_llm.py
"""

import os
import subprocess

import modal

app = modal.App("coda-kernels-llm")

# Ungated mirror of meta-llama/Llama-2-7b-chat-hf (identical weights).
MODEL = "NousResearch/Llama-2-7b-chat-hf"

image = (
    modal.Image.from_registry(
        "nvidia/cuda:12.4.1-devel-ubuntu22.04", add_python="3.11"
    )
    .apt_install("curl", "build-essential", "ca-certificates")
    .run_commands(
        "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs "
        "| sh -s -- -y --profile minimal --default-toolchain stable"
    )
    .pip_install("torch", index_url="https://download.pytorch.org/whl/cpu")
    .pip_install("transformers", "sentencepiece", "protobuf", "numpy", "huggingface_hub")
    # Bake the model into the image so runs don't re-download it.
    .run_commands(
        f"python -c \"from huggingface_hub import snapshot_download; "
        f"snapshot_download('{MODEL}')\""
    )
    .env(
        {
            "PATH": (
                "/usr/local/cuda/bin:/root/.cargo/bin:"
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            ),
            "LD_LIBRARY_PATH": "/usr/local/cuda/lib64",
        }
    )
    .add_local_file("coda-kernels-rust/Cargo.toml", "/work/Cargo.toml", copy=True)
    .add_local_file("coda-kernels-rust/Cargo.lock", "/work/Cargo.lock", copy=True)
    .add_local_file("coda-kernels-rust/build.rs", "/work/build.rs", copy=True)
    .add_local_dir("coda-kernels-rust/src", "/work/src", copy=True)
    .add_local_dir("coda-kernels-rust/cuda", "/work/cuda", copy=True)
    .add_local_dir("coda-kernels-rust/modal", "/work/modal", copy=True)
)


def _run(cmd: list[str], **kw) -> None:
    print(f"\n$ {' '.join(cmd)}", flush=True)
    subprocess.run(cmd, check=True, **kw)


@app.function(image=image, gpu="A100-80GB", memory=131072, timeout=3600)
def run_llm() -> None:
    """Convert Llama-2-7B-chat, run it on the CUDA backend, and decode the output."""
    _run(["nvidia-smi"])
    _run(["python", "/work/modal/prepare_llm.py", "prepare"])
    _run(
        ["cargo", "build", "--release", "--features", "cuda", "--bin", "coda-llm"],
        cwd="/work",
    )
    _run(["/work/target/release/coda-llm"], env={**os.environ})
    _run(["python", "/work/modal/prepare_llm.py", "decode"])
    print("\n[modal] coda-llm finished.", flush=True)


@app.local_entrypoint()
def main() -> None:
    # `.spawn()` (not `.remote()`) so a `modal run --detach` invocation truly
    # detaches: the local entrypoint returns immediately, the function runs in
    # the background, and the run survives a local-client disconnect. Follow
    # progress with `modal app logs <app-id>`; Modal prints the run URL above.
    print("[modal] launching Llama-2-7B-chat on the CODA CUDA backend ...")
    call = run_llm.spawn()
    print(f"[modal] spawned FunctionCall {call.object_id}")
