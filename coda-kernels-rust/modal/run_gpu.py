"""Modal deployment for the CODA-rs CUDA backend.

Builds the `coda-rs` crate with `--features cuda` on a CUDA toolkit image and
runs the `coda-gpu` binary on a real NVIDIA GPU. That binary verifies every
CUDA GEMM-plus-epilogue kernel against the CPU reference, runs the full
Transformer forward and the device-resident training loop, and benchmarks
GPU vs CPU.

Usage:
    pip install modal
    modal token set --token-id <id> --token-secret <secret>
    modal run modal/run_gpu.py                        # default: T4, small scale
    modal run modal/run_gpu.py --gpu A100 --scale big # ~100M-param run on A100
"""

import os
import subprocess

import modal

app = modal.App("coda-kernels-gpu")

# A CUDA *devel* image (nvcc included) + Python (Modal needs it) + Rust.
image = (
    modal.Image.from_registry(
        "nvidia/cuda:12.4.1-devel-ubuntu22.04", add_python="3.11"
    )
    .apt_install("curl", "build-essential", "ca-certificates")
    .run_commands(
        "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs "
        "| sh -s -- -y --profile minimal --default-toolchain stable"
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
    # Only the crate sources - never the local (CPU-built) target/ directory.
    .add_local_file("coda-kernels-rust/Cargo.toml", "/work/Cargo.toml", copy=True)
    .add_local_file("coda-kernels-rust/Cargo.lock", "/work/Cargo.lock", copy=True)
    .add_local_file("coda-kernels-rust/build.rs", "/work/build.rs", copy=True)
    .add_local_dir("coda-kernels-rust/src", "/work/src", copy=True)
    .add_local_dir("coda-kernels-rust/cuda", "/work/cuda", copy=True)
)


def _run(cmd: list[str], **kw) -> None:
    print(f"\n$ {' '.join(cmd)}", flush=True)
    subprocess.run(cmd, check=True, **kw)


@app.function(image=image, gpu="T4", timeout=3600)
def build_and_run(scale: str = "small") -> None:
    """Compile the CUDA backend and run the GPU verification + benchmark."""
    _run(["nvidia-smi"])
    _run(["nvcc", "--version"])
    _run(["cargo", "--version"])
    _run(
        ["cargo", "build", "--release", "--features", "cuda", "--bin", "coda-gpu"],
        cwd="/work",
    )
    # CODA_SCALE=big selects the ~100M-parameter training config.
    env = {**os.environ, "CODA_SCALE": scale}
    _run(["/work/target/release/coda-gpu"], env=env)
    print("\n[modal] coda-gpu finished successfully.", flush=True)


@app.local_entrypoint()
def main(gpu: str = "T4", scale: str = "small") -> None:
    """Run the GPU job. `--gpu` picks the accelerator (T4/A10/A100/H100);
    `--scale big` selects the ~100M-parameter training config."""
    print(f"[modal] launching coda-gpu on a {gpu} GPU (scale={scale}) ...")
    build_and_run.with_options(gpu=gpu).remote(scale)
